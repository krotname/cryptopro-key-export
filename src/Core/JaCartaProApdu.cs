using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Чтение файловых контейнеров КриптоПро из апплета PRO на eToken PRO (Java). Backend разрешён
    /// только для точной комбинации CK_TOKEN_INFO, indexed reader и live ATR, проверенной
    /// на физическом VID_0529/PID_0620. Все команды чтения относятся только к выбранному
    /// контейнеру; защищённые EF требуют challenge-response перед каждым READ.
    /// </summary>
    internal sealed class JaCartaProApdu
    {
        internal const string ExactAtr = "3B D5 18 00 81 31 FE 7D 80 73 C8 21 10 F4";
        private const string ExactModel = "PRO";
        private const string ExactManufacturer = "Aladdin R.D.";

        /// <summary>
        /// Проверенные семейства считывателя апплета PRO. Корпус eToken PRO (Java) появляется под
        /// именем <c>Aladdin Token JC N</c>; тот же апплет PRO на носителе SafeNet — под
        /// <c>SafeNet Token JC N</c>. У обоих совпадают model=<c>PRO</c>, manufacturer=
        /// <c>Aladdin R.D.</c> и live ATR <see cref="ExactAtr"/>, поэтому протокол чтения один и тот
        /// же. Список закрытый: любое другое имя reader к этому backend не допускается.
        /// </summary>
        private static readonly string[] ReaderFamilies = { "Aladdin Token JC", "SafeNet Token JC" };
        private const string DisplayName = "eToken PRO (Java) / PRO";
        private const int LastContainerIndex = 15;

        private static readonly byte[] AppletAid = Convert.FromHexString("A0000003120202");
        private static readonly byte[] ContainerRoot = Convert.FromHexString("66665000E00E0B00");
        private static readonly byte[] ServiceSaltPath = Convert.FromHexString("66665000000F");
        private const int LegacyServiceSaltLength = 20;
        private const int CurrentServiceSaltLength = 43;

        private static readonly (byte Id, string File, bool Protected)[] Files =
        {
            (0x01, "masks.key", true),
            (0x02, "primary.key", true),
            (0x03, "header.key", false),
            (0x04, "masks2.key", true),
            (0x05, "primary2.key", true),
            (0x06, "name.key", false),
        };

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        internal static bool IsExactMetadata(Pkcs11TokenInfo token)
            => token != null
            && token.Kind == RutokenKind.JaCartaPro
            && string.Equals((token.Model ?? string.Empty).Trim(), ExactModel,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals((token.Manufacturer ?? string.Empty).Trim(), ExactManufacturer,
                StringComparison.OrdinalIgnoreCase)
            && IsIndexedReader(token.Reader)
            && IsExactAtr(token.Atr);

        internal static bool IsExactLiveReader(Pkcs11TokenInfo token,
                                               IEnumerable<PcscReader> readers)
        {
            if (!IsExactMetadata(token)) return false;
            int matches = 0;
            foreach (PcscReader reader in readers ?? Array.Empty<PcscReader>())
            {
                if (reader == null || !reader.CardPresent
                    || !string.Equals((reader.Name ?? string.Empty).Trim(), token.Reader.Trim(),
                        StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!IsExactAtr(reader.Atr)) return false;
                matches++;
            }
            return matches == 1;
        }

        private static bool IsIndexedReader(string reader)
        {
            string value = (reader ?? string.Empty).Trim();
            foreach (string family in ReaderFamilies)
            {
                if (!value.StartsWith(family + " ", StringComparison.Ordinal)) continue;
                string index = value.Substring(family.Length + 1);
                if (index.Length > 0 && index.All(character => character is >= '0' and <= '9'))
                    return true;
            }
            return false;
        }

        private static bool IsExactAtr(string atr)
            => string.Equals((atr ?? string.Empty).Trim(), ExactAtr,
                StringComparison.OrdinalIgnoreCase);

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            var result = new List<DirectTokenContainerRef>();
            using var session = PcscApduSession.Open(reader, ExactAtr);
            SelectApplet(session);
            for (int index = 0; index <= LastContainerIndex; index++)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] directory = ContainerPath(index);
                byte[] selected = session.Transmit(SelectPath(directory, 0x0C));
                int status = PcscApduSession.Status(selected);
                if (IsMissing(status)) continue;
                PcscApduSession.RequireOk(selected, $"SELECT {DisplayName} CC{index:X2}");

                byte[] namePath = FilePath(index, 0x06);
                byte[] nameSelect = session.Transmit(SelectPath(namePath, 0x0C));
                status = PcscApduSession.Status(nameSelect);
                if (IsMissing(status)) continue;
                PcscApduSession.RequireOk(nameSelect, $"SELECT {DisplayName} F006/{index:X2}");
                byte[] name = ReadDer(session, null);
                try
                {
                    result.Add(new DirectTokenContainerRef
                    {
                        Kind = RutokenKind.JaCartaPro,
                        Reader = reader,
                        Name = RutokenLiteApdu.ParseName(name),
                        OutputName = $"jacartapro_{index:X2}",
                        Index = index,
                    });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(name);
                }
            }
            return result;
        }

        public RutokenContainer ReadContainer(string reader, DirectTokenContainerRef selected,
                                              string pin)
        {
            if (selected == null || selected.Index is < 0 or > LastContainerIndex)
                throw new ArgumentException(nameof(selected));
            if (string.IsNullOrEmpty(pin))
                throw new LiteApduException(Strings.Format("err.lite.pin", "—"));

            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            byte[] key = null;
            bool transferred = false;
            try
            {
                using var session = PcscApduSession.Open(reader, ExactAtr);
                SelectApplet(session);
                byte[] saltResponse = null;
                byte[] saltPayload = null;
                byte[] salt = null;
                try
                {
                    byte[] saltSelect = session.Transmit(SelectPath(ServiceSaltPath, 0x04));
                    try
                    {
                        PcscApduSession.RequireOk(saltSelect,
                            $"SELECT {DisplayName} service salt");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(saltSelect);
                    }
                    saltResponse = session.Transmit(ReadAt(0));
                    PcscApduSession.RequireOk(saltResponse, $"READ {DisplayName} service salt");
                    saltPayload = PcscApduSession.Data(saltResponse);
                    salt = ExtractServiceSalt(saltPayload);
                    key = DeriveKey(pin, salt);
                }
                finally
                {
                    if (salt != null) CryptographicOperations.ZeroMemory(salt);
                    if (saltPayload != null) CryptographicOperations.ZeroMemory(saltPayload);
                    if (saltResponse != null) CryptographicOperations.ZeroMemory(saltResponse);
                }

                foreach (var mapping in Files)
                {
                    Cancel.ThrowIfCancellationRequested();
                    byte[] response = session.Transmit(
                        SelectPath(FilePath(selected.Index, mapping.Id), 0x0C));
                    try
                    {
                        PcscApduSession.RequireOk(response,
                            $"SELECT {DisplayName} F0{mapping.Id:X2}/{selected.Index:X2}");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(response);
                    }
                    byte[] value = ReadDer(session, mapping.Protected ? key : null);
                    try
                    {
                        int length = value.Length;
                        blobs.Add(mapping.File, value);
                        value = null;
                        Say($"  {mapping.File} ({length})");
                    }
                    finally
                    {
                        if (value != null) CryptographicOperations.ZeroMemory(value);
                    }
                }

                ValidateBlobs(blobs, reader);
                var result = new RutokenContainer
                {
                    TokenName = reader,
                    TokenDir = $"APDU/PRO/CC{selected.Index:X2}",
                    ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                        ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                    Files = blobs,
                };
                transferred = true;
                return result;
            }
            finally
            {
                if (key != null) CryptographicOperations.ZeroMemory(key);
                if (!transferred) ZeroBlobs(blobs);
            }
        }

        private static void SelectApplet(PcscApduSession session)
        {
            var command = new byte[6 + AppletAid.Length];
            command[1] = 0xA4;
            command[2] = 0x04;
            command[4] = checked((byte)AppletAid.Length);
            Array.Copy(AppletAid, 0, command, 5, AppletAid.Length);
            byte[] response = session.Transmit(command);
            PcscApduSession.RequireOk(response, $"SELECT {DisplayName} applet");
        }

        private static byte[] SelectPath(byte[] path, byte p2)
        {
            var command = new byte[6 + path.Length];
            command[1] = 0xA4;
            command[2] = 0x08;
            command[3] = p2;
            command[4] = checked((byte)path.Length);
            Array.Copy(path, 0, command, 5, path.Length);
            return command;
        }

        private static byte[] ContainerPath(int index)
            => ContainerRoot.Concat(new byte[] { 0xCC, checked((byte)index) }).ToArray();

        private static byte[] FilePath(int index, byte file)
            => ContainerPath(index).Concat(new byte[] { 0xF0, file }).ToArray();

        private static bool IsMissing(int status) => status is 0x6A82 or 0x6A86 or 0x6A88;

        private static byte[] ReadAt(ushort offset) => new byte[]
        {
            0x80, 0x18, 0x00, 0x00, 0x04, 0x0E, 0x02,
            (byte)(offset >> 8), (byte)offset, 0x00,
        };

        private static byte[] ReadDer(PcscApduSession session, byte[] key)
        {
            byte[] first = null;
            byte[] chunk = null;
            byte[] result = null;
            try
            {
                first = ReadChunk(session, 0, key);
                int total = DerLength(first);
                result = new byte[total];
                int copied = Math.Min(total, first.Length);
                Array.Copy(first, 0, result, 0, copied);
                CryptographicOperations.ZeroMemory(first);
                first = null;
                while (copied < total)
                {
                    chunk = ReadChunk(session, checked((ushort)copied), key);
                    if (chunk.Length == 0) throw ProtocolError("SHORT_READ");
                    int count = Math.Min(total - copied, chunk.Length);
                    Array.Copy(chunk, 0, result, copied, count);
                    copied += count;
                    CryptographicOperations.ZeroMemory(chunk);
                    chunk = null;
                }
                byte[] completed = result;
                result = null;
                return completed;
            }
            finally
            {
                if (first != null) CryptographicOperations.ZeroMemory(first);
                if (chunk != null) CryptographicOperations.ZeroMemory(chunk);
                if (result != null) CryptographicOperations.ZeroMemory(result);
            }
        }

        private static byte[] ReadChunk(PcscApduSession session, ushort offset, byte[] key)
        {
            if (key != null) Authenticate(session, key);
            byte[] response = session.Transmit(ReadAt(offset));
            try
            {
                PcscApduSession.RequireOk(response, $"READ {DisplayName} object");
                return PcscApduSession.Data(response);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }
        }

        internal static int DerLength(byte[] header)
        {
            if (header == null || header.Length < 2 || header[0] != 0x30)
                throw ProtocolError("DER_TAG");
            int marker = header[1];
            if ((marker & 0x80) == 0) return checked(2 + marker);
            int count = marker & 0x7F;
            if (count is < 1 or > 2 || header.Length < 2 + count)
                throw ProtocolError("DER_LENGTH");
            int content = 0;
            for (int i = 0; i < count; i++) content = (content << 8) | header[2 + i];
            int total = checked(2 + count + content);
            if (total > ushort.MaxValue) throw ProtocolError("OBJECT_SIZE");
            return total;
        }

        private static void Authenticate(PcscApduSession session, byte[] key)
        {
            byte[] challengeResponse = null;
            byte[] challenge = null;
            byte[] cryptogram = null;
            byte[] command = null;
            byte[] response = null;
            try
            {
                challengeResponse = session.Transmit(Convert.FromHexString("8017000008"));
                PcscApduSession.RequireOk(challengeResponse, $"GET CHALLENGE {DisplayName}");
                challenge = PcscApduSession.Data(challengeResponse);
                if (challenge.Length != 8) throw ProtocolError("CHALLENGE_LENGTH");
                cryptogram = EncryptChallenge(key, challenge);
                command = new byte[15]
                {
                    0x80, 0x11, 0x00, 0x11, 0x0A, 0x10, 0x08,
                    0, 0, 0, 0, 0, 0, 0, 0,
                };
                Array.Copy(cryptogram, 0, command, 7, cryptogram.Length);
                response = session.Transmit(command);
                int status = PcscApduSession.Status(response);
                if (status != 0x9000)
                    throw new LiteApduException(Strings.Format(
                        "err.lite.pin", "0x" + status.ToString("X4")));
            }
            finally
            {
                if (challengeResponse != null)
                    CryptographicOperations.ZeroMemory(challengeResponse);
                if (challenge != null) CryptographicOperations.ZeroMemory(challenge);
                if (cryptogram != null) CryptographicOperations.ZeroMemory(cryptogram);
                if (command != null) CryptographicOperations.ZeroMemory(command);
                if (response != null) CryptographicOperations.ZeroMemory(response);
            }
        }

        internal static byte[] EncryptChallenge(byte[] key, byte[] challenge)
        {
            if (key == null || key.Length != 24) throw new ArgumentException(nameof(key));
            if (challenge == null || challenge.Length != 8)
                throw new ArgumentException(nameof(challenge));
            byte[] iv = new byte[8];
            byte[] result = null;
            bool completed = false;
            using TripleDES cipher = TripleDES.Create();
            try
            {
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.None;
                cipher.Key = key;
                cipher.IV = iv;
                using ICryptoTransform encryptor = cipher.CreateEncryptor();
                result = encryptor.TransformFinalBlock(challenge, 0, challenge.Length);
                completed = true;
                return result;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(iv);
                if (!completed && result != null) CryptographicOperations.ZeroMemory(result);
            }
        }

        internal static byte[] DeriveKey(string pin, byte[] salt)
        {
            if (pin == null) throw new ArgumentNullException(nameof(pin));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            const int digestSize = 20;
            const int blockSize = 64;
            const int iterations = 999;
            const int outputLength = 24;
            byte[] password = null;
            byte[] diversifier = null;
            byte[] saltMaterial = null;
            byte[] passwordMaterial = null;
            byte[] material = null;
            byte[] output = null;
            byte[] initial = null;
            byte[] current = null;
            byte[] repeated = null;
            bool completed = false;
            try
            {
                password = Encoding.BigEndianUnicode.GetBytes(pin + "\0");
                diversifier = Enumerable.Repeat((byte)3, blockSize).ToArray();
                saltMaterial = RepeatToBlock(salt, blockSize);
                passwordMaterial = RepeatToBlock(password, blockSize);
                material = new byte[saltMaterial.Length + passwordMaterial.Length];
                Array.Copy(saltMaterial, 0, material, 0, saltMaterial.Length);
                Array.Copy(passwordMaterial, 0, material, saltMaterial.Length,
                    passwordMaterial.Length);
                output = new byte[outputLength];

                using SHA1 sha1 = SHA1.Create();
                for (int outputOffset = 0; outputOffset < outputLength;
                     outputOffset += digestSize)
                {
                    initial = new byte[diversifier.Length + material.Length];
                    Array.Copy(diversifier, 0, initial, 0, diversifier.Length);
                    Array.Copy(material, 0, initial, diversifier.Length, material.Length);
                    current = sha1.ComputeHash(initial);
                    CryptographicOperations.ZeroMemory(initial);
                    initial = null;
                    for (int round = 1; round < iterations; round++)
                    {
                        byte[] next = sha1.ComputeHash(current);
                        CryptographicOperations.ZeroMemory(current);
                        current = next;
                    }
                    Array.Copy(current, 0, output, outputOffset,
                        Math.Min(digestSize, outputLength - outputOffset));

                    repeated = new byte[blockSize];
                    for (int offset = 0; offset < repeated.Length; offset += current.Length)
                        Array.Copy(current, 0, repeated, offset,
                            Math.Min(current.Length, repeated.Length - offset));
                    for (int block = 0; block < material.Length; block += blockSize)
                    {
                        int carry = 1;
                        for (int index = block + blockSize - 1; index >= block; index--)
                        {
                            int sum = material[index] + repeated[index - block] + carry;
                            material[index] = (byte)sum;
                            carry = sum >> 8;
                        }
                    }
                    CryptographicOperations.ZeroMemory(current);
                    current = null;
                    CryptographicOperations.ZeroMemory(repeated);
                    repeated = null;
                }
                completed = true;
                return output;
            }
            finally
            {
                if (password != null) CryptographicOperations.ZeroMemory(password);
                if (diversifier != null) CryptographicOperations.ZeroMemory(diversifier);
                if (saltMaterial != null) CryptographicOperations.ZeroMemory(saltMaterial);
                if (passwordMaterial != null)
                    CryptographicOperations.ZeroMemory(passwordMaterial);
                if (material != null) CryptographicOperations.ZeroMemory(material);
                if (initial != null) CryptographicOperations.ZeroMemory(initial);
                if (current != null) CryptographicOperations.ZeroMemory(current);
                if (repeated != null) CryptographicOperations.ZeroMemory(repeated);
                if (!completed && output != null) CryptographicOperations.ZeroMemory(output);
            }
        }

        internal static bool IsSupportedServiceSaltLength(int length)
            => length == LegacyServiceSaltLength || length == CurrentServiceSaltLength;

        internal static byte[] ExtractServiceSalt(byte[] payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (!IsSupportedServiceSaltLength(payload.Length))
                throw ProtocolError("SERVICE_SALT_LENGTH");
            // The current PRO EF is a 43-byte record; only its first 20 bytes participate
            // in the legacy challenge KDF. Keep the complete payload separately for cleanup.
            var salt = new byte[LegacyServiceSaltLength];
            Array.Copy(payload, salt, salt.Length);
            return salt;
        }

        private static byte[] RepeatToBlock(byte[] value, int blockSize)
        {
            if (value.Length == 0) return Array.Empty<byte>();
            int length = blockSize * ((value.Length + blockSize - 1) / blockSize);
            var result = new byte[length];
            for (int i = 0; i < result.Length; i++) result[i] = value[i % value.Length];
            return result;
        }

        private static LiteApduException ProtocolError(string code)
            => new LiteApduException(Strings.Format("err.com.call", $"{DisplayName} APDU", code));

        internal static void ZeroBlobs(IDictionary<string, byte[]> blobs)
        {
            if (blobs == null) return;
            foreach (byte[] value in blobs.Values)
                if (value != null) CryptographicOperations.ZeroMemory(value);
            blobs.Clear();
        }

        private static void ValidateBlobs(IReadOnlyDictionary<string, byte[]> blobs, string source)
        {
            foreach (string file in ContainerStore.ContainerFiles)
                if (!blobs.ContainsKey(file))
                    throw new LiteApduException(Strings.Format("err.extract.nofile", file, source));
        }
    }
}
