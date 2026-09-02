using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Read-only доступ к файловым контейнерам КриптоПро в пассивном CSP-разделе ESMART.
    /// Протокол подтверждён трассировкой штатного esmarttoken.dll на двух собственных
    /// устройствах: MF → DF 7F01, слоты F100…F900 и стандартные READ BINARY.
    /// Команды создания, удаления и записи этот backend никогда не отправляет.
    /// </summary>
    internal sealed class EsmartApdu
    {
        private const int FirstSlot = 1;
        private const int LastSlot = 9;

        /// <summary>
        /// Второй допущенный профиль — ESMART Token ГОСТ (MIK51, 72 КБ). В отличие от
        /// «ISBC ESMART Token» и «ESMART Token USB 64K» он показывает не собственное имя, а
        /// универсальный CCID-считыватель Feitian SCR301, в который можно вставить любую
        /// смарт-карту. Поэтому имени считывателя здесь недостаточно: допуск требует точную
        /// пару model/manufacturer PKCS#11 и live ATR самой карты, как у eToken PRO.
        /// </summary>
        internal const string GostExactAtr =
            "3B 7C 95 00 00 45 53 4D 41 52 54 47 4F 53 54 31 30";
        private const string GostExactModel = "ESMARTToken GOST";
        private const string GostExactManufacturer = "ISBC";
        private const string GostReaderFamily = "Feitian SCR301";

        private static readonly (int Suffix, string File)[] Files =
        {
            (0x06, "name.key"), (0x03, "header.key"),
            (0x02, "primary.key"), (0x01, "masks.key"),
            (0x12, "primary2.key"), (0x11, "masks2.key"),
        };

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        /// <summary>Считыватель универсального CCID-семейства, за которым может стоять любая карта.</summary>
        internal static bool IsGostReader(string reader)
            => IsIndexedReader(reader, GostReaderFamily);

        /// <summary>
        /// Статическая часть допуска ESMART Token ГОСТ: точные model/manufacturer PKCS#11 и ATR
        /// из метаданных. Одного свидетельства ESMART в модели мало — за универсальным
        /// считывателем может оказаться другая карта того же вендора.
        /// </summary>
        internal static bool IsExactGostMetadata(Pkcs11TokenInfo token)
            => token != null
            && token.Kind == RutokenKind.Esmart
            && IsGostReader(token.Reader)
            && string.Equals((token.Model ?? string.Empty).Trim(), GostExactModel,
                StringComparison.OrdinalIgnoreCase)
            && string.Equals((token.Manufacturer ?? string.Empty).Trim(), GostExactManufacturer,
                StringComparison.OrdinalIgnoreCase)
            && IsExactGostAtr(token.Atr);

        /// <summary>
        /// Динамическая часть допуска: тот же считыватель прямо сейчас держит ровно одну карту и
        /// её ATR совпадает с проверенным. Между опросом PKCS#11 и APDU карту можно подменить,
        /// поэтому статических метаданных недостаточно.
        /// </summary>
        internal static bool IsExactLiveGostReader(Pkcs11TokenInfo token,
                                                   IEnumerable<PcscReader> readers)
        {
            if (!IsExactGostMetadata(token)) return false;
            int matches = 0;
            foreach (PcscReader reader in readers ?? Array.Empty<PcscReader>())
            {
                if (reader == null || !reader.CardPresent
                    || !string.Equals((reader.Name ?? string.Empty).Trim(), token.Reader.Trim(),
                        StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!IsExactGostAtr(reader.Atr)) return false;
                matches++;
            }
            return matches == 1;
        }

        /// <summary>
        /// ATR, который обязан показать считыватель при открытии сессии: у универсального SCR301 —
        /// точная карта ESMART ГОСТ, у эксклюзивных имён имя считывателя уже задаёт модель.
        /// </summary>
        internal static string ExpectedAtr(string reader)
            => IsGostReader(reader) ? GostExactAtr : null;

        private static bool IsExactGostAtr(string atr)
            => string.Equals((atr ?? string.Empty).Trim(), GostExactAtr,
                StringComparison.OrdinalIgnoreCase);

        private static bool IsIndexedReader(string reader, string family)
        {
            string value = (reader ?? string.Empty).Trim();
            if (!value.StartsWith(family + " ", StringComparison.OrdinalIgnoreCase)) return false;
            string index = value.Substring(family.Length + 1);
            return index.Length > 0 && index.All(character => character is >= '0' and <= '9');
        }

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            var result = new List<DirectTokenContainerRef>();
            using var session = PcscApduSession.Open(reader, ExpectedAtr(reader));
            SelectStore(session);
            for (int slot = FirstSlot; slot <= LastSlot; slot++)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] nameFcp = TrySelectFile(session, FileId(slot, 0x06));
                if (nameFcp == null) continue;

                bool header = FileExists(session, FileId(slot, 0x03));
                bool exchange = FileExists(session, FileId(slot, 0x02))
                    && FileExists(session, FileId(slot, 0x01));
                bool signature = FileExists(session, FileId(slot, 0x12))
                    && FileExists(session, FileId(slot, 0x11));
                if (!header || (!exchange && !signature)) continue;

                // Проверки существования меняют выбранный EF — перед чтением выбираем name.key снова.
                nameFcp = TrySelectFile(session, FileId(slot, 0x06));
                byte[] name = ReadSelectedDer(session, FcpSize(nameFcp));
                result.Add(new DirectTokenContainerRef
                {
                    Kind = RutokenKind.Esmart,
                    Reader = reader,
                    Name = RutokenLiteApdu.ParseName(name),
                    OutputName = $"esmart_F{slot:X1}00",
                    Index = slot,
                });
            }
            return result;
        }

        public RutokenContainer ReadContainer(string reader, DirectTokenContainerRef selected,
                                              string pin)
        {
            if (selected == null || selected.Index is < FirstSlot or > LastSlot)
                throw new ArgumentException(nameof(selected));
            if (string.IsNullOrEmpty(pin))
                throw new LiteApduException(Strings.Format("err.lite.pin", "—"));

            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            using var session = PcscApduSession.Open(reader, ExpectedAtr(reader));
            SelectStore(session);
            VerifyPin(session, pin);
            foreach (var mapping in Files)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] value = ReadFile(session, FileId(selected.Index, mapping.Suffix));
                if (value == null) continue;
                blobs[mapping.File] = value;
                Say($"  {mapping.File} ({value.Length})");
            }

            ValidateBlobs(blobs, reader);
            return new RutokenContainer
            {
                TokenName = reader,
                TokenDir = $"APDU/ESMART/F{selected.Index:X1}00",
                ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                    ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                Files = blobs,
            };
        }

        internal static ushort FileId(int slot, int suffix)
        {
            if (slot is < FirstSlot or > LastSlot || suffix is < 0 or > 0xFF)
                throw new ArgumentOutOfRangeException(nameof(slot));
            return checked((ushort)(0xF000 | (slot << 8) | suffix));
        }

        internal static int FcpSize(byte[] fcp)
        {
            byte[] value = FindTag(fcp, 0x80);
            if (value == null || value.Length is < 1 or > 2) return -1;
            int size = 0;
            foreach (byte item in value) size = (size << 8) | item;
            return size > 0 ? size : -1;
        }

        internal static byte[] FindTag(byte[] tlv, int wanted)
        {
            if (tlv == null) return null;
            for (int offset = 0; offset < tlv.Length;)
            {
                if (offset + 2 > tlv.Length) return null;
                int tag = tlv[offset++];
                int length = ReadLength(tlv, ref offset);
                if (length < 0 || offset + length > tlv.Length) return null;
                if (tag == wanted)
                {
                    var value = new byte[length];
                    Array.Copy(tlv, offset, value, 0, length);
                    return value;
                }
                if ((tag & 0x20) != 0)
                {
                    var nested = new byte[length];
                    Array.Copy(tlv, offset, nested, 0, length);
                    byte[] found = FindTag(nested, wanted);
                    if (found != null) return found;
                }
                offset += length;
            }
            return null;
        }

        private static int ReadLength(byte[] tlv, ref int offset)
        {
            if (offset >= tlv.Length) return -1;
            int marker = tlv[offset++];
            if ((marker & 0x80) == 0) return marker;
            int count = marker & 0x7F;
            if (count is < 1 or > 2 || offset + count > tlv.Length) return -1;
            int length = 0;
            for (int i = 0; i < count; i++) length = (length << 8) | tlv[offset++];
            return length;
        }

        private static void SelectStore(PcscApduSession session)
        {
            byte[] root = session.TransmitWithGetResponse(
                new byte[] { 0x00, 0xA4, 0x00, 0x00 });
            PcscApduSession.RequireOk(root, "SELECT ESMART MF");
            byte[] store = session.TransmitWithGetResponse(
                new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x7F, 0x01 });
            PcscApduSession.RequireOk(store, "SELECT ESMART 7F01");
        }

        private static bool FileExists(PcscApduSession session, ushort fileId) =>
            TrySelectFile(session, fileId) != null;

        private static byte[] TrySelectFile(PcscApduSession session, ushort fileId)
        {
            byte[] response = session.TransmitWithGetResponse(new byte[]
                { 0x00, 0xA4, 0x00, 0x00, 0x02, (byte)(fileId >> 8), (byte)fileId });
            if (PcscApduSession.Status(response) == 0x6A82) return null;
            PcscApduSession.RequireOk(response, $"SELECT ESMART {fileId:X4}");
            byte[] fcp = PcscApduSession.Data(response);
            if (FcpSize(fcp) <= 0) throw ProtocolError("FCP_SIZE");
            return fcp;
        }

        private static byte[] ReadFile(PcscApduSession session, ushort fileId)
        {
            byte[] fcp = TrySelectFile(session, fileId);
            return fcp == null ? null : ReadSelectedDer(session, FcpSize(fcp));
        }

        private static byte[] ReadSelectedDer(PcscApduSession session, int size) =>
            NormalizePayload(ReadBinary(session, size));

        /// <summary>
        /// ESMART EF начинается с однобайтового служебного маркера 01, затем содержит
        /// обычный DER и нулевой хвост до фиксированного размера файла.
        /// </summary>
        internal static byte[] NormalizePayload(byte[] raw)
        {
            if (raw == null) return null;
            if (raw.Length >= 2 && raw[0] == 0x01 && raw[1] == 0x30)
            {
                var derAndPadding = new byte[raw.Length - 1];
                Array.Copy(raw, 1, derAndPadding, 0, derAndPadding.Length);
                return RutokenLiteApdu.TrimDer(derAndPadding);
            }
            return RutokenLiteApdu.TrimDer(raw);
        }

        private static byte[] ReadBinary(PcscApduSession session, int size)
        {
            if (size <= 0 || size > ushort.MaxValue) throw ProtocolError("EF_SIZE");
            var output = new byte[size];
            int offset = 0;
            while (offset < size)
            {
                int count = Math.Min(255, size - offset);
                byte[] response = session.Transmit(new byte[]
                    { 0x00, 0xB0, (byte)(offset >> 8), (byte)offset, (byte)count });
                PcscApduSession.RequireOk(response, "READ BINARY ESMART");
                byte[] data = PcscApduSession.Data(response);
                if (data.Length == 0) throw ProtocolError("SHORT_READ");
                int take = Math.Min(data.Length, size - offset);
                Array.Copy(data, 0, output, offset, take);
                offset += take;
            }
            return output;
        }

        private static void VerifyPin(PcscApduSession session, string pin)
        {
            if (pin.Length is < 4 or > 100 || pin.Any(character => character > 0x7F))
                throw new LiteApduException(Strings.Format("err.lite.pin", "0x6A80"));
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pin);
            var command = new byte[5 + bytes.Length];
            command[0] = 0x00; command[1] = 0x20; command[2] = 0x00;
            command[3] = 0x81; command[4] = checked((byte)bytes.Length);
            Array.Copy(bytes, 0, command, 5, bytes.Length);
            byte[] response = session.Transmit(command);
            if (!PcscApduSession.IsOk(response))
                throw new LiteApduException(Strings.Format(
                    "err.lite.pin", "0x" + PcscApduSession.Status(response).ToString("X4")));
        }

        private static void ValidateBlobs(IReadOnlyDictionary<string, byte[]> blobs, string source)
        {
            foreach (string common in new[] { "name.key", "header.key" })
                if (!blobs.ContainsKey(common))
                    throw new LiteApduException(Strings.Format("err.extract.nofile", common, source));
            bool exchangePrimary = blobs.ContainsKey("primary.key");
            bool exchangeMasks = blobs.ContainsKey("masks.key");
            bool signaturePrimary = blobs.ContainsKey("primary2.key");
            bool signatureMasks = blobs.ContainsKey("masks2.key");
            if (exchangePrimary != exchangeMasks)
                throw new LiteApduException(Strings.Format("err.extract.nofile",
                    exchangePrimary ? "masks.key" : "primary.key", source));
            if (signaturePrimary != signatureMasks)
                throw new LiteApduException(Strings.Format("err.extract.nofile",
                    signaturePrimary ? "masks2.key" : "primary2.key", source));
            if (!(exchangePrimary && exchangeMasks) && !(signaturePrimary && signatureMasks))
                throw new LiteApduException(Strings.Format(
                    "err.extract.nofile", "primary.key / primary2.key", source));
        }

        private static LiteApduException ProtocolError(string code) =>
            new LiteApduException(Strings.Format("err.com.call", "ESMART APDU", code));
    }
}
