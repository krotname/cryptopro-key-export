using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Прямое чтение файловой памяти Rutoken S по штатному ISO-7816 профилю старых
    /// Рутокенов. Используется вместо rtCOMLite: его SAFEARRAY-обход рушит кучу на
    /// непустом Rutoken S, а поштучный EnumFiles возвращает Unsupported function.
    /// </summary>
    internal sealed class RutokenSApdu
    {
        private const int MaxDepth = 16;
        private const int MaxNodes = 1024;

        private static readonly (int Suffix, string File)[] Files =
        {
            (0x06, "name.key"), (0x03, "header.key"),
            (0x02, "primary.key"), (0x01, "masks.key"),
            (0x05, "primary2.key"), (0x04, "masks2.key"),
        };

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            var result = new List<DirectTokenContainerRef>();
            int visited = 0;
            using var session = PcscApduSession.Open(reader);
            SelectMf(session);
            Walk(session, reader, new List<ushort> { 0x3F00 }, result, ref visited);
            return result;
        }

        public RutokenContainer ReadContainer(string reader, DirectTokenContainerRef selected,
                                              string pin)
        {
            if (selected?.Path == null || selected.Path.Length < 2)
                throw new ArgumentException(nameof(selected));
            if (string.IsNullOrEmpty(pin))
                throw new LiteApduException(Strings.Format("err.lite.pin", "—"));

            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            using var session = PcscApduSession.Open(reader);
            SelectMf(session);
            ResetAccessRights(session);
            try
            {
                VerifyPin(session, pin);
                SelectPath(session, selected.Path);
                List<Item> items = ListItems(session);
                ushort containerId = selected.Path[selected.Path.Length - 1];
                foreach (var mapping in Files)
                {
                    Cancel.ThrowIfCancellationRequested();
                    Item item = items.FirstOrDefault(candidate => !candidate.IsDirectory
                        && (candidate.Id & 0xFF) == mapping.Suffix
                        && (candidate.Id & 0xFF00) == (containerId & 0xFF00));
                    if (item.Id == 0) continue;
                    byte[] fcp = SelectPath(session, selected.Path.Concat(new[] { item.Id }).ToArray());
                    int size = FcpSize(fcp);
                    if (size <= 0) continue;
                    byte[] value = RutokenLiteApdu.TrimDer(ReadBinary(session, size));
                    blobs[mapping.File] = value;
                    Say($"  {mapping.File} ({value.Length})");
                }
            }
            finally
            {
                try { ResetAccessRights(session); } catch { }
            }

            // Та же проверка целостности, что у Lite/JaCarta LT, но без записи на диск.
            ValidateBlobs(blobs, reader);
            return new RutokenContainer
            {
                TokenName = reader,
                TokenDir = "/" + string.Join("/", selected.Path.Select(id => id.ToString("X4"))) + "/",
                ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                    ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                Files = blobs,
            };
        }

        private void Walk(PcscApduSession session, string reader, List<ushort> path,
                          List<DirectTokenContainerRef> result, ref int visited)
        {
            Cancel.ThrowIfCancellationRequested();
            if (path.Count > MaxDepth || ++visited > MaxNodes)
                throw ProtocolError("TREE_LIMIT");

            SelectPath(session, path);
            List<Item> items = ListItems(session);
            ushort current = path[path.Count - 1];
            Item nameFile = items.FirstOrDefault(item => !item.IsDirectory
                && (item.Id & 0xFF) == 0x06 && (item.Id & 0xFF00) == (current & 0xFF00));
            bool hasHeader = items.Any(item => !item.IsDirectory
                && (item.Id & 0xFF) == 0x03 && (item.Id & 0xFF00) == (current & 0xFF00));
            bool hasPair = HasCompletePair(items, current, 0x01, 0x02)
                || HasCompletePair(items, current, 0x04, 0x05);
            if (nameFile.Id != 0 && hasHeader && hasPair)
            {
                byte[] fcp = SelectPath(session, path.Concat(new[] { nameFile.Id }).ToArray());
                int size = FcpSize(fcp);
                byte[] name = size > 0
                    ? RutokenLiteApdu.TrimDer(ReadBinary(session, size)) : null;
                string parsed = RutokenLiteApdu.ParseName(name);
                result.Add(new DirectTokenContainerRef
                {
                    Kind = RutokenKind.RutokenS,
                    Reader = reader,
                    Name = parsed,
                    OutputName = $"rutokens_{current:X4}",
                    Path = path.ToArray(),
                    Index = current,
                });
            }

            foreach (Item directory in items.Where(item => item.IsDirectory))
            {
                path.Add(directory.Id);
                Walk(session, reader, path, result, ref visited);
                path.RemoveAt(path.Count - 1);
            }
        }

        private static bool HasCompletePair(IEnumerable<Item> items, ushort current,
                                            int masks, int primary)
        {
            bool m = false, p = false;
            foreach (Item item in items)
            {
                if (item.IsDirectory || (item.Id & 0xFF00) != (current & 0xFF00)) continue;
                if ((item.Id & 0xFF) == masks) m = true;
                if ((item.Id & 0xFF) == primary) p = true;
            }
            return m && p;
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
            bool exchange = exchangePrimary && exchangeMasks;
            bool signature = signaturePrimary && signatureMasks;
            if (!exchange && !signature)
                throw new LiteApduException(Strings.Format(
                    "err.extract.nofile", "primary.key / primary2.key", source));
        }

        private static void SelectMf(PcscApduSession session)
        {
            byte[] response = session.TransmitWithGetResponse(
                new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x3F });
            PcscApduSession.RequireOk(response, "SELECT MF");
        }

        private static byte[] SelectPath(PcscApduSession session, IEnumerable<ushort> path)
        {
            ushort[] all = path.ToArray();
            if (all.Length == 1 && all[0] == 0x3F00)
            {
                byte[] mf = session.TransmitWithGetResponse(
                    new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x3F });
                PcscApduSession.RequireOk(mf, "SELECT MF");
                return PcscApduSession.Data(mf);
            }

            IEnumerable<ushort> relative = all.Length > 0 && all[0] == 0x3F00
                ? all.Skip(1) : all;
            ushort[] ids = relative.ToArray();
            var command = new List<byte>
                { 0x00, 0xA4, 0x08, 0x00, checked((byte)(ids.Length * 2)) };
            foreach (ushort id in ids)
            {
                command.Add((byte)id);
                command.Add((byte)(id >> 8));
            }
            byte[] response = session.TransmitWithGetResponse(command.ToArray());
            PcscApduSession.RequireOk(response, "SELECT PATH");
            return PcscApduSession.Data(response);
        }

        private static List<Item> ListItems(PcscApduSession session)
        {
            var result = new List<Item>();
            byte[] command = { 0x00, 0xA4, 0x00, 0x00, 0x00 };
            var seen = new HashSet<ushort>();
            for (int guard = 0; guard < 512; guard++)
            {
                byte[] response = session.TransmitWithGetResponse(command);
                int status = PcscApduSession.Status(response);
                if (status == 0x6A82) break;
                PcscApduSession.RequireOk(response, "LIST FILES");
                byte[] fcp = PcscApduSession.Data(response);
                byte[] rawId = FindTag(fcp, 0x83);
                byte[] descriptor = FindTag(fcp, 0x82);
                if (rawId == null || rawId.Length != 2 || descriptor == null || descriptor.Length == 0)
                    throw ProtocolError("FCP_FORMAT");
                ushort id = (ushort)((rawId[1] << 8) | rawId[0]);
                if (!seen.Add(id)) throw ProtocolError("FILE_LIST_CYCLE");
                bool directory = descriptor[0] == 0x38;
                result.Add(new Item(id, directory));
                if (directory)
                    PcscApduSession.RequireOk(session.Transmit(
                        new byte[] { 0x00, 0xA4, 0x03, 0x00, 0x00 }), "SELECT PARENT");
                command = new byte[] { 0x00, 0xA4, 0x00, 0x02, 0x02, rawId[0], rawId[1] };
            }
            return result;
        }

        private static byte[] ReadBinary(PcscApduSession session, int size)
        {
            if (size <= 0 || size > ushort.MaxValue)
                throw ProtocolError("EF_SIZE");
            var output = new byte[size];
            int offset = 0;
            while (offset < size)
            {
                int chunk = Math.Min(255, size - offset);
                byte[] response = session.Transmit(new byte[]
                    { 0x00, 0xB0, (byte)(offset >> 8), (byte)offset, (byte)chunk });
                PcscApduSession.RequireOk(response, "READ BINARY");
                byte[] data = PcscApduSession.Data(response);
                if (data.Length == 0) throw ProtocolError("SHORT_READ");
                int take = Math.Min(data.Length, size - offset);
                Array.Copy(data, 0, output, offset, take);
                offset += take;
            }
            return output;
        }

        internal static int FcpSize(byte[] fcp)
        {
            byte[] value = FindTag(fcp, 0x80);
            return value != null && value.Length == 2 ? (value[1] << 8) | value[0] : -1;
        }

        internal static byte[] FindTag(byte[] tlv, int wanted)
        {
            if (tlv == null) return null;
            int offset = 0;
            if (tlv.Length >= 2 && tlv[0] == 0x62)
            {
                int length = tlv[1];
                if ((length & 0x80) != 0 || 2 + length > tlv.Length) return null;
                var inner = new byte[length];
                Array.Copy(tlv, 2, inner, 0, length);
                tlv = inner;
            }
            while (offset + 2 <= tlv.Length)
            {
                int tag = tlv[offset++];
                int length = tlv[offset++];
                if ((length & 0x80) != 0 || offset + length > tlv.Length) return null;
                if (tag == wanted)
                {
                    var value = new byte[length];
                    Array.Copy(tlv, offset, value, 0, length);
                    return value;
                }
                offset += length;
            }
            return null;
        }

        private static void ResetAccessRights(PcscApduSession session) =>
            PcscApduSession.RequireOk(session.Transmit(
                new byte[] { 0x80, 0x40, 0x00, 0x00 }), "RESET ACCESS RIGHTS");

        private static LiteApduException ProtocolError(string code) =>
            new LiteApduException(Strings.Format("err.com.call", "Rutoken S APDU", code));

        private static void VerifyPin(PcscApduSession session, string pin)
        {
            if (pin.Length > byte.MaxValue || pin.Any(character => character > 0x7F))
                throw new LiteApduException(Strings.Format("err.lite.pin", "0x6A80"));
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pin);
            var command = new byte[5 + bytes.Length];
            command[0] = 0x00; command[1] = 0x20; command[2] = 0x00;
            command[3] = 0x02; command[4] = (byte)bytes.Length;
            Array.Copy(bytes, 0, command, 5, bytes.Length);
            byte[] response = session.Transmit(command);
            if (!PcscApduSession.IsOk(response))
                throw new LiteApduException(Strings.Format(
                    "err.lite.pin", "0x" + PcscApduSession.Status(response).ToString("X4")));
        }

        private readonly struct Item
        {
            public Item(ushort id, bool isDirectory) { Id = id; IsDirectory = isDirectory; }
            public ushort Id { get; }
            public bool IsDirectory { get; }
        }
    }
}
