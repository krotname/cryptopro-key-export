using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Чтение файловых контейнеров КриптоПро из пассивного хранилища JaCarta LT.
    /// Протокол снят с штатного backend'а КриптоПро 5.0 на своём VID_24DC/PID_0102:
    /// апплет A000000448000301, таблица 80 20 60, чтение 80 20 30, login 80 10 10.
    /// Ни одна команда записи к токену не отправляется.
    /// </summary>
    internal sealed class JaCartaLtApdu
    {
        private static readonly byte[] SelectApplet =
            { 0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x04, 0x48, 0x00, 0x03, 0x01 };

        private static readonly (byte Code, string File)[] Files =
        {
            (0xF6, "name.key"), (0xF3, "header.key"),
            (0xF2, "primary.key"), (0xF1, "masks.key"),
            (0xF5, "primary2.key"), (0xF4, "masks2.key"),
        };

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            using var session = PcscApduSession.Open(reader);
            Select(session);
            List<ObjectEntry> entries = ListEntries(session);
            var result = new List<DirectTokenContainerRef>();
            foreach (ContainerEntries group in GroupContainers(entries))
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] name = ReadDer(session, group.ByCode[0xF6].Index);
                result.Add(new DirectTokenContainerRef
                {
                    Kind = RutokenKind.JaCartaLt,
                    Reader = reader,
                    Name = RutokenLiteApdu.ParseName(name),
                    OutputName = $"jacartalt_{group.ByCode[0xF6].Index:X2}",
                    Index = group.ByCode[0xF6].Index,
                });
            }
            return result;
        }

        public RutokenContainer ReadContainer(string reader, DirectTokenContainerRef selected,
                                              string pin)
        {
            if (selected == null) throw new ArgumentNullException(nameof(selected));
            if (string.IsNullOrEmpty(pin))
                throw new LiteApduException(Strings.Format("err.lite.pin", "—"));

            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            using var session = PcscApduSession.Open(reader);
            Select(session);
            List<ContainerEntries> groups = GroupContainers(ListEntries(session));
            ContainerEntries group = groups.FirstOrDefault(candidate =>
                candidate.ByCode.TryGetValue(0xF6, out ObjectEntry name)
                && name.Index == selected.Index);
            if (group == null)
                throw new LiteApduException(Strings.Format("err.lite.none", reader));

            Login(session, pin);
            foreach (var mapping in Files)
            {
                Cancel.ThrowIfCancellationRequested();
                if (!group.ByCode.TryGetValue(mapping.Code, out ObjectEntry entry)) continue;
                byte[] value = ReadDer(session, entry.Index);
                blobs[mapping.File] = value;
                Say($"  {mapping.File} ({value.Length})");
            }
            ValidateBlobs(blobs, reader);
            return new RutokenContainer
            {
                TokenName = reader,
                TokenDir = $"APDU/LT/{selected.Index:X2}",
                ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                    ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                Files = blobs,
            };
        }

        private static void Select(PcscApduSession session)
        {
            byte[] response = session.Transmit(SelectApplet);
            PcscApduSession.RequireOk(response, "SELECT JaCarta LT");
        }

        private static void Login(PcscApduSession session, string pin)
        {
            if (pin.Length is < 1 or > 32 || pin.Any(character => character > 0x7F))
                throw new LiteApduException(Strings.Format("err.lite.pin", "0x6A80"));
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pin);
            var command = new List<byte>
                { 0x80, 0x10, 0x10, 0x00, checked((byte)(bytes.Length + 2)), 0x00, checked((byte)bytes.Length) };
            command.AddRange(bytes);
            byte[] response = session.Transmit(command.ToArray());
            if (!PcscApduSession.IsOk(response))
                throw new LiteApduException(Strings.Format(
                    "err.lite.pin", "0x" + PcscApduSession.Status(response).ToString("X4")));
        }

        private List<ObjectEntry> ListEntries(PcscApduSession session)
        {
            var result = new List<ObjectEntry>();
            for (ushort offset = 0; offset < 4096;)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] response = session.Transmit(new byte[]
                    { 0x80, 0x20, 0x60, 0x00, 0x02,
                      (byte)(offset >> 8), (byte)offset, 0x00 });
                PcscApduSession.RequireOk(response, "LIST JaCarta LT");
                byte[] data = PcscApduSession.Data(response);
                if (data.Length == 0) break;
                List<ObjectEntry> page = ParseObjectTable(data);
                result.AddRange(page);
                offset = checked((ushort)(offset + page.Count));
            }
            return result;
        }

        internal static List<ObjectEntry> ParseObjectTable(byte[] data)
        {
            if (data == null || data.Length % 7 != 0)
                throw ProtocolError("OBJECT_TABLE_FORMAT");
            var result = new List<ObjectEntry>();
            for (int offset = 0; offset < data.Length; offset += 7)
            {
                if (data[offset] != 0)
                    throw ProtocolError("OBJECT_TABLE_MARKER");
                result.Add(new ObjectEntry(data[offset + 1], data[offset + 2],
                    data[offset + 3], new byte[]
                        { data[offset + 4], data[offset + 5], data[offset + 6] }));
            }
            return result;
        }

        internal static List<ContainerEntries> GroupContainers(IReadOnlyList<ObjectEntry> entries)
        {
            var result = new List<ContainerEntries>();
            for (int i = 0; i < (entries?.Count ?? 0); i++)
            {
                ObjectEntry current = entries[i];
                // name.key (0xF6) отмечает начало контейнера. Его Type — общий идентификатор
                // всех шести файлов ЭТОГО контейнера; у разных контейнеров он разный (0x03,
                // 0x0E, …). Раньше тип был захардкожен 0x03, поэтому на носителе со вторым
                // контейнером тот целиком терялся — снять его по APDU было нельзя.
                if (current.Code != 0xF6) continue;
                byte containerType = current.Type;
                var group = new ContainerEntries();
                for (int j = i; j < entries.Count; j++)
                {
                    ObjectEntry candidate = entries[j];
                    if (j != i && candidate.Code == 0xF6) break;
                    if (candidate.Type == containerType
                        && Files.Any(file => file.Code == candidate.Code)
                        && !group.ByCode.ContainsKey(candidate.Code))
                        group.ByCode[candidate.Code] = candidate;
                }
                bool exchange = group.ByCode.ContainsKey(0xF2) && group.ByCode.ContainsKey(0xF1);
                bool signature = group.ByCode.ContainsKey(0xF5) && group.ByCode.ContainsKey(0xF4);
                if (group.ByCode.ContainsKey(0xF3) && (exchange || signature)) result.Add(group);
            }
            return result;
        }

        private static byte[] ReadDer(PcscApduSession session, byte index)
        {
            byte[] header = Read(session, index, 0, 4);
            int total = DerLength(header);
            var result = new byte[total];
            int offset = 0;
            while (offset < total)
            {
                int count = Math.Min(240, total - offset);
                byte[] chunk = Read(session, index, checked((ushort)offset), checked((ushort)count));
                if (chunk.Length < count) throw ProtocolError("SHORT_READ");
                Array.Copy(chunk, 0, result, offset, count);
                offset += count;
            }
            return result;
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
            if (total > ushort.MaxValue)
                throw ProtocolError("OBJECT_SIZE");
            return total;
        }

        private static byte[] Read(PcscApduSession session, byte index, ushort offset, ushort count)
        {
            byte[] response = session.Transmit(new byte[]
                { 0x80, 0x20, 0x30, 0x00, 0x06, 0x00, index,
                  (byte)(offset >> 8), (byte)offset,
                  (byte)(count >> 8), (byte)count, 0x00 });
            PcscApduSession.RequireOk(response, $"READ JaCarta LT {index:X2}");
            return PcscApduSession.Data(response);
        }

        private static LiteApduException ProtocolError(string code) =>
            new LiteApduException(Strings.Format("err.com.call", "JaCarta LT APDU", code));

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

        internal readonly struct ObjectEntry
        {
            public ObjectEntry(byte index, byte type, byte code, byte[] metadata)
            {
                Index = index; Type = type; Code = code; Metadata = metadata;
            }
            public byte Index { get; }
            public byte Type { get; }
            public byte Code { get; }
            public byte[] Metadata { get; }
        }

        internal sealed class ContainerEntries
        {
            public Dictionary<byte, ObjectEntry> ByCode { get; } = new Dictionary<byte, ObjectEntry>();
        }
    }
}
