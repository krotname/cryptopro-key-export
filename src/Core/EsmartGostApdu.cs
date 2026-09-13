using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Read-only доступ к файловым контейнерам КриптоПро на ESMART Token ГОСТ (платформа MIK51,
    /// 72 КБ). В отличие от «ISBC ESMART Token»/«ESMART Token USB 64K» этот носитель показывает
    /// не собственное имя, а универсальный CCID-считыватель Feitian SCR301, поэтому семейство и
    /// принадлежность карты подтверждаются точными model/manufacturer PKCS#11 и live ATR
    /// (см. <see cref="EsmartApdu.IsExactLiveGostReader"/>), а сам считыватель открывается с
    /// проверкой ATR.
    ///
    /// Файловая раскладка тоже иная и подтверждена трассировкой штатного csptest на собственном
    /// экземпляре: MF → апплеты <c>F0 49 53 42 43 44 48</c> (ISBCDH) и <c>F0 49 53 42 43</c> (ISBC),
    /// хранилище выбирается по пути <c>8F01/7F01</c>, а контейнеры занимают группы EF
    /// <c>F011…F016</c>, <c>F021…F026</c> и далее по таблице carrier CSP
    /// обычным DER (без служебного префикса старого ESMART), доступ на чтение открывает VERIFY PIN
    /// по ссылке <c>0x83</c>. Команды создания, записи и удаления backend не отправляет никогда —
    /// закрытый ключ (primary+masks) сходит с карты открытым текстом, как у прочих пассивных
    /// CSP-носителей.
    /// </summary>
    internal sealed class EsmartGostApdu
    {
        private const int FirstSlot = 1;
        private const int LastSlot = 24;

        // Апплеты, устанавливающие контекст чтения (порядок и значения — из трассы csptest).
        // У ISBCDH хвостовой байт 00 обязателен: карта отвечает на точный 8-байтный AID
        // (Lc=08). Проверено на железе — 7-байтный `F0 49 53 42 43 44 48` даёт 6A82.
        private static readonly byte[] AppletIsbcDh = Convert.FromHexString("F049534243444800");
        private static readonly byte[] AppletIsbc = Convert.FromHexString("F049534243");

        // Файлы контейнера ГОСТ: суффиксы 1..6 идут подряд, вторая пара — 04/05
        // (у старого ESMART вторая пара лежит на 0x11/0x12).
        private static readonly (int Suffix, string File)[] Files =
        {
            (0x06, "name.key"), (0x03, "header.key"),
            (0x02, "primary.key"), (0x01, "masks.key"),
            (0x05, "primary2.key"), (0x04, "masks2.key"),
        };

        // Чтение всех ключевых EF (обе пары) открывает VERIFY по одной ссылке 0x83 —
        // проверено на железе. Спекулятивный VERIFY по 0x81 не шлём: если у карты
        // разные секреты 0x81/0x83, подстановка 0x83-PIN в 0x81 молча сжигала бы попытку
        // и могла заблокировать этот credential при повторных экспортах.
        private const byte ReadPinReference = 0x83;

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            var result = new List<DirectTokenContainerRef>();
            using var session = PcscApduSession.Open(reader, EsmartApdu.GostExactAtr);
            SelectStore(session);
            for (int slot = FirstSlot; slot <= LastSlot; slot++)
            {
                Cancel.ThrowIfCancellationRequested();
                // Контейнер считается настоящим только с header.key и хотя бы одной парой ключей.
                bool header = SelectFile(session, FileId(slot: slot, suffix: 0x03)) != null;
                bool exchange = FileExists(session, slot, 0x02) && FileExists(session, slot, 0x01);
                bool signature = FileExists(session, slot, 0x05) && FileExists(session, slot, 0x04);
                if (!header || (!exchange && !signature)) continue;

                byte[] nameFcp = SelectFile(session, FileId(slot, 0x06));
                if (nameFcp == null) continue;
                byte[] name = ReadSelected(session, EsmartApdu.FcpSize(nameFcp));
                result.Add(new DirectTokenContainerRef
                {
                    Kind = RutokenKind.Esmart,
                    Reader = reader,
                    Name = RutokenLiteApdu.ParseName(name),
                    OutputName = OutputName(slot),
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
            using var session = PcscApduSession.Open(reader, EsmartApdu.GostExactAtr);
            SelectStore(session);
            VerifyPin(session, pin);
            foreach (var mapping in Files)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] fcp = SelectFile(session, FileId(selected.Index, mapping.Suffix));
                if (fcp == null) continue;
                byte[] value = ReadSelected(session, EsmartApdu.FcpSize(fcp));
                if (value == null) continue;
                blobs[mapping.File] = value;
                Say($"  {mapping.File} ({value.Length})");
            }

            ValidateBlobs(blobs, reader);
            return new RutokenContainer
            {
                TokenName = reader,
                TokenDir = $"APDU/ESMARTGOST/{OutputName(selected.Index)}",
                ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                    ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                Files = blobs,
            };
        }

        internal static ushort FileId(int slot, int suffix)
        {
            if (slot is < FirstSlot or > LastSlot || suffix is < 0 or > 0x0F)
                throw new ArgumentOutOfRangeException(nameof(slot));
            return checked((ushort)(FolderId(slot) | suffix));
        }

        internal static ushort FolderId(int slot)
        {
            if (slot is < FirstSlot or > LastSlot) throw new ArgumentOutOfRangeException(nameof(slot));
            // Точная таблица ESMARTTokenGOST/Default/Folders из CryptoPro CSP:
            // F010…F0F0, затем F110…F190 (F100 зарезервирован и пропущен).
            return checked((ushort)(slot <= 15
                ? 0xF000 | (slot << 4)
                : 0xF100 | ((slot - 15) << 4)));
        }

        // До исправления многослотового обхода первый контейнер уже публиковался как 7F01.
        // Сохраняем этот идентификатор и добавляем к нему реальный FID для следующих слотов.
        internal static string OutputName(int slot)
        {
            if (slot is < FirstSlot or > LastSlot) throw new ArgumentOutOfRangeException(nameof(slot));
            return slot == 1 ? "esmartgost_7F01" : $"esmartgost_7F01_{FolderId(slot):X4}";
        }

        private void SelectStore(PcscApduSession session)
        {
            byte[] mf = session.TransmitWithGetResponse(new byte[] { 0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00 });
            PcscApduSession.RequireOk(mf, "SELECT ESMART GOST MF");
            SelectAidExact(session, AppletIsbcDh, "SELECT ISBCDH");
            SelectAidExact(session, AppletIsbc, "SELECT ISBC");
            byte[] path = { 0x8F, 0x01, 0x7F, 0x01 };
            var command = new byte[5 + path.Length];
            command[0] = 0x00; command[1] = 0xA4; command[2] = 0x08; command[3] = 0x00;
            command[4] = checked((byte)path.Length);
            Array.Copy(path, 0, command, 5, path.Length);
            PcscApduSession.RequireOk(session.TransmitWithGetResponse(command),
                "SELECT ESMART GOST 8F01/7F01");
        }

        private static void SelectAidExact(PcscApduSession session, byte[] aid, string label)
        {
            var command = new byte[5 + aid.Length];
            command[0] = 0x00; command[1] = 0xA4; command[2] = 0x04; command[3] = 0x00;
            command[4] = checked((byte)aid.Length);
            Array.Copy(aid, 0, command, 5, aid.Length);
            PcscApduSession.RequireOk(session.TransmitWithGetResponse(command), label);
        }

        private static bool FileExists(PcscApduSession session, int slot, int suffix) =>
            SelectFile(session, FileId(slot, suffix)) != null;

        private static byte[] SelectFile(PcscApduSession session, ushort fileId)
        {
            byte[] response = session.TransmitWithGetResponse(new byte[]
                { 0x00, 0xA4, 0x00, 0x00, 0x02, (byte)(fileId >> 8), (byte)fileId });
            if (PcscApduSession.Status(response) == 0x6A82) return null;
            PcscApduSession.RequireOk(response, $"SELECT ESMART GOST {fileId:X4}");
            byte[] fcp = PcscApduSession.Data(response);
            if (EsmartApdu.FcpSize(fcp) <= 0) throw ProtocolError("FCP_SIZE");
            return fcp;
        }

        private static byte[] ReadSelected(PcscApduSession session, int size) =>
            RutokenLiteApdu.TrimDer(ReadBinary(session, size));

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
                PcscApduSession.RequireOk(response, "READ BINARY ESMART GOST");
                byte[] data = PcscApduSession.Data(response);
                if (data.Length == 0) throw ProtocolError("SHORT_READ");
                int take = Math.Min(data.Length, size - offset);
                Array.Copy(data, 0, output, offset, take);
                offset += take;
            }
            return output;
        }

        private void VerifyPin(PcscApduSession session, string pin)
        {
            if (pin.Length is < 4 or > 100 || pin.Any(character => character > 0x7F))
                throw new LiteApduException(Strings.Format("err.lite.pin", "0x6A80"));
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pin);
            var command = new byte[5 + bytes.Length];
            command[0] = 0x00; command[1] = 0x20; command[2] = 0x00;
            command[3] = ReadPinReference; command[4] = checked((byte)bytes.Length);
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
            new LiteApduException(Strings.Format("err.com.call", "ESMART GOST APDU", code));
    }
}
