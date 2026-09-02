using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Read-only доступ к файловым контейнерам КриптоПро на носителе БИФИТ/МультиСофт
    /// MS_KEY K «АНГАРА» напрямую по APDU (PC/SC), минуя CSP.
    ///
    /// Протокол снят прокси-winscard'ом со штатного csptest на живом носителе и проверен
    /// независимым чтением без КриптоПро (разбор — docs/apdu/bifit-mskey.md):
    ///   • приложение выбирается по имени <c>MSKEYKC</c> (AID 4D 53 4B 45 59 4B 43);
    ///   • контейнер — DF с FID <c>00&lt;base&gt;</c>, base ∈ {01, 11, 21, …} (шаг 0x10);
    ///   • внутри DF шесть логических *.key лежат в EF <c>00&lt;base+offset&gt;</c>:
    ///     masks(+0), primary(+1), header(+2), name(+5);
    ///   • name.key и header.key читаются без авторизации, primary.key и masks.key —
    ///     после VERIFY по ссылке P2=0x7D (для контейнеров protected=none это транспортный
    ///     «11111111», который CSP посылает сам).
    ///
    /// Носитель — пассивная файловая карта: карточных крипто-команд в обмене нет, поэтому
    /// прочитанный маскированный закрытый ключ восстанавливает офлайн
    /// <see cref="ContainerKeyExtractor"/> (как у Rutoken Lite / JaCarta LT). Команды создания,
    /// удаления и записи этот backend никогда не отправляет.
    /// </summary>
    internal sealed class MsKeyAngaraApdu
    {
        // Приложение КриптоПро на MS_KEY K: SELECT по имени (DF name) "MSKEYKC".
        private static readonly byte[] ApplicationId =
            { 0x4D, 0x53, 0x4B, 0x45, 0x59, 0x4B, 0x43 };

        // База DF первого контейнера и шаг между контейнерами в файловой памяти.
        private const int FirstBase = 0x01;
        private const int BaseStep = 0x10;
        private const int MaxContainers = 16;

        // Смещение EF внутри DF -> имя логического файла контейнера.
        private static readonly (int Offset, string File)[] Files =
        {
            (0x00, "masks.key"), (0x01, "primary.key"),
            (0x02, "header.key"), (0x05, "name.key"),
        };

        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;
        private void Say(string message) => Log?.Invoke(message);

        public List<DirectTokenContainerRef> ListContainers(string reader)
        {
            var result = new List<DirectTokenContainerRef>();
            using var session = PcscApduSession.Open(reader);
            if (!SelectApplication(session)) return result;   // не MS_KEY K (напр. iBank2Key)
            for (int index = 0; index < MaxContainers; index++)
            {
                Cancel.ThrowIfCancellationRequested();
                int df = ContainerBase(index);
                if (!SelectApplication(session) || !SelectDf(session, df)) continue;
                // name.key доступен без PIN — по нему и опознаётся контейнер. Носитель держит
                // пустые предвыделенные слоты (все EF из нулей): их отбраковываем — настоящий
                // контейнер начинается с валидного DER-SEQUENCE и несёт непустое имя.
                byte[] name = ReadFile(session, EfId(df, 0x05));
                if (!IsDerSequence(name) || string.IsNullOrEmpty(RutokenLiteApdu.ParseName(name)))
                    continue;
                // header доступен без PIN — проверяем его содержимое, а не только существование.
                if (!IsDerSequence(ReadFile(session, EfId(df, 0x02)))) continue; // header.key
                bool key = FileExists(session, EfId(df, 0x01))                   // primary.key
                    && FileExists(session, EfId(df, 0x00));                      // masks.key
                if (!key) continue;
                result.Add(new DirectTokenContainerRef
                {
                    Kind = RutokenKind.Bifit,
                    Reader = reader,
                    Name = RutokenLiteApdu.ParseName(name),
                    OutputName = $"angara_{df:X2}",
                    Index = index,
                });
            }
            return result;
        }

        public RutokenContainer ReadContainer(string reader, DirectTokenContainerRef selected,
                                              string pin)
        {
            if (selected == null || selected.Index is < 0 or >= MaxContainers)
                throw new ArgumentException(nameof(selected));
            if (string.IsNullOrEmpty(pin))
                throw new LiteApduException(Strings.Format("err.lite.pin", "—"));

            int df = ContainerBase(selected.Index);
            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            using var session = PcscApduSession.Open(reader);
            if (!SelectApplication(session) || !SelectDf(session, df))
                throw new LiteApduException(Strings.Format("err.lite.none", reader));
            VerifyPin(session, pin);
            foreach (var (offset, file) in Files)
            {
                Cancel.ThrowIfCancellationRequested();
                byte[] value = ReadFile(session, EfId(df, offset));
                if (value == null) continue;
                blobs[file] = value;
                Say($"  {file} ({value.Length})");
            }

            ValidateBlobs(blobs, reader);
            return new RutokenContainer
            {
                TokenName = reader,
                TokenDir = $"APDU/ANGARA/{df:X2}",
                ContainerName = blobs.TryGetValue("name.key", out byte[] name)
                    ? RutokenLiteApdu.ParseName(name) ?? selected.Name : selected.Name,
                Files = blobs,
            };
        }

        /// <summary>Начинается ли блоб с DER-SEQUENCE (0x30) — отличает контейнер от пустого слота.</summary>
        internal static bool IsDerSequence(byte[] blob) =>
            blob != null && blob.Length >= 2 && blob[0] == 0x30;

        internal static int ContainerBase(int index)
        {
            if (index is < 0 or >= MaxContainers)
                throw new ArgumentOutOfRangeException(nameof(index));
            return FirstBase + index * BaseStep;
        }

        internal static byte EfId(int df, int offset)
        {
            int ef = df + offset;
            if (df is < 0 or > 0xFF || ef is < 0 or > 0xFF)
                throw new ArgumentOutOfRangeException(nameof(offset));
            return (byte)ef;
        }

        // ---------------------------------------------------------------- APDU

        private static bool SelectApplication(PcscApduSession session)
        {
            var command = new byte[5 + ApplicationId.Length];
            command[0] = 0x00; command[1] = 0xA4; command[2] = 0x04; command[3] = 0x0C;
            command[4] = (byte)ApplicationId.Length;
            Array.Copy(ApplicationId, 0, command, 5, ApplicationId.Length);
            return PcscApduSession.IsOk(session.TransmitWithGetResponse(command));
        }

        // SELECT DF по FID: P1=00 (по идентификатору), P2=0C (без данных ответа).
        private static bool SelectDf(PcscApduSession session, int df) =>
            PcscApduSession.IsOk(session.TransmitWithGetResponse(
                new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x00, (byte)df }));

        // SELECT EF по FID: P1=00, P2=04 (вернуть FCP). null, если EF нет.
        private static byte[] TrySelectFile(PcscApduSession session, byte ef)
        {
            byte[] response = session.TransmitWithGetResponse(
                new byte[] { 0x00, 0xA4, 0x00, 0x04, 0x02, 0x00, ef });
            int status = PcscApduSession.Status(response);
            if (status is 0x6A82 or 0x6A83) return null;
            PcscApduSession.RequireOk(response, $"SELECT ANGARA EF 00{ef:X2}");
            byte[] fcp = PcscApduSession.Data(response);
            if (FcpSize(fcp) <= 0) throw ProtocolError("FCP_SIZE");
            return fcp;
        }

        private static bool FileExists(PcscApduSession session, byte ef) =>
            TrySelectFile(session, ef) != null;

        private static byte[] ReadFile(PcscApduSession session, byte ef)
        {
            byte[] fcp = TrySelectFile(session, ef);
            return fcp == null ? null : RutokenLiteApdu.TrimDer(ReadBinary(session, FcpSize(fcp)));
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
                    { 0x00, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), (byte)count });
                PcscApduSession.RequireOk(response, "READ BINARY ANGARA");
                byte[] data = PcscApduSession.Data(response);
                if (data.Length == 0) throw ProtocolError("SHORT_READ");
                int take = Math.Min(data.Length, size - offset);
                Array.Copy(data, 0, output, offset, take);
                offset += take;
            }
            return output;
        }

        // VERIFY по ссылке доступа контейнера (P2=0x7D). PIN не подбираем: значение задаёт
        // вызывающий; для protected=none это транспортный «11111111», который посылает сам CSP.
        private static void VerifyPin(PcscApduSession session, string pin)
        {
            if (pin.Length is < 1 or > 100 || pin.Any(character => character > 0x7F))
                throw new LiteApduException(Strings.Format("err.lite.pin", "0x6A80"));
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(pin);
            var command = new byte[5 + bytes.Length];
            command[0] = 0x00; command[1] = 0x20; command[2] = 0x00;
            command[3] = 0x7D; command[4] = checked((byte)bytes.Length);
            Array.Copy(bytes, 0, command, 5, bytes.Length);
            byte[] response = session.Transmit(command);
            if (!PcscApduSession.IsOk(response))
                throw new LiteApduException(Strings.Format(
                    "err.lite.pin", "0x" + PcscApduSession.Status(response).ToString("X4")));
        }

        internal static int FcpSize(byte[] fcp)
        {
            byte[] value = EsmartApdu.FindTag(fcp, 0x80);
            if (value == null || value.Length is < 1 or > 2) return -1;
            int size = 0;
            foreach (byte item in value) size = (size << 8) | item;
            return size > 0 ? size : -1;
        }

        private static void ValidateBlobs(IReadOnlyDictionary<string, byte[]> blobs, string source)
        {
            foreach (string common in new[] { "name.key", "header.key" })
                if (!blobs.ContainsKey(common))
                    throw new LiteApduException(Strings.Format("err.extract.nofile", common, source));
            bool primary = blobs.ContainsKey("primary.key");
            bool masks = blobs.ContainsKey("masks.key");
            if (primary != masks)
                throw new LiteApduException(Strings.Format("err.extract.nofile",
                    primary ? "masks.key" : "primary.key", source));
            if (!primary)
                throw new LiteApduException(Strings.Format(
                    "err.extract.nofile", "primary.key", source));
        }

        private static LiteApduException ProtocolError(string code) =>
            new LiteApduException(Strings.Format("err.com.call", "ANGARA APDU", code));
    }
}
