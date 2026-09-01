using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace CryptoProExport
{
    /// <summary>Ошибка обмена с Рутокен Lite по APDU (PC/SC).</summary>
    public sealed class LiteApduException : Exception
    {
        public LiteApduException(string message) : base(message) { }
    }

    /// <summary>Ссылка на контейнер КриптоПро в файловой памяти Lite: индекс DF и имя.</summary>
    public sealed class LiteContainerRef
    {
        /// <summary>Индекс каталога контейнера (старший байт FID: DF = &lt;index&gt;00).</summary>
        public int DfIndex { get; internal set; }
        /// <summary>Имя контейнера из name.key (cp1251), если удалось прочитать.</summary>
        public string Name { get; internal set; }
    }

    /// <summary>
    /// Читает файловый контейнер КриптоПро с Рутокен Lite напрямую по APDU (PC/SC),
    /// минуя CSP и rtCOMLite (который файловую память Lite не видит, AGENTS п. 20).
    /// Контейнер лежит в файловой памяти карты: DF <c>&lt;idx&gt;00</c>, шесть <c>*.key</c> —
    /// EF <c>&lt;idx&gt;0N</c>. Снятые файлы разбирает <see cref="ContainerKeyExtractor"/>.
    /// Протокол проверен на живом токене (fw 9.02), разбор — docs/apdu/rutoken-lite-fw9.md.
    /// </summary>
    public sealed class RutokenLiteApdu
    {
        /// <summary>Журнал прогресса (как у остальных исполнителей). Может быть null.</summary>
        public Action<string> Log { get; set; }
        private void Say(string s) => Log?.Invoke(s);

        // Абсолютный путь EF от MF, наблюдённый в трассе CSP: 1000/1003/<DF>/<EF>.
        private static readonly byte[] PathPrefix = { 0x10, 0x00, 0x10, 0x03 };

        // Суффикс EF (младший байт FID) -> имя файла контейнера. Обмен: 01/02, подпись: 04/05.
        private static readonly (int Suffix, string File)[] Files =
        {
            (0x01, "masks.key"),   (0x02, "primary.key"),
            (0x03, "header.key"),  (0x06, "name.key"),
            (0x04, "masks2.key"),  (0x05, "primary2.key"),
        };

        /// <summary>
        /// Перечисляет контейнеры на Lite, читая только name.key — <b>без ввода PIN</b>
        /// (имя доступно без авторизации, счётчик попыток не тратится). Возвращает пустой
        /// список, если контейнеров нет.
        /// </summary>
        public List<LiteContainerRef> ListContainers(string reader)
        {
            var list = new List<LiteContainerRef>();
            using (var s = ApduSession.Open(reader))
            {
                for (int df = 1; df <= 0x40; df++)
                {
                    if (!s.SelectPath(df, 0)) continue;         // каталога с таким индексом нет
                    byte[] name = s.TryReadEf(df, 0x06);         // name.key — без PIN
                    if (name == null) continue;                  // это не контейнер КриптоПро
                    list.Add(new LiteContainerRef { DfIndex = df, Name = ParseName(name) });
                }
            }
            return list;
        }

        /// <summary>
        /// Снимает контейнер с индексом <paramref name="dfIndex"/> в папку <paramref name="outDir"/>
        /// (шесть <c>*.key</c>). Требует верный PIN для чтения ключевых файлов; PIN <b>не подбирается</b>
        /// — вызывающий обязан убедиться в его правильности (см. <see cref="Pkcs11Token"/>,
        /// флаг <c>PinDefault</c>). Возвращает имя контейнера из name.key.
        /// </summary>
        public string ReadContainer(string reader, int dfIndex, string pin, string outDir)
        {
            if (string.IsNullOrEmpty(pin)) throw new LiteApduException(Strings.Format("err.lite.pin", "—"));
            if (dfIndex <= 0 || dfIndex > byte.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(dfIndex));

            // До успешной авторизации и полного чтения карту с диском не смешиваем: прежняя
            // реализация удаляла старые *.key ещё до VERIFY PIN, и опечатка в PIN уничтожала
            // уже существующий годный бэкап.
            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            string name = null;
            using (var s = ApduSession.Open(reader))
            {
                if (!s.SelectPath(dfIndex, 0))
                    throw new LiteApduException(Strings.Format("err.lite.none", reader));
                s.VerifyPin(pin);
                foreach (var (suffix, file) in Files)
                {
                    byte[] blob = s.TryReadEf(dfIndex, suffix);
                    if (blob == null) continue;                  // пары подписи может не быть
                    blob = TrimDer(blob);                        // на карте EF добит FF до размера файла
                    blobs[file] = blob;
                    if (suffix == 0x06) name = ParseName(blob);
                    Say($"  {file} ({blob.Length})");   // только данные — переводить нечего
                }
            }
            SaveFiles(outDir, blobs);
            return name;
        }

        /// <summary>
        /// Записать уже полностью прочитанный набор файлов. Общие header/name обязательны,
        /// каждая присутствующая пара ключа должна быть целой, и нужна хотя бы одна пара
        /// (обмена или подписи). Старые файлы удаляются только после успешной подготовки новых.
        /// </summary>
        internal static void SaveFiles(string outDir, IReadOnlyDictionary<string, byte[]> blobs)
        {
            if (outDir == null) throw new ArgumentNullException(nameof(outDir));
            foreach (string required in new[] { "header.key", "name.key" })
                if (blobs == null || !blobs.ContainsKey(required) || blobs[required] == null)
                    throw new LiteApduException(Strings.Format("err.extract.nofile", required, outDir));

            bool hasMasks = blobs.ContainsKey("masks.key") && blobs["masks.key"] != null;
            bool hasPrimary = blobs.ContainsKey("primary.key") && blobs["primary.key"] != null;
            if (hasMasks != hasPrimary)
            {
                string missing = hasMasks ? "primary.key" : "masks.key";
                throw new LiteApduException(Strings.Format("err.extract.nofile", missing, outDir));
            }

            bool hasMasks2 = blobs.ContainsKey("masks2.key") && blobs["masks2.key"] != null;
            bool hasPrimary2 = blobs.ContainsKey("primary2.key") && blobs["primary2.key"] != null;
            if (hasMasks2 != hasPrimary2)
            {
                string missing = hasMasks2 ? "primary2.key" : "masks2.key";
                throw new LiteApduException(Strings.Format("err.extract.nofile", missing, outDir));
            }
            if (!hasPrimary && !hasPrimary2)
                throw new LiteApduException(Strings.Format(
                    "err.extract.nofile", "primary.key / primary2.key", outDir));

            string destination = Path.GetFullPath(outDir).TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string parent = Path.GetDirectoryName(destination)
                ?? throw new ArgumentException(Strings.Format("err.folder.notlike", outDir));
            Directory.CreateDirectory(parent);
            string leaf = Path.GetFileName(destination);
            string nonce = Guid.NewGuid().ToString("N");
            string staging = Path.Combine(parent, "." + leaf + "." + nonce + ".tmp");
            string rollback = Path.Combine(parent, "." + leaf + "." + nonce + ".rollback");
            Directory.CreateDirectory(staging);
            Directory.CreateDirectory(rollback);
            var existed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var (_, file) in Files)
                {
                    if (!blobs.TryGetValue(file, out byte[] bytes) || bytes == null) continue;
                    File.WriteAllBytes(Path.Combine(staging, file), bytes);
                }

                Directory.CreateDirectory(destination);
                foreach (var (_, file) in Files)
                {
                    string target = Path.Combine(destination, file);
                    if (!File.Exists(target)) continue;
                    File.Copy(target, Path.Combine(rollback, file));
                    existed.Add(file);
                }

                try
                {
                    foreach (var (_, file) in Files)
                    {
                        string prepared = Path.Combine(staging, file);
                        string target = Path.Combine(destination, file);
                        if (File.Exists(prepared)) OverwriteFile(prepared, target);
                        else if (File.Exists(target)) File.Delete(target);
                    }
                }
                catch (Exception commitError)
                {
                    var rollbackErrors = new List<Exception>();
                    foreach (var (_, file) in Files)
                    {
                        try
                        {
                            string target = Path.Combine(destination, file);
                            if (existed.Contains(file))
                                OverwriteFile(Path.Combine(rollback, file), target);
                            else if (File.Exists(target))
                                File.Delete(target);
                        }
                        catch (Exception e) { rollbackErrors.Add(e); }
                    }
                    if (rollbackErrors.Count != 0)
                    {
                        rollbackErrors.Insert(0, commitError);
                        throw new AggregateException(rollbackErrors);
                    }
                    throw;
                }
            }
            finally
            {
                if (Directory.Exists(staging))
                    try { Directory.Delete(staging, recursive: true); } catch (IOException) { }
                if (Directory.Exists(rollback))
                    try { Directory.Delete(rollback, recursive: true); } catch (IOException) { }
            }
        }

        /// <summary>
        /// Атомарно занять имя каталога до долгого чтения карты. Простая проверка Exists
        /// оставляет race между двумя процессами с одинаковым DF index.
        /// </summary>
        public static string ReserveOutputDirectory(string parent, string baseName)
        {
            if (parent == null) throw new ArgumentNullException(nameof(parent));
            Directory.CreateDirectory(parent);
            baseName = RutokenContainer.SafeFolderName(baseName);
            string reservation = Path.Combine(parent, ".cpx-reserve-" + Guid.NewGuid().ToString("N") + ".tmp");
            Directory.CreateDirectory(reservation);
            try
            {
                for (int n = 1; n <= 1000; n++)
                {
                    string name = n == 1 ? baseName : $"{baseName}({n})";
                    string path = Path.Combine(parent, name);
                    if (Directory.Exists(path) || File.Exists(path)) continue;
                    try
                    {
                        Directory.Move(reservation, path);
                        return path;
                    }
                    catch (IOException) when (Directory.Exists(path) || File.Exists(path))
                    {
                        // Другой процесс занял кандидат после проверки — пробуем следующий.
                    }
                }
                throw new IOException(Strings.Format("err.store.full", parent));
            }
            finally
            {
                if (Directory.Exists(reservation))
                    try { Directory.Delete(reservation); } catch (IOException) { }
            }
        }

        /// <summary>Перезаписать содержимое файла, сохранив ACL существующего файла.</summary>
        private static void OverwriteFile(string source, string target)
        {
            using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None);
            input.CopyTo(output);
            output.Flush(flushToDisk: true);
        }

        /// <summary>
        /// Обрезает EF до конца первого ASN.1-объекта: на карте файл имеет фиксированный размер и
        /// добит байтами <c>FF</c>, а разбор (<see cref="ContainerKeyExtractor"/>) ждёт «чистый» DER,
        /// как в файловом контейнере на диске. Если это не DER (не 0x30) — возвращает как есть.
        /// </summary>
        internal static byte[] TrimDer(byte[] blob)
        {
            if (blob == null || blob.Length < 2 || blob[0] != 0x30) return blob;
            int lenByte = blob[1];
            int total;
            if (lenByte < 0x80) total = 2 + lenByte;
            else
            {
                int n = lenByte & 0x7F;
                if (n == 0 || n > 4 || 2 + n > blob.Length) return blob;
                int len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | blob[2 + i];
                total = 2 + n + len;
            }
            if (total <= 0 || total > blob.Length) return blob;
            if (total == blob.Length) return blob;
            var t = new byte[total];
            Array.Copy(blob, t, total);
            return t;
        }

        /// <summary>FCP: тег 0x80 (2 байта) = число байт содержимого EF. -1 если нет.</summary>
        internal static int FcpSize(byte[] fcp)
        {
            if (fcp == null) return -1;
            int i = 0;
            if (fcp.Length >= 2 && fcp[0] == 0x62) i = 2;       // войти в шаблон FCP
            while (i + 2 <= fcp.Length)
            {
                int tag = fcp[i], len = fcp[i + 1];
                if (tag == 0x90 && len == 0x00) break;           // добрались до SW
                if (tag == 0x80 && len == 2 && i + 4 <= fcp.Length)
                    return (fcp[i + 2] << 8) | fcp[i + 3];
                i += 2 + len;
            }
            return -1;
        }

        /// <summary>name.key = SEQUENCE { строка }. Достаёт значение строки в cp1251; null при сбое.</summary>
        internal static string ParseName(byte[] nameKey)
        {
            try
            {
                // 30 Lf  <tag> Ln  <value>  — берём значение первого вложенного примитива.
                if (nameKey == null || nameKey.Length < 4 || nameKey[0] != 0x30) return null;
                int p = 2;                                   // короткая длина SEQUENCE (< 128)
                if (nameKey[1] >= 0x80) p = 2 + (nameKey[1] & 0x7F);
                if (p + 2 > nameKey.Length) return null;
                int len = nameKey[p + 1];
                int start = p + 2;
                if (len >= 0x80 || start + len > nameKey.Length) return null;
                return Cp1251.GetString(nameKey, start, len);
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ PC/SC session

        private sealed class ApduSession : IDisposable
        {
            private IntPtr _ctx, _card;
            private IoRequest _pci;

            public static ApduSession Open(string reader)
            {
                if (string.IsNullOrWhiteSpace(reader)) throw new LiteApduException(CryptoErrors.Describe(unchecked((int)0x80100009)));
                var s = new ApduSession();
                int rc;
                try { rc = SCardEstablishContext(SCOPE_USER, IntPtr.Zero, IntPtr.Zero, out s._ctx); }
                catch (DllNotFoundException e) { throw new LiteApduException(e.Message); }
                if (rc != 0) throw new LiteApduException(CryptoErrors.Describe(rc));
                rc = SCardConnect(s._ctx, reader, SHARE_SHARED, PROTO_T0 | PROTO_T1, out s._card, out uint active);
                if (rc != 0)
                {
                    SCardReleaseContext(s._ctx);
                    throw new LiteApduException(CryptoErrors.Describe(rc));
                }
                s._pci = new IoRequest { Protocol = active, PciLength = 8 };
                return s;
            }

            private byte[] Transmit(byte[] apdu)
            {
                var resp = new byte[4096];
                int len = resp.Length;
                int rc = SCardTransmit(_card, ref _pci, apdu, apdu.Length, IntPtr.Zero, resp, ref len);
                if (rc != 0) throw new LiteApduException(CryptoErrors.Describe(rc));
                var outp = new byte[len];
                Array.Copy(resp, outp, len);
                return outp;
            }

            private static bool Ok(byte[] r) => r.Length >= 2 && r[r.Length - 2] == 0x90 && r[r.Length - 1] == 0x00;

            /// <summary>SELECT по абсолютному пути 1000/1003/&lt;df&gt;00[/&lt;df&gt;&lt;ef&gt;]. true при 9000.</summary>
            public bool SelectPath(int df, int ef)
            {
                var path = new List<byte>(PathPrefix) { (byte)df, 0x00 };
                if (ef != 0) { path.Add((byte)df); path.Add((byte)ef); }
                var apdu = new List<byte> { 0x00, 0xA4, 0x08, 0x04, (byte)path.Count };
                apdu.AddRange(path); apdu.Add(0x00);
                return Ok(Transmit(apdu.ToArray()));
            }

            /// <summary>Выбирает EF и читает его целиком (по FCP-размеру, чанками ≤255). null если EF нет.</summary>
            public byte[] TryReadEf(int df, int ef)
            {
                var fcp = Transmit(BuildSelect(df, ef));
                if (!Ok(fcp)) return null;
                int size = RutokenLiteApdu.FcpSize(fcp);
                if (size <= 0) return null;
                var buf = new byte[size];
                int got = 0;
                while (got < size)
                {
                    int chunk = Math.Min(255, size - got);
                    var r = Transmit(new byte[] { 0x00, 0xB0, (byte)(got >> 8), (byte)got, (byte)chunk });
                    if (!Ok(r))
                        throw new LiteApduException(Strings.Format("err.com.call", "READ BINARY", Status(r)));
                    int n = Math.Min(r.Length - 2, size - got);
                    if (n <= 0)
                        throw new LiteApduException(Strings.Format("err.com.call", "READ BINARY", Hex(0)));
                    Array.Copy(r, 0, buf, got, n);
                    got += n;
                }
                return buf;
            }

            private static byte[] BuildSelect(int df, int ef)
            {
                var path = new List<byte>(PathPrefix) { (byte)df, 0x00, (byte)df, (byte)ef };
                var apdu = new List<byte> { 0x00, 0xA4, 0x08, 0x04, (byte)path.Count };
                apdu.AddRange(path); apdu.Add(0x00);
                return apdu.ToArray();
            }

            /// <summary>VERIFY PIN (00 20 00 02 Lc pin). Бросает при отказе карты — PIN не подбираем.</summary>
            public void VerifyPin(string pin)
            {
                Transmit(new byte[] { 0x80, 0x40, 0x00, 0x00 });     // штатная преамбула из трассы CSP
                if (pin.Length > byte.MaxValue)
                    throw new LiteApduException(Strings.Format("err.lite.pin", Hex(0x6700)));
                foreach (char c in pin)
                    if (c > 0x7F)
                        throw new LiteApduException(Strings.Format("err.lite.pin", Hex(0x6A80)));
                var bytes = System.Text.Encoding.ASCII.GetBytes(pin);
                var apdu = new byte[5 + bytes.Length];
                apdu[0] = 0x00; apdu[1] = 0x20; apdu[2] = 0x00; apdu[3] = 0x02; apdu[4] = (byte)bytes.Length;
                Array.Copy(bytes, 0, apdu, 5, bytes.Length);
                var r = Transmit(apdu);
                if (!Ok(r)) throw new LiteApduException(Strings.Format("err.lite.pin", Status(r)));
            }

            private static string Status(byte[] response) => response != null && response.Length >= 2
                ? Hex((response[response.Length - 2] << 8) | response[response.Length - 1])
                : Hex(0);

            private static string Hex(int code) => "0x" + ((uint)code).ToString("X8");

            public void Dispose()
            {
                if (_card != IntPtr.Zero) SCardDisconnect(_card, LEAVE_CARD);
                if (_ctx != IntPtr.Zero) SCardReleaseContext(_ctx);
                _card = _ctx = IntPtr.Zero;
            }
        }

        // ------------------------------------------------------------------ winscard P/Invoke

        [StructLayout(LayoutKind.Sequential)]
        private struct IoRequest { public uint Protocol; public uint PciLength; }

        private const uint SCOPE_USER = 0, SHARE_SHARED = 2, PROTO_T0 = 1, PROTO_T1 = 2, LEAVE_CARD = 0;

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(uint scope, IntPtr r1, IntPtr r2, out IntPtr ctx);
        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(IntPtr ctx);
        [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardConnectW")]
        private static extern int SCardConnect(IntPtr ctx, string reader, uint share, uint proto, out IntPtr card, out uint active);
        [DllImport("winscard.dll")]
        private static extern int SCardDisconnect(IntPtr card, uint disposition);
        [DllImport("winscard.dll")]
        private static extern int SCardTransmit(IntPtr card, ref IoRequest send, byte[] sendBuf, int sendLen,
                                                IntPtr recvPci, byte[] recvBuf, ref int recvLen);
    }
}
