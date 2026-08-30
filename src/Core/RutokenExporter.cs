using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Один прочитанный с токена контейнер: путь-«директория» на токене,
    /// открытое имя контейнера и байты 6 файлов (name/header/primary/masks/primary2/masks2 .key).
    /// </summary>
    public sealed class RutokenContainer
    {
        public string TokenName;      // имя считывателя/токена
        public string TokenDir;       // внутренний путь на токене, например "/4096/4096/"
        public string ContainerName;  // человекочитаемое имя контейнера (из name.key)
        public Dictionary<string, byte[]> Files = new Dictionary<string, byte[]>();

        /// <summary>Записать контейнер на диск как папку с 6 файлами .key.</summary>
        public string SaveTo(string parentDir, string folderName = null)
        {
            if (parentDir == null) throw new ArgumentNullException(nameof(parentDir));

            // Пишем сначала в отдельную папку и только готовый набор переименовываем в итоговый.
            // Так сбой записи не портит прежний бэкап, а два токена с одинаковой меткой контейнера
            // не смешивают свои *.key в одном каталоге.
            Directory.CreateDirectory(parentDir);
            string baseName = SafeFolderName(folderName ?? ContainerName);
            string staging = Path.Combine(parentDir, "." + baseName + "." + Guid.NewGuid().ToString("N") + ".tmp");
            Directory.CreateDirectory(staging);
            try
            {
                var allowed = new HashSet<string>(ContainerStore.ContainerFiles,
                                                  StringComparer.OrdinalIgnoreCase);
                foreach (var kv in Files)
                {
                    if (string.IsNullOrWhiteSpace(kv.Key) ||
                        !allowed.Contains(kv.Key))
                        throw new IOException(Strings.Format("err.folder.notlike", kv.Key));
                    if (kv.Value == null)
                        throw new IOException(Strings.Format("err.extract.nofile", kv.Key, staging));
                    File.WriteAllBytes(Path.Combine(staging, kv.Key), kv.Value);
                }

                for (int n = 1; n <= 1000; n++)
                {
                    string name = n == 1 ? baseName : $"{baseName}({n})";
                    string dst = Path.Combine(parentDir, name);
                    if (Directory.Exists(dst) || File.Exists(dst)) continue;
                    try
                    {
                        Directory.Move(staging, dst);
                        return dst;
                    }
                    catch (IOException) when (Directory.Exists(dst) || File.Exists(dst))
                    {
                        // Другой процесс занял имя между проверкой и Move — берём следующее.
                    }
                }
                throw new IOException(Strings.Format("err.store.full", parentDir));
            }
            finally
            {
                if (Directory.Exists(staging))
                    try { Directory.Delete(staging, recursive: true); } catch (IOException) { }
            }
        }

        /// <summary>
        /// Имя папки для контейнера, безопасное для файловой системы. Имя приходит из
        /// <c>name.key</c> на токене, то есть из данных, а не от пользователя, и одной замены
        /// недопустимых символов мало: <see cref="Path.GetInvalidFileNameChars"/> не считает
        /// недопустимой точку, поэтому имя «..» прошло бы фильтр и <see cref="Path.Combine"/>
        /// увёл бы запись в родительский каталог, затерев там чужие *.key.
        /// </summary>
        internal static string SafeFolderName(string name)
        {
            name ??= string.Empty;
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            name = name.Trim().TrimEnd('.');   // хвостовые точки Windows молча отбрасывает
            if (name.Length == 0) name = "container";
            return name.Length > 80 ? name.Substring(0, 80) : name;
        }
    }

    /// <summary>
    /// Экспорт контейнеров КриптоПро с Рутокена через COM-компонент rtCOMLite.rtContext
    /// (rtComLite.dll, «компонент диагностики Рутокен»). Порт логики Tokens.exe/tokens.hta.
    ///
    /// Читает файловую память токена НАПРЯМУЮ, минуя КриптоПро CSP — поэтому запрет на
    /// экспорт закрытого ключа на уровне CSP здесь не действует.
    ///
    /// Late-binding через dynamic: тип-библиотека rtCOMLite не требуется на этапе сборки.
    /// На этапе выполнения библиотека берётся из вшитой копии и грузится без регистрации
    /// в системе (<see cref="RegFreeCom"/>); если это невозможно — используется компонент,
    /// зарегистрированный в системе (устанавливается из https://help.kontur.ru/rtComLite.exe).
    ///
    /// Работает только на Рутокен S / старых (файловый контейнер в памяти токена). На
    /// Рутокен Lite и ЭЦП обход находит каталоги, но файлов контейнера не отдаёт (AGENTS п. 20):
    /// они обслуживаются по смарт-карточному профилю, и путь к ним — <see cref="Pkcs11Token"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class RutokenExporter
    {
        // Канонический порядок файлов контейнера, когда в папке ровно 6 объектов
        private static readonly string[] Bind =
            { "name.key", "header.key", "primary.key", "masks.key", "primary2.key", "masks2.key" };

        private const int RT_SHARED = 2;   // режим OpenReader
        private const int RT_USER   = 2;   // тип PIN / прав (USER)
        private const int RT_LEAVE  = 0;   // CloseReader
        private const int OpenTimeoutMs = 5000;

        /// <summary>Предохранитель: сколько объектов максимум берём из одного каталога токена.</summary>
        private const int MaxEntries = 512;

        /// <summary>CLSID coclass rtCOMLite.rtContext (совпадает с записью установленного компонента в реестре).</summary>
        public static readonly Guid ClsidRtContext = new Guid("0ACACF07-54A6-4230-8FA2-6CBBE9B87BB9");

        public const string ProgId = "rtCOMLite.rtContext";

        /// <summary>
        /// PIN пользователя. Если null — при недефолтном PIN откроется системное окно ввода
        /// (AuthenticateOwnerFromGUI). Если на токене PIN по умолчанию — используется 12345678.
        /// </summary>
        public string UserPin { get; set; }

        /// <summary>Лог диагностики (как строка «action» в tokens.hta).</summary>
        public Action<string> Log { get; set; } = _ => { };

        /// <summary>
        /// Отмена. Проверяется между шагами обхода токена: вызов в COM прервать нельзя,
        /// поэтому текущий файл дочитывается, а дальше работа прекращается.
        /// </summary>
        public CancellationToken Cancel { get; set; } = CancellationToken.None;

        /// <summary>
        /// Считыватели, которые обходить не нужно, — обычно смарт-карточные Рутокены,
        /// опознанные по PKCS#11 (<see cref="Pkcs11Token.SmartCardReaders"/>). Список задаёт
        /// вызывающий: он уже перечислил токены и знает их модели точнее, чем rtCOMLite.
        /// </summary>
        public ISet<string> SkipReaders { get; set; }

        /// <summary>
        /// Нужно ли обходить файловую память этого считывателя.
        ///
        /// Обход подтверждённых Рутокенов не просто бесполезен (для S есть прямой APDU,
        /// у смарт-карточных моделей файлов контейнера этим API нет) — он может
        /// <b>убить процесс</b>. На Рутокен ЭЦП 3.0 (прошивка 30.02)
        /// в каталоге <c>/4096/4097/</c> лежит файл 256 байт, и <c>rtISCard::ReadBinary</c> на нём
        /// рушит кучу процесса (0xC0000374) прямо внутри нативного вызова — как SAFEARRAY-методы
        /// из п. 19, и так же не ловится <c>catch</c>. На прежних ЭЦП 2.0 и Lite файлов было ноль,
        /// поэтому <c>ReadBinary</c> ни разу не вызывался и падения не было видно.
        ///
        /// Носители чужих вендоров (JaCarta, eToken…) исключаются по той же причине: файловая
        /// память rtCOMLite — это API Рутокен S, к чужой смарт-карте она неприменима, а вызов
        /// ReadBinary на непустом каталоге уже один раз стоил падения процесса. На практике
        /// rtCOMLite их и не показывает (13.08.2026: при четырёх считывателях EnumReaders вернул
        /// три — только Рутокены), но полагаться на это как на защиту не стоит.
        ///
        /// Признак берётся из PKCS#11, а при отсутствии драйвера — из имени считывателя:
        /// «Aktiv Rutoken ECP 0», «Aktiv Rutoken lite 0», «Aladdin Token JC 0» классифицируются
        /// и по нему. Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static bool ShouldWalk(string readerName, ISet<string> skipReaders)
        {
            if (string.IsNullOrEmpty(readerName)) return false;
            if (skipReaders != null && skipReaders.Contains(readerName)) return false;
            if (Pkcs11Token.HasUnsafeForeignFileWalkEvidence(readerName)) return false;
            RutokenKind kind = Pkcs11Token.Classify(readerName);
            return kind != RutokenKind.RutokenS
                && kind != RutokenKind.RutokenEcp && kind != RutokenKind.RutokenLite
                && kind != RutokenKind.JaCartaLt && kind != RutokenKind.JaCartaPro
                && kind != RutokenKind.Esmart
                && kind != RutokenKind.Other;
        }

        /// <summary>Перечислить и прочитать все контейнеры со всех подключённых Рутокенов.</summary>
        public List<RutokenContainer> ReadAllContainers()
        {
            Cancel.ThrowIfCancellationRequested();
            var result = new List<RutokenContainer>();
            dynamic ctx = CreateContext();
            Log(Strings.Get("token.connect"));
            try
            {
                // Acquire внутри try: если он бросит, Free() всё равно должен быть вызван —
                // иначе контекст rtCOMLite остаётся захваченным до конца процесса.
                ctx.Acquire();
                object[] readers = ToArray(ctx.EnumReaders());
                Log(Strings.Format("token.found", readers?.Length ?? 0));
                if (readers == null) return result;

                foreach (var rObj in readers)
                {
                    Cancel.ThrowIfCancellationRequested();
                    string tokenName = Convert.ToString(rObj);
                    if (string.IsNullOrEmpty(tokenName)) continue;
                    if (!ShouldWalk(tokenName, SkipReaders))
                    {
                        Log(Strings.Format("token.skip.smartcard", tokenName));
                        continue;
                    }
                    Log(Strings.Format("token.open", tokenName));
                    dynamic rt = ctx.OpenReader(tokenName, RT_SHARED, OpenTimeoutMs);
                    try
                    {
                        // BeginTransaction тоже внутри try: он падает, когда токен занят другим
                        // процессом (SCARD_E_SHARING_VIOLATION), и без CloseReader считыватель
                        // остался бы захваченным — следующие токены уже не обошлись бы.
                        rt.BeginTransaction();
                        Authenticate(rt);
                        rt.SelectMF();
                        _folderCount = _fileCount = 0;
                        EnumFolders(rt, tokenName, new List<string>(), result);
                        Log(Strings.Format("token.walk", _folderCount, _fileCount, result.Count));
                    }
                    finally
                    {
                        try { rt.ResetAccessRights(RT_USER); } catch { }
                        try { rt.EndTransaction(); } catch { }
                        try { ctx.CloseReader(rt, RT_LEAVE); } catch { }
                    }
                }
            }
            finally
            {
                try { ctx.Free(); } catch { }
            }
            return result;
        }

        /// <summary>
        /// Создать rtCOMLite.rtContext. Порядок: вшитая копия DLL без регистрации в системе →
        /// компонент, зарегистрированный в системе (ProgID). Ничего скачивать и ставить не нужно,
        /// пока работает первый вариант.
        /// </summary>
        private dynamic CreateContext()
        {
            string dll = BundledTools.TryExtract(
                BundledTools.RtComLiteResource, BundledTools.RtComLiteFileName, out string extractError);

            if (dll != null)
            {
                if (RegFreeCom.MatchesProcess(dll, out string detail))
                {
                    try
                    {
                        object ctx = RegFreeCom.CreateInstance(dll, ClsidRtContext);
                        Log(Strings.Format("diag.rtcom", Strings.Get("diag.rtcom.bundled")));
                        return ctx;
                    }
                    catch (Exception e)
                    {
                        Log(Strings.Format("token.rtcom.loadfail", e.Message));
                    }
                }
                else
                {
                    Log(Strings.Format("token.rtcom.mismatch", detail));
                }
            }
            else if (extractError != null)
            {
                Log(Strings.Format("token.rtcom.extractfail", extractError));
            }

            Type ctxType = Type.GetTypeFromProgID(ProgId, throwOnError: false);
            if (ctxType == null)
                throw new InvalidOperationException(Strings.Get("token.rtcom.unavailable"));
            object system = Activator.CreateInstance(ctxType);
            Log(Strings.Format("diag.rtcom", Strings.Get("diag.rtcom.system")));
            return system;
        }

        /// <summary>Короткая сводка: откуда будет взят rtCOMLite (без обращения к токену).</summary>
        public static string SourceSummary()
        {
            string dll = BundledTools.TryExtract(
                BundledTools.RtComLiteResource, BundledTools.RtComLiteFileName, out _);
            if (dll != null && RegFreeCom.MatchesProcess(dll, out _))
                return Strings.Get("diag.rtcom.bundled");
            if (Type.GetTypeFromProgID(ProgId, throwOnError: false) != null)
                return Strings.Get("diag.rtcom.system");
            return Strings.Get("diag.rtcom.missing");
        }

        /// <summary>Диагностика без обращения к токену: откуда будет взят COM-компонент rtCOMLite.</summary>
        public static List<string> DescribeSource()
        {
            var lines = new List<string>();
            string dll = BundledTools.TryExtract(
                BundledTools.RtComLiteResource, BundledTools.RtComLiteFileName, out string extractError);

            if (dll == null)
                lines.Add("  " + Strings.Format("diag.rtcom.detail.none",
                    extractError ?? Strings.Get("diag.notbundled")));
            else if (RegFreeCom.MatchesProcess(dll, out string detail))
                lines.Add("  " + Strings.Format("diag.rtcom.detail.ok", dll, detail));
            else
                lines.Add("  " + Strings.Format("diag.rtcom.detail.bad", dll, detail));

            lines.Add("  " + Strings.Get(Type.GetTypeFromProgID(ProgId, throwOnError: false) != null
                ? "diag.rtcom.registered"
                : "diag.rtcom.unregistered"));
            return lines;
        }

        private void Authenticate(dynamic rt)
        {
            bool pinDefault = false;
            try { pinDefault = (bool)rt.IsPINDefault(RT_USER); } catch { }
            if (pinDefault)
            {
                Log(Strings.Get("token.pin.default"));
                rt.AuthenticateOwner(RT_USER, StandardPins.UserPinFor(RutokenKind.RutokenLite));
            }
            else if (!string.IsNullOrEmpty(UserPin))
            {
                Log(Strings.Get("token.pin.given"));
                rt.AuthenticateOwner(RT_USER, UserPin);
            }
            else
            {
                Log(Strings.Get("token.pin.system"));
                rt.AuthenticateOwnerFromGUI();
            }
        }

        // Рекурсивный обход файловой структуры токена (порт enumFolders из tokens.hta)
        private void EnumFolders(dynamic rt, string tokenName, List<string> paths,
                                 List<RutokenContainer> result)
        {
            var files = FileIds(rt);
            var folders = FolderIds(rt);
            _folderCount += folders.Count;
            _fileCount += files.Count;

            foreach (ushort f in folders)
            {
                Cancel.ThrowIfCancellationRequested();
                paths.Add(f.ToString(CultureInfo.InvariantCulture));
                rt.SelectFolder(f);
                EnumFolders(rt, tokenName, paths, result);
                rt.SelectUpperFolder();
                paths.RemoveAt(paths.Count - 1);
            }

            string curDir = "/" + string.Join("/", paths) + "/";
            if (files.Count == 0) return;

            var cont = new RutokenContainer { TokenName = tokenName, TokenDir = curDir };
            bool any = false;
            for (int i = 0; i < files.Count; i++)
            {
                ushort file = files[i];
                int size;
                try { size = Convert.ToInt32(rt.GetFileSize(file)); }
                catch { continue; }
                if (size <= 0) continue;

                string logical = (files.Count == 6) ? Bind[i] : file.ToString(CultureInfo.InvariantCulture);
                byte[] bytes = ToBytes(rt.ReadBinary(file, 0, size));
                cont.Files[logical] = bytes;
                any = true;

                // Имя контейнера — из первого файла (name.key), ASN.1: 30 xx 16 len <name(cp1251)>
                if (i == 0)
                    cont.ContainerName = NameKey.Parse(bytes) ?? cont.ContainerName;
            }

            // Контейнер валиден, если есть закрытый ключ (primary/primary2)
            if (any && (cont.Files.ContainsKey("primary.key") || cont.Files.ContainsKey("primary2.key")))
            {
                Log(Strings.Format("token.container", curDir, cont.ContainerName, cont.Files.Count));
                result.Add(cont);
            }
        }

        // Счётчики обхода — только для итоговой строки в журнале.
        private int _folderCount;
        private int _fileCount;

        /// <summary>Идентификаторы вложенных папок текущего каталога токена.</summary>
        private static List<ushort> FolderIds(dynamic rt) =>
            Enumerate(() => rt.EnumFirstFolder(), id => rt.EnumNextFolder(id));

        /// <summary>Идентификаторы файлов текущего каталога токена.</summary>
        private static List<ushort> FileIds(dynamic rt) =>
            Enumerate(() => rt.EnumFirstFile(), id => rt.EnumNextFile(id));

        /// <summary>
        /// Поштучный обход каталога: EnumFirst* → EnumNext*(предыдущий), 0 — конец списка.
        ///
        /// Именно поштучно, а не через EnumFolders()/EnumFiles(): те возвращают SAFEARRAY,
        /// и в rtCOMLite 1.0.3.1 непустой SAFEARRAY рушит кучу процесса (0xC0000374/0xC0000005)
        /// прямо внутри вызова. Порча памяти в нативном коде не ловится catch — приложение
        /// умирало системным окном без единой строки в журнале. Пустой список эти методы
        /// отдают корректно, поэтому баг и не проявлялся, пока токен не подключён.
        /// </summary>
        private static List<ushort> Enumerate(Func<object> first, Func<ushort, object> next)
        {
            var ids = new List<ushort>();
            var seen = new HashSet<ushort>();
            ushort id = ToId(first());
            while (id != 0 && seen.Add(id) && ids.Count < MaxEntries)
            {
                ids.Add(id);
                id = ToId(next(id));
            }
            return ids;
        }

        private static ushort ToId(object value)
        {
            if (value == null) return 0;
            try { return Convert.ToUInt16(value, CultureInfo.InvariantCulture); }
            catch (Exception e) when (e is InvalidCastException || e is FormatException || e is OverflowException)
            {
                return 0;
            }
        }

        // --- helpers для работы с SAFEARRAY, приходящими из COM ---
        internal static object[] ToArray(object comArray)
        {
            if (comArray == null) return null;
            if (comArray is object[] oa) return oa;
            if (comArray is Array a)
            {
                var list = new List<object>(a.Length);
                foreach (var x in a) list.Add(x);
                return list.ToArray();
            }
            return new[] { comArray };
        }

        internal static byte[] ToBytes(object comArray)
        {
            if (comArray is byte[] b) return b;
            if (comArray is Array a)
            {
                var buf = new byte[a.Length];
                int i = 0;
                foreach (var x in a) buf[i++] = Convert.ToByte(x);
                return buf;
            }
            return Array.Empty<byte>();
        }
    }
}
