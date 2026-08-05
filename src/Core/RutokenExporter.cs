using System;
using System.Collections.Generic;
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
            folderName ??= (ContainerName ?? "container");
            foreach (char c in Path.GetInvalidFileNameChars())
                folderName = folderName.Replace(c, '_');
            string dst = Path.Combine(parentDir, folderName);
            Directory.CreateDirectory(dst);
            foreach (var kv in Files)
                File.WriteAllBytes(Path.Combine(dst, kv.Key), kv.Value);
            return dst;
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
    /// Поддерживаются Рутокен S / Lite / старые (файловый контейнер в памяти токена).
    /// Рутокен ЭЦП 2.0 с аппаратным неизвлекаемым ключом так не выгрузить.
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

        /// <summary>Перечислить и прочитать все контейнеры со всех подключённых Рутокенов.</summary>
        public List<RutokenContainer> ReadAllContainers()
        {
            Cancel.ThrowIfCancellationRequested();
            var result = new List<RutokenContainer>();
            dynamic ctx = CreateContext();
            Log("Подключаемся к службе смарт-карт...");
            ctx.Acquire();
            try
            {
                object[] readers = ToArray(ctx.EnumReaders());
                Log($"Найдено устройств: {readers?.Length ?? 0}");
                if (readers == null) return result;

                foreach (var rObj in readers)
                {
                    Cancel.ThrowIfCancellationRequested();
                    string tokenName = Convert.ToString(rObj);
                    if (string.IsNullOrEmpty(tokenName)) continue;
                    Log($"Открываем токен: {tokenName}");
                    dynamic rt = ctx.OpenReader(tokenName, RT_SHARED, OpenTimeoutMs);
                    rt.BeginTransaction();
                    try
                    {
                        Authenticate(rt);
                        rt.SelectMF();
                        EnumFolders(rt, tokenName, new List<string>(), result);
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
                        Log("rtCOMLite: встроенная копия, без регистрации в системе");
                        return ctx;
                    }
                    catch (Exception e)
                    {
                        Log($"Встроенный rtCOMLite не загрузился ({e.Message}); пробуем зарегистрированный в системе");
                    }
                }
                else
                {
                    Log($"Встроенный rtCOMLite не подходит ({detail}); пробуем зарегистрированный в системе");
                }
            }
            else if (extractError != null)
            {
                Log($"Не удалось распаковать встроенный rtCOMLite ({extractError}); пробуем зарегистрированный в системе");
            }

            Type ctxType = Type.GetTypeFromProgID(ProgId, throwOnError: false);
            if (ctxType == null)
                throw new InvalidOperationException(
                    "Компонент rtCOMLite недоступен: встроенная копия не загрузилась, а в системе он не зарегистрирован. " +
                    "Проверьте разрядность приложения (нужна x86) или установите компонент с https://help.kontur.ru/rtComLite.exe.");
            object system = Activator.CreateInstance(ctxType);
            Log("rtCOMLite: компонент, зарегистрированный в системе");
            return system;
        }

        /// <summary>Короткая сводка: откуда будет взят rtCOMLite (без обращения к токену).</summary>
        public static string SourceSummary()
        {
            string dll = BundledTools.TryExtract(
                BundledTools.RtComLiteResource, BundledTools.RtComLiteFileName, out _);
            if (dll != null && RegFreeCom.MatchesProcess(dll, out _))
                return "встроенная копия, без регистрации в системе";
            if (Type.GetTypeFromProgID(ProgId, throwOnError: false) != null)
                return "компонент, зарегистрированный в системе";
            return "НЕДОСТУПЕН";
        }

        /// <summary>Диагностика без обращения к токену: откуда будет взят COM-компонент rtCOMLite.</summary>
        public static List<string> DescribeSource()
        {
            var lines = new List<string>();
            string dll = BundledTools.TryExtract(
                BundledTools.RtComLiteResource, BundledTools.RtComLiteFileName, out string extractError);

            if (dll == null)
                lines.Add("  встроенная копия: нет" + (extractError != null ? " (" + extractError + ")" : " (не вшита в сборку)"));
            else if (RegFreeCom.MatchesProcess(dll, out string detail))
                lines.Add($"  встроенная копия: {dll} ({detail}) — грузится без регистрации");
            else
                lines.Add($"  встроенная копия: {dll} — не подходит ({detail})");

            lines.Add(Type.GetTypeFromProgID(ProgId, throwOnError: false) != null
                ? "  в системе: зарегистрирован (запасной вариант)"
                : "  в системе: не зарегистрирован");
            return lines;
        }

        private void Authenticate(dynamic rt)
        {
            bool pinDefault = false;
            try { pinDefault = (bool)rt.IsPINDefault(RT_USER); } catch { }
            if (pinDefault)
            {
                Log("PIN по умолчанию — авторизуемся 12345678");
                rt.AuthenticateOwner(RT_USER, "12345678");
            }
            else if (!string.IsNullOrEmpty(UserPin))
            {
                Log("Авторизуемся заданным PIN");
                rt.AuthenticateOwner(RT_USER, UserPin);
            }
            else
            {
                Log("Авторизуемся через системное окно ввода PIN");
                rt.AuthenticateOwnerFromGUI();
            }
        }

        // Рекурсивный обход файловой структуры токена (порт enumFolders из tokens.hta)
        private void EnumFolders(dynamic rt, string tokenName, List<string> paths,
                                 List<RutokenContainer> result)
        {
            object[] files = ToArray(rt.EnumFiles());
            object[] folders = ToArray(rt.EnumFolders());

            if (folders != null)
            {
                foreach (var f in folders)
                {
                    Cancel.ThrowIfCancellationRequested();
                    string folder = Convert.ToString(f);
                    paths.Add(folder);
                    rt.SelectFolder(f);
                    EnumFolders(rt, tokenName, paths, result);
                    rt.SelectUpperFolder();
                    paths.RemoveAt(paths.Count - 1);
                }
            }

            string curDir = "/" + string.Join("/", paths) + "/";
            if (files == null || files.Length == 0) return;

            var cont = new RutokenContainer { TokenName = tokenName, TokenDir = curDir };
            bool any = false;
            for (int i = 0; i < files.Length; i++)
            {
                object file = files[i];
                int size;
                try { size = Convert.ToInt32(rt.GetFileSize(file)); }
                catch { continue; }
                if (size <= 0) continue;

                string logical = (files.Length == 6) ? Bind[i] : Convert.ToString(file);
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
                Log($"Контейнер: {curDir} \"{cont.ContainerName}\" ({cont.Files.Count} файлов)");
                result.Add(cont);
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
