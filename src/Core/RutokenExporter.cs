using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;

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
    /// Late-binding через dynamic: тип-библиотека rtCOMLite не требуется на этапе сборки,
    /// но rtComLite.dll должен быть зарегистрирован в системе на этапе выполнения
    /// (ставится https://help.kontur.ru/rtComLite.exe).
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

        /// <summary>
        /// PIN пользователя. Если null — при недефолтном PIN откроется системное окно ввода
        /// (AuthenticateOwnerFromGUI). Если на токене PIN по умолчанию — используется 12345678.
        /// </summary>
        public string UserPin { get; set; }

        /// <summary>Лог диагностики (как строка «action» в tokens.hta).</summary>
        public Action<string> Log { get; set; } = _ => { };

        /// <summary>Перечислить и прочитать все контейнеры со всех подключённых Рутокенов.</summary>
        public List<RutokenContainer> ReadAllContainers()
        {
            var result = new List<RutokenContainer>();
            Type ctxType = Type.GetTypeFromProgID("rtCOMLite.rtContext", throwOnError: true);
            dynamic ctx = Activator.CreateInstance(ctxType);
            Log("Подключаемся к службе смарт-карт...");
            ctx.Acquire();
            try
            {
                object[] readers = ToArray(ctx.EnumReaders());
                Log($"Найдено устройств: {readers?.Length ?? 0}");
                if (readers == null) return result;

                foreach (var rObj in readers)
                {
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
                if (i == 0 && bytes.Length > 4 && bytes[0] == 0x30 && bytes[2] == 0x16)
                {
                    int len = bytes[3];
                    if (len > 0 && 4 + len <= bytes.Length)
                        cont.ContainerName = Cp1251.GetString(bytes, 4, len);
                }
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
