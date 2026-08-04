using System;
using System.IO;
using System.Reflection;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Внешние нативные зависимости, вшитые в сборку как embedded resources, и их распаковка
    /// в пользовательский кэш при первом обращении.
    ///
    /// Смысл: пользователю не нужно ничего скачивать и класть рядом с exe —
    ///   • <c>p12utility.win32.exe</c> (КриптоПро, снятие запрета на экспорт);
    ///   • <c>rtCOMLite.dll</c> (Rutoken COM Lite, чтение файловой памяти токена)
    ///     — грузится без регистрации в системе, см. <see cref="RegFreeCom"/>.
    /// Единственное, что остаётся внешним, — сам КриптоПро CSP (лицензионный продукт,
    /// его CryptoAPI-провайдер должен быть установлен в системе).
    ///
    /// Кэш: <c>%LOCALAPPDATA%\CryptoProExport\bundled\&lt;версия&gt;\</c>. Распаковка идемпотентна:
    /// файл переписывается, только если отсутствует или отличается по размеру.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class BundledTools
    {
        public const string P12UtilityResource = "CryptoProExport.Tools.p12utility.win32.exe";
        public const string RtComLiteResource  = "CryptoProExport.Tools.rtCOMLite.dll";

        public const string P12UtilityFileName = "p12utility.win32.exe";
        public const string RtComLiteFileName  = "rtCOMLite.dll";

        private static readonly object Gate = new object();
        private static readonly Assembly Self = typeof(BundledTools).Assembly;

        /// <summary>Каталог, куда распаковываются вшитые зависимости.</summary>
        public static string CacheDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoProExport", "bundled", Self.GetName().Version?.ToString() ?? "0.0.0.0");

        /// <summary>Есть ли ресурс в сборке (в репозитории без бинарников его может не быть).</summary>
        public static bool Has(string resourceName) => Self.GetManifestResourceInfo(resourceName) != null;

        /// <summary>Путь к вшитому p12utility (распаковывается при первом вызове) или null, если не вшит.</summary>
        public static string P12Utility() => Extract(P12UtilityResource, P12UtilityFileName);

        /// <summary>Путь к вшитому rtCOMLite.dll (распаковывается при первом вызове) или null, если не вшит.</summary>
        public static string RtComLite() => Extract(RtComLiteResource, RtComLiteFileName);

        /// <summary>То же, что <see cref="P12Utility"/>/<see cref="RtComLite"/>, но без исключений: при ошибке вернёт null.</summary>
        public static string TryExtract(string resourceName, string fileName, out string error)
        {
            error = null;
            try { return Extract(resourceName, fileName); }
            catch (Exception e) { error = e.Message; return null; }
        }

        /// <summary>Распаковать ресурс в кэш и вернуть путь. null — ресурса нет в сборке.</summary>
        public static string Extract(string resourceName, string fileName)
        {
            using var src = Self.GetManifestResourceStream(resourceName);
            if (src == null) return null;

            string path = Path.Combine(CacheDir, fileName);
            lock (Gate)
            {
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length == src.Length) return path;

                Directory.CreateDirectory(CacheDir);
                string tmp = $"{path}.{Environment.ProcessId}.tmp";
                using (var dst = File.Create(tmp)) src.CopyTo(dst);
                try
                {
                    File.Move(tmp, path, overwrite: true);
                }
                catch (IOException)
                {
                    // Файл уже занят другим экземпляром приложения — считаем существующий валидным.
                    try { File.Delete(tmp); } catch { }
                    if (!File.Exists(path)) throw;
                }
                return path;
            }
        }
    }
}
