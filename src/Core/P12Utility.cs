using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Обёртка над КриптоПро p12utility. Реализует «Сделать экспортируемым» точно как CertFix:
    /// собирает командную строку --cprepair --keyexport/--keyexport_sg и запускает процесс
    /// с рабочим каталогом = папка контейнера.
    ///
    /// Внимание: у p12utility 4.0.8 нет режима контейнер → PKCS#12 (есть только обратный
    /// --p12tocp). Экспорт в .pfx делается через certmgr, см. <see cref="CertMgr"/>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class P12Utility
    {
        public string ExePath { get; }
        public Action<string> Log { get; set; } = _ => { };

        public P12Utility(string exePath)
        {
            ExePath = exePath ?? throw new ArgumentNullException(nameof(exePath));
            if (!File.Exists(ExePath))
                throw new FileNotFoundException("p12utility не найден", ExePath);
        }

        /// <summary>Найти внешний p12utility в типовых местах (рядом с приложением / в КриптоПро CSP).</summary>
        public static string Locate()
        {
            string[] cand =
            {
                Path.Combine(AppContext.BaseDirectory, "p12utility.win32.exe"),
                Path.Combine(AppContext.BaseDirectory, "p12utility.exe"),
                @"C:\Program Files\Crypto Pro\CSP\p12utility.exe",
                @"C:\Program Files (x86)\Crypto Pro\CSP\p12utility.exe",
            };
            foreach (var c in cand) if (File.Exists(c)) return c;
            return null;
        }

        /// <summary>
        /// Путь к p12utility: внешняя копия, если она есть, иначе вшитая в приложение
        /// (распаковывается в <see cref="BundledTools.CacheDir"/>). null — не найдено ничего.
        /// </summary>
        public static string Resolve() => Locate() ?? BundledTools.TryExtract(
            BundledTools.P12UtilityResource, BundledTools.P12UtilityFileName, out _);

        /// <summary>Диагностика: откуда будет взят p12utility.</summary>
        public static List<string> DescribeSource()
        {
            var lines = new List<string>();
            string external = Locate();
            lines.Add(external != null ? "  внешняя копия: " + external : "  внешняя копия: нет");

            string bundled = BundledTools.TryExtract(
                BundledTools.P12UtilityResource, BundledTools.P12UtilityFileName, out string error);
            lines.Add(bundled != null
                ? "  встроенная копия: " + bundled
                : "  встроенная копия: нет" + (error != null ? " (" + error + ")" : " (не вшита в сборку)"));

            string used = Resolve();
            lines.Add(used != null ? "  будет использован: " + used : "  будет использован: НЕ НАЙДЕН");
            return lines;
        }

        /// <summary>
        /// Сборка аргументов --cprepair — ровно как ветвление в CertFix (адрес 0x40D14F).
        /// Вынесена отдельно, чтобы покрыть тестами без запуска процесса.
        /// </summary>
        internal static string BuildRepairArguments(
            bool hasExchange, bool hasSignature, string containerPassword, bool normalHeader)
        {
            var sb = new StringBuilder();
            sb.Append("--cprepair --container_folder \".\"");
            if (hasExchange)
                sb.Append(" --cert \"cert_exchange.cer\" --keyexport");
            if (hasSignature)
                sb.Append(" --certsg \"cert_signature.cer\" --keyexport_sg");
            if (!string.IsNullOrEmpty(containerPassword))
                sb.Append(" --passcp ").Append(containerPassword);
            if (normalHeader)
                sb.Append(" --normal_header");
            return sb.ToString();
        }

        /// <summary>
        /// Снять запрет на экспорт закрытого ключа контейнера, лежащего в папке containerFolder
        /// (6 файлов .key). Нужен минимум один сертификат (обмена и/или подписи) в формате DER (.cer).
        /// </summary>
        public ToolResult MakeExportable(
            string containerFolder,
            string certExchangePath = null,
            string certSignaturePath = null,
            string containerPassword = null,
            bool normalHeader = false,
            int timeoutMs = 15000)
        {
            if (!Directory.Exists(containerFolder))
                throw new DirectoryNotFoundException(containerFolder);
            string header = Path.Combine(containerFolder, "header.key");
            if (!File.Exists(header))
                throw new FileNotFoundException("В папке нет header.key", header);

            bool hasExchange = !string.IsNullOrEmpty(certExchangePath);
            bool hasSignature = !string.IsNullOrEmpty(certSignaturePath);
            if (!hasExchange && !hasSignature)
                throw new ArgumentException(
                    "Нужен минимум один сертификат (--cert/--certsg). Экспортируйте .cer из хранилища «Личное» или из контейнера.");

            // Бэкап header.key (как CertFix: header.key.backup)
            File.Copy(header, header + ".backup", overwrite: true);

            // Копируем сертификаты в папку контейнера с ожидаемыми именами
            if (hasExchange)
                CopyIfDifferent(certExchangePath, Path.Combine(containerFolder, "cert_exchange.cer"));
            if (hasSignature)
                CopyIfDifferent(certSignaturePath, Path.Combine(containerFolder, "cert_signature.cer"));

            string args = BuildRepairArguments(hasExchange, hasSignature, containerPassword, normalHeader);
            return Execute(args, containerFolder, timeoutMs);
        }

        /// <summary>Показать открытый ключ контейнера (--cppublic). Быстрая проверка, что папка — валидный контейнер.</summary>
        public ToolResult ShowPublic(string containerFolder, string containerPassword = null, int timeoutMs = 15000)
        {
            var sb = new StringBuilder("--cppublic --container_folder \".\"");
            if (!string.IsNullOrEmpty(containerPassword))
                sb.Append(" --passcp ").Append(containerPassword);
            return Execute(sb.ToString(), containerFolder, timeoutMs);
        }

        private ToolResult Execute(string args, string workingDirectory, int timeoutMs)
        {
            Log($"\"{ExePath}\" {MaskPassword(args)}");
            var r = ProcessRunner.Run(ExePath, args, workingDirectory, timeoutMs);
            if (!string.IsNullOrEmpty(r.Output)) Log(r.Output);
            if (!r.Success) Log("p12utility: " + r.Explain());
            return r;
        }

        /// <summary>Пароль контейнера не должен попадать ни в окно лога, ни в файл журнала.</summary>
        internal static string MaskPassword(string args)
        {
            const string flag = "--passcp ";
            int i = args.IndexOf(flag, StringComparison.Ordinal);
            if (i < 0) return args;
            int valueStart = i + flag.Length;
            int end = args.IndexOf(" --", valueStart, StringComparison.Ordinal);
            return args.Substring(0, valueStart) + "***" + (end < 0 ? "" : args.Substring(end));
        }

        private static void CopyIfDifferent(string source, string target)
        {
            if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                return;
            File.Copy(source, target, overwrite: true);
        }
    }
}
