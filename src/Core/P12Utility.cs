using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Runtime.Versioning;
using System.Threading;

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

        /// <summary>Отмена: прерывает ожидание и снимает запущенный процесс утилиты.</summary>
        public CancellationToken Cancel { get; set; } = CancellationToken.None;

        public P12Utility(string exePath)
        {
            ExePath = exePath ?? throw new ArgumentNullException(nameof(exePath));
            if (!File.Exists(ExePath))
                throw new FileNotFoundException(Strings.Get("err.p12.notfound"), ExePath);
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
            lines.Add("  " + Strings.Format("diag.p12.external", Locate() ?? Strings.Get("common.none")));

            string bundled = BundledTools.TryExtract(
                BundledTools.P12UtilityResource, BundledTools.P12UtilityFileName, out string error);
            lines.Add("  " + Strings.Format("diag.p12.bundled", bundled
                ?? Strings.Get("common.none") + " (" + (error ?? Strings.Get("diag.notbundled")) + ")"));

            lines.Add("  " + Strings.Format("diag.p12.used", Resolve() ?? Strings.Get("diag.notfound")));
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
                sb.Append(" --passcp ").Append(Quote(containerPassword)); // кавычки — пароль может быть с пробелом
            if (normalHeader)
                sb.Append(" --normal_header");
            return sb.ToString();
        }

        /// <summary>
        /// Значение аргумента в кавычках. Собственная кавычка внутри значения — ошибка, а не
        /// повод «как-нибудь» экранировать: утилиты КриптоПро принимают строку целиком и
        /// разбирают её сами, поэтому пароль <c>my"pass</c> дошёл бы до них как <c>my</c>, и
        /// .pfx молча получил бы не тот пароль, который ввёл пользователь.
        /// </summary>
        internal static string Quote(string value)
        {
            if (value != null && value.IndexOf('"') >= 0)
                throw new ArgumentException(Strings.Get("err.arg.quote"));
            return "\"" + value + "\"";
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
                throw new FileNotFoundException(Strings.Get("err.header.missing"), header);

            bool hasExchange = !string.IsNullOrEmpty(certExchangePath);
            bool hasSignature = !string.IsNullOrEmpty(certSignaturePath);
            if (!hasExchange && !hasSignature)
                throw new ArgumentException(Strings.Get("err.cert.required"));

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
                sb.Append(" --passcp ").Append(Quote(containerPassword)); // без кавычек пароль с пробелом разъехался бы
            return Execute(sb.ToString(), containerFolder, timeoutMs);
        }

        private ToolResult Execute(string args, string workingDirectory, int timeoutMs)
        {
            Log($"\"{ExePath}\" {MaskPassword(args)}");
            var r = ProcessRunner.Run(ExePath, args, workingDirectory, timeoutMs, Cancel);
            if (!string.IsNullOrEmpty(r.Output)) Log(r.Output);
            if (!r.Success) Log("p12utility: " + r.Explain());
            return r;
        }

        /// <summary>Пароль контейнера не должен попадать ни в окно лога, ни в файл журнала.</summary>
        internal static string MaskPassword(string args) => MaskQuotedValue(args, "--passcp ");

        /// <summary>Заменить значение в кавычках после флага на «***».</summary>
        internal static string MaskQuotedValue(string args, string flag)
        {
            int i = IndexOfFlag(args, flag);
            if (i < 0) return args;
            int open = args.IndexOf('"', i + flag.Length);
            int close = open < 0 ? -1 : args.IndexOf('"', open + 1);
            if (open < 0 || close < 0) return args.Substring(0, i + flag.Length) + "***";
            return args.Substring(0, open) + "\"***\"" + args.Substring(close + 1);
        }

        /// <summary>
        /// Позиция флага в командной строке, считая только текст вне кавычек. Простой IndexOf
        /// нашёл бы флаг и внутри чужого значения: путь к .pfx выбирает пользователь, и файл
        /// с именем вроде <c>backup -pin .pfx</c> увёл бы маскирование на путь, а настоящий
        /// пароль ушёл бы в журнал открытым текстом.
        /// </summary>
        private static int IndexOfFlag(string args, string flag)
        {
            bool inQuotes = false;
            for (int i = 0; i + flag.Length <= args.Length; i++)
            {
                if (args[i] == '"') { inQuotes = !inQuotes; continue; }
                if (!inQuotes && string.CompareOrdinal(args, i, flag, 0, flag.Length) == 0) return i;
            }
            return -1;
        }

        private static void CopyIfDifferent(string source, string target)
        {
            if (string.Equals(Path.GetFullPath(source), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                return;
            File.Copy(source, target, overwrite: true);
        }
    }
}
