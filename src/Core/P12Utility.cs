using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Обёртка над КриптоПро p12utility. Реализует «Сделать экспортируемым» точно как CertFix:
    /// собирает командную строку --cprepair --keyexport/--keyexport_sg и запускает процесс
    /// с рабочим каталогом = папка контейнера.
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

        /// <summary>Найти p12utility в типовых местах (рядом с приложением / в КриптоПро CSP).</summary>
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

        public sealed class Result
        {
            public bool Success;
            public int ExitCode;
            public string Output;
        }

        /// <summary>
        /// Снять запрет на экспорт закрытого ключа контейнера, лежащего в папке containerFolder
        /// (6 файлов .key). Нужен минимум один сертификат (обмена и/или подписи) в формате DER (.cer).
        /// Порт сборки командной строки из CertFix (адрес 0x40D14F).
        /// </summary>
        public Result MakeExportable(
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

            // Бэкап header.key (как CertFix: header.key.backup)
            File.Copy(header, header + ".backup", overwrite: true);

            bool hasExchange = !string.IsNullOrEmpty(certExchangePath);
            bool hasSignature = !string.IsNullOrEmpty(certSignaturePath);
            if (!hasExchange && !hasSignature)
                throw new ArgumentException(
                    "Нужен минимум один сертификат (--cert/--certsg). Экспортируйте .cer из хранилища «Личное» или из контейнера.");

            // Копируем сертификаты в папку контейнера с ожидаемыми именами
            if (hasExchange)
                File.Copy(certExchangePath, Path.Combine(containerFolder, "cert_exchange.cer"), true);
            if (hasSignature)
                File.Copy(certSignaturePath, Path.Combine(containerFolder, "cert_signature.cer"), true);

            // Сборка аргументов — ровно как ветвление в CertFix
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

            Log($"\"{ExePath}\" {sb}");

            var psi = new ProcessStartInfo
            {
                FileName = ExePath,
                Arguments = sb.ToString(),
                WorkingDirectory = containerFolder,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            string outText = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return new Result { Success = false, ExitCode = -1, Output = "Таймаут p12utility" };
            }
            Log(outText);
            return new Result { Success = p.ExitCode == 0, ExitCode = p.ExitCode, Output = outText };
        }
    }
}
