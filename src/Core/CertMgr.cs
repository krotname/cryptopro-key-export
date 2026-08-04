using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Обёртка над certmgr из состава КриптоПро CSP — им делается финальный шаг,
    /// которого нет у p12utility: выгрузка контейнера в PKCS#12 (.pfx).
    ///
    /// Работает только если запрет на экспорт закрытого ключа уже снят
    /// (см. <see cref="P12Utility.MakeExportable"/>) — иначе CSP не отдаст ключ.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class CertMgr
    {
        public string ExePath { get; }
        public Action<string> Log { get; set; } = _ => { };

        public CertMgr(string exePath)
        {
            ExePath = exePath ?? throw new ArgumentNullException(nameof(exePath));
            if (!File.Exists(ExePath))
                throw new FileNotFoundException("certmgr не найден", ExePath);
        }

        /// <summary>Найти certmgr.exe в установленном КриптоПро CSP. null — CSP не установлен.</summary>
        public static string Locate()
        {
            string[] cand =
            {
                @"C:\Program Files\Crypto Pro\CSP\certmgr.exe",
                @"C:\Program Files (x86)\Crypto Pro\CSP\certmgr.exe",
                Path.Combine(AppContext.BaseDirectory, "certmgr.exe"),
            };
            foreach (var c in cand) if (File.Exists(c)) return c;
            return null;
        }

        /// <summary>Полное имя контейнера для certmgr: \\.\HDIMAGE\name.</summary>
        public static string HdImageContainer(string name) => @"\\.\HDIMAGE\" + name;

        /// <summary>Установить сертификат в хранилище «Личное» и связать его с контейнером.</summary>
        public ToolResult InstallCertificate(string cerPath, string container, bool signatureKey = false)
        {
            var sb = new StringBuilder("-install -file ").Append(Quote(cerPath));
            sb.Append(" -container ").Append(Quote(container));
            if (signatureKey) sb.Append(" -at_signature");
            sb.Append(" -silent");
            return Execute(sb.ToString(), 30000);
        }

        /// <summary>Выгрузить сертификат вместе с закрытым ключом в PKCS#12.</summary>
        public ToolResult ExportPfx(string container, string destPfx, string password, bool signatureKey = false)
        {
            var sb = new StringBuilder("-export -pfx -dest ").Append(Quote(destPfx));
            sb.Append(" -container ").Append(Quote(container));
            if (!string.IsNullOrEmpty(password)) sb.Append(" -pin ").Append(Quote(password));
            if (signatureKey) sb.Append(" -at_signature");
            sb.Append(" -silent");
            return Execute(sb.ToString(), 60000);
        }

        /// <summary>
        /// Полный экспорт контейнера в .pfx: сертификат извлекается из контейнера, ставится
        /// в хранилище «Личное» (нужно certmgr, чтобы связать сертификат с ключом) и выгружается вместе с ключом.
        /// Контейнер должен быть виден CSP — снятую с токена папку сначала установите
        /// через <see cref="ContainerStore.Install"/>.
        /// </summary>
        public ToolResult ExportContainerToPfx(
            string container, string destPfx, string password, bool signatureKey = false, string certPath = null)
        {
            if (string.IsNullOrWhiteSpace(container))
                throw new ArgumentException("Не задано имя контейнера", nameof(container));

            var check = CertFromContainer.CheckExportable(
                container, signatureKey ? CertFromContainer.AT_SIGNATURE : CertFromContainer.AT_KEYEXCHANGE);
            if (!check.KeyFound)
                return new ToolResult { Success = false, ExitCode = -2, Output = $"Контейнер \"{container}\" не найден или в нём нет ключа нужного типа" };
            if (!check.Exportable)
                return new ToolResult
                {
                    Success = false,
                    ExitCode = -3,
                    Output = "Закрытый ключ неэкспортируемый — сначала снимите запрет " +
                             $"(«Сделать экспортируемым»). {CryptoErrors.Describe(check.Error)}",
                };

            string tempDir = null;
            try
            {
                if (certPath == null)
                {
                    tempDir = Path.Combine(Path.GetTempPath(), "cpx-pfx-" + Guid.NewGuid().ToString("N"));
                    var (exchange, signature) = CertFromContainer.SaveCerts(container, tempDir);
                    certPath = signatureKey ? signature : exchange;
                    certPath ??= signatureKey ? exchange : signature;
                }
                if (certPath == null)
                    return new ToolResult { Success = false, ExitCode = -4, Output = "Не удалось извлечь сертификат из контейнера" };

                Log("Устанавливаем сертификат в хранилище «Личное» и связываем с контейнером…");
                var install = InstallCertificate(certPath, container, signatureKey);
                if (!install.Success)
                    Log("certmgr -install вернул " + install.Explain() + " — пробуем экспорт: сертификат мог быть установлен ранее");

                Log("Выгружаем контейнер в PKCS#12…");
                var export = ExportPfx(container, destPfx, password, signatureKey);
                if (export.Success && !File.Exists(destPfx))
                    return new ToolResult { Success = false, ExitCode = -5, Output = "certmgr отчитался об успехе, но файл не создан: " + destPfx };
                return export;
            }
            finally
            {
                if (tempDir != null)
                    try { Directory.Delete(tempDir, recursive: true); } catch (IOException) { }
            }
        }

        private ToolResult Execute(string args, int timeoutMs)
        {
            Log($"\"{ExePath}\" {Mask(args)}");
            var r = ProcessRunner.Run(ExePath, args, Path.GetDirectoryName(ExePath), timeoutMs);
            if (!string.IsNullOrEmpty(r.Output)) Log(r.Output);
            if (!r.Success) Log("certmgr: " + r.Explain());
            return r;
        }

        /// <summary>Пароль PFX не должен попадать в лог.</summary>
        private static string Mask(string args) => P12Utility.MaskQuotedValue(args, "-pin ");

        private static string Quote(string s) => "\"" + s + "\"";
    }
}
