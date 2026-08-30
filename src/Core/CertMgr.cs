using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;

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
        public sealed class CertificateInstallSummary
        {
            public int Found { get; internal set; }
            public int Installed { get; internal set; }
            public List<ToolResult> Results { get; } = new List<ToolResult>();
            public bool AllSucceeded => Found > 0 && Found == Installed;
        }

        public string ExePath { get; }
        public Action<string> Log { get; set; } = _ => { };

        /// <summary>Отмена: прерывает ожидание и снимает запущенный процесс certmgr.</summary>
        public CancellationToken Cancel { get; set; } = CancellationToken.None;

        public CertMgr(string exePath)
        {
            ExePath = exePath ?? throw new ArgumentNullException(nameof(exePath));
            if (!File.Exists(ExePath))
                throw new FileNotFoundException(Strings.Get("err.certmgr.notfound"), ExePath);
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
            return Execute(BuildInstallArguments(cerPath, container, signatureKey), 30000);
        }

        internal static string BuildInstallArguments(
            string cerPath, string container, bool signatureKey = false)
        {
            var sb = new StringBuilder("-install -file ").Append(Quote(cerPath));
            sb.Append(" -container ").Append(Quote(container));
            if (signatureKey) sb.Append(" -at_signature");
            sb.Append(" -silent");
            return sb.ToString();
        }

        /// <summary>
        /// Установить найденные сертификаты в «Личное» и привязать их к точному контейнеру.
        /// Сначала используются cert_exchange.cer/cert_signature.cer из снятой папки; для
        /// отсутствующих файлов сертификат пробуем извлечь уже из установленной HDIMAGE-копии.
        /// </summary>
        public CertificateInstallSummary InstallContainerCertificates(
            string containerFolder, string container)
        {
            if (string.IsNullOrWhiteSpace(containerFolder))
                throw new ArgumentException(nameof(containerFolder));
            if (string.IsNullOrWhiteSpace(container))
                throw new ArgumentException(Strings.Get("err.container.name"), nameof(container));

            string exchange = ExistingCertificate(containerFolder, "cert_exchange.cer");
            string signature = ExistingCertificate(containerFolder, "cert_signature.cer");
            string tempDir = null;
            try
            {
                if (exchange == null || signature == null)
                {
                    tempDir = Path.Combine(Path.GetTempPath(),
                        "cpx-cert-install-" + Guid.NewGuid().ToString("N"));
                    var extracted = CertFromContainer.SaveCerts(container, tempDir);
                    exchange ??= extracted.exchange;
                    signature ??= extracted.signature;
                }

                var summary = new CertificateInstallSummary();
                InstallIfPresent(summary, exchange, container, signatureKey: false);
                InstallIfPresent(summary, signature, container, signatureKey: true);
                return summary;
            }
            finally
            {
                if (tempDir != null && Directory.Exists(tempDir))
                    try { Directory.Delete(tempDir, recursive: true); } catch (IOException) { }
            }
        }

        private void InstallIfPresent(CertificateInstallSummary summary, string path,
                                      string container, bool signatureKey)
        {
            if (path == null) return;
            summary.Found++;
            Log(Strings.Get("tool.certmgr.install"));
            ToolResult result = InstallCertificate(path, container, signatureKey);
            summary.Results.Add(result);
            if (result.Success) summary.Installed++;
        }

        private static string ExistingCertificate(string folder, string fileName)
        {
            string path = Path.Combine(folder, fileName);
            return File.Exists(path) ? path : null;
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
                throw new ArgumentException(Strings.Get("err.container.name"), nameof(container));

            var check = CertFromContainer.CheckExportable(
                container, signatureKey ? CertFromContainer.AT_SIGNATURE : CertFromContainer.AT_KEYEXCHANGE);
            // Одноключевая копия подписного ключа не должна требовать отдельного
            // флага в GUI/CLI: если ключа обмена нет, а подписной есть, выбираем его.
            if (!signatureKey && !check.KeyFound)
            {
                var signatureCheck = CertFromContainer.CheckExportable(
                    container, CertFromContainer.AT_SIGNATURE);
                if (signatureCheck.KeyFound)
                {
                    signatureKey = true;
                    check = signatureCheck;
                }
            }
            if (!check.KeyFound)
                return new ToolResult { Success = false, ExitCode = -2, Output = Strings.Format("err.container.nokey", container) };
            if (!check.Exportable)
                return new ToolResult
                {
                    Success = false,
                    ExitCode = -3,
                    Output = Strings.Format("err.key.locked", Strings.Get("btn.full"), check),
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
                    return new ToolResult { Success = false, ExitCode = -4, Output = Strings.Get("err.cert.extract") };

                Log(Strings.Get("tool.certmgr.install"));
                var install = InstallCertificate(certPath, container, signatureKey);
                if (!install.Success)
                    Log(Strings.Format("tool.certmgr.installwarn", install.Explain()));

                Log(Strings.Get("tool.certmgr.export"));
                var export = ExportPfx(container, destPfx, password, signatureKey);
                if (export.Success && !File.Exists(destPfx))
                    return new ToolResult { Success = false, ExitCode = -5, Output = Strings.Format("err.pfx.missing", destPfx) };
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
            var r = ProcessRunner.Run(ExePath, args, Path.GetDirectoryName(ExePath), timeoutMs, Cancel);
            if (!string.IsNullOrEmpty(r.Output)) Log(r.Output);
            if (!r.Success) Log("certmgr: " + r.Explain());
            return r;
        }

        /// <summary>Пароль PFX не должен попадать в лог.</summary>
        private static string Mask(string args) => P12Utility.MaskQuotedValue(args, "-pin ");

        /// <summary>Значение в кавычках; кавычка внутри значения — ошибка (см. <see cref="P12Utility.Quote"/>).</summary>
        private static string Quote(string s) => P12Utility.Quote(s);
    }
}
