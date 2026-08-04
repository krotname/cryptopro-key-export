using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Полная цепочка «неэкспортируемый ключ с Рутокена → экспортируемый файловый контейнер»:
    ///   1) RutokenExporter — снять контейнер(ы) с токена на диск (обход CSP через rtCOMLite);
    ///   2) CertFromContainer — вытащить сертификат из контейнера через CryptoAPI (пока токен вставлен);
    ///   3) P12Utility.MakeExportable — снять запрет на экспорт закрытого ключа (--keyexport).
    /// Дальше экспортируемый контейнер конвертируется в PKCS#12
    /// (p12utility --cptop12 / cptools / openssl+gost).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ExportPipeline
    {
        public RutokenExporter Exporter { get; }
        public P12Utility P12 { get; }
        public Action<string> Log { get; set; } = Console.WriteLine;

        public ExportPipeline(string p12UtilityPath = null)
        {
            string p12 = p12UtilityPath ?? P12Utility.Locate()
                ?? throw new FileNotFoundException(
                    "p12utility не найден. Положите p12utility.win32.exe рядом с приложением или укажите путь.");
            Exporter = new RutokenExporter();
            P12 = new P12Utility(p12);
            Exporter.Log = m => Log("[rutoken] " + m);
            P12.Log = m => Log("[p12utility] " + m);
        }

        /// <summary>Снять все контейнеры со всех токенов в подпапки destParent. Возвращает прочитанные контейнеры и пути.</summary>
        public List<(RutokenContainer container, string folder)> ExportFromTokens(string destParent, string userPin = null)
        {
            Directory.CreateDirectory(destParent);
            Exporter.UserPin = userPin;
            var saved = new List<(RutokenContainer, string)>();
            foreach (var c in Exporter.ReadAllContainers())
            {
                string folder = c.SaveTo(destParent);
                Log($"Сохранён контейнер \"{c.ContainerName}\" -> {folder}");
                saved.Add((c, folder));
            }
            return saved;
        }

        /// <summary>
        /// Полный проход: снять контейнеры с токенов и сделать ключи экспортируемыми.
        /// Сертификат берётся автоматически через CryptoAPI (по имени контейнера, пока токен вставлен);
        /// при неудаче — используются переданные certExchange/certSignature (.cer).
        /// </summary>
        public void ExportAndMakeExportable(
            string destParent, string certExchange = null, string certSignature = null,
            string userPin = null, string containerPassword = null)
        {
            foreach (var (container, folder) in ExportFromTokens(destParent, userPin))
            {
                string ex = certExchange, sg = certSignature;

                // Авто-извлечение сертификата из контейнера (пока токен ещё вставлен)
                if (ex == null && sg == null && !string.IsNullOrEmpty(container.ContainerName))
                {
                    try
                    {
                        var found = CertFromContainer.SaveCerts(container.ContainerName, folder);
                        ex = found.exchange; sg = found.signature;
                        if (ex != null || sg != null)
                            Log($"Сертификат извлечён из контейнера \"{container.ContainerName}\" через CryptoAPI");
                    }
                    catch (Exception e) { Log("Не удалось авто-извлечь сертификат: " + e.Message); }
                }

                if (ex == null && sg == null)
                {
                    Log($"ПРОПУСК keyexport для \"{folder}\": не найден сертификат (.cer). Укажите его вручную.");
                    continue;
                }

                var r = P12.MakeExportable(folder, ex, sg, containerPassword);
                Log(r.Success
                    ? $"OK: ключ в \"{folder}\" помечен экспортируемым"
                    : $"ОШИБКА keyexport ({r.ExitCode}) в \"{folder}\": {r.Output}");
            }
        }
    }
}
