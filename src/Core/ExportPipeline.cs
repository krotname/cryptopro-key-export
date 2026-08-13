using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;

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

        /// <summary>
        /// Отмена всего конвейера: раздаётся исполнителям и проверяется между контейнерами.
        /// Прервать можно только между шагами — вызов в COM или запущенную утилиту
        /// приходится сначала довести до конца (утилита при этом снимается).
        /// </summary>
        public CancellationToken Cancel
        {
            get => _cancel;
            set { _cancel = value; Exporter.Cancel = value; P12.Cancel = value; }
        }

        private CancellationToken _cancel = CancellationToken.None;

        public ExportPipeline(string p12UtilityPath = null)
        {
            string p12 = p12UtilityPath ?? P12Utility.Resolve()
                ?? throw new FileNotFoundException(Strings.Get("err.p12.unavailable"));
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
            // Смарт-карточные Рутокены (ЭЦП, Lite) из обхода исключаются: файлов контейнера там нет,
            // а ReadBinary на ЭЦП 3.0 рушит процесс (см. RutokenExporter.ShouldWalk).
            Exporter.SkipReaders = Pkcs11Token.SmartCardReaders(
                Pkcs11Token.Enumerate(readContainers: false, cancel: Cancel));
            var saved = new List<(RutokenContainer, string)>();
            foreach (var c in Exporter.ReadAllContainers())
            {
                Cancel.ThrowIfCancellationRequested();
                string folder = c.SaveTo(destParent);
                Log(Strings.Format("pipe.saved", c.ContainerName, folder));
                saved.Add((c, folder));
            }
            return saved;
        }

        /// <summary>
        /// Полный проход: снять контейнеры с токенов и сделать ключи экспортируемыми.
        /// Сертификат берётся автоматически через CryptoAPI (по имени контейнера, пока токен вставлен);
        /// при неудаче — используются переданные certExchange/certSignature (.cer).
        /// Возвращает число снятых контейнеров: ноль означает, что токена не было, и вызывающему
        /// это надо отличать от успеха.
        /// </summary>
        public int ExportAndMakeExportable(
            string destParent, string certExchange = null, string certSignature = null,
            string userPin = null, string containerPassword = null)
        {
            int processed = 0;
            foreach (var (container, folder) in ExportFromTokens(destParent, userPin))
            {
                processed++;
                Cancel.ThrowIfCancellationRequested();
                string ex = certExchange, sg = certSignature;

                // Авто-извлечение сертификата из контейнера (пока токен ещё вставлен)
                if (ex == null && sg == null && !string.IsNullOrEmpty(container.ContainerName))
                {
                    try
                    {
                        var found = CertFromContainer.SaveCerts(container.ContainerName, folder);
                        ex = found.exchange; sg = found.signature;
                        if (ex != null || sg != null)
                            Log(Strings.Format("pipe.cert.found", container.ContainerName));
                    }
                    catch (Exception e) { Log(Strings.Format("pipe.cert.autofail", e.Message)); }
                }

                if (ex == null && sg == null)
                {
                    Log(Strings.Format("pipe.keyexport.skip", folder));
                    continue;
                }

                var r = P12.MakeExportable(folder, ex, sg, containerPassword);
                Log(r.Success
                    ? Strings.Format("pipe.keyexport.ok", folder)
                    : Strings.Format("pipe.keyexport.fail", folder, r.Explain(), r.Output));
            }
            return processed;
        }
    }
}
