using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>Итог полного цикла: сколько контейнеров снято и сколько действительно исправлено.</summary>
    public sealed class ExportPipelineResult
    {
        public int Exported { get; internal set; }
        public int Completed { get; internal set; }
        public bool AllSucceeded => Exported > 0 && Completed == Exported;
    }

    /// <summary>
    /// Полная цепочка «неэкспортируемый ключ с Рутокена → экспортируемый файловый контейнер»:
    ///   1) DirectTokenApdu или RutokenExporter — снять контейнер(ы) с токена на диск;
    ///   2) CertFromContainer — вытащить сертификат из контейнера через CryptoAPI (пока токен вставлен);
    ///   3) P12Utility.MakeExportable — снять запрет на экспорт закрытого ключа (--keyexport).
    /// Дальше экспортируемый контейнер конвертируется в PKCS#12
    /// (p12utility --cptop12 / cptools / openssl+gost).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class ExportPipeline
    {
        public RutokenExporter Exporter { get; }
        public DirectTokenApdu Direct { get; }
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
            set
            {
                _cancel = value;
                Exporter.Cancel = value;
                Direct.Cancel = value;
                if (P12 != null) P12.Cancel = value;
            }
        }

        private CancellationToken _cancel = CancellationToken.None;

        public ExportPipeline(string p12UtilityPath = null)
        {
            Exporter = new RutokenExporter();
            Exporter.Log = m => Log("[rtCOMLite] " + m);
            Direct = new DirectTokenApdu();
            Direct.Log = m => Log("[APDU] " + m);

            // Простому `export` p12utility не нужен. Отсутствие утилиты проверяется только
            // перед полным циклом, иначе сборка без embedded tools не могла бы хотя бы снять
            // файловый контейнер с Рутокен S.
            string p12 = p12UtilityPath ?? P12Utility.Resolve();
            if (p12 != null)
            {
                P12 = new P12Utility(p12);
                P12.Log = m => Log("[p12utility] " + m);
            }
        }

        /// <summary>Снять все контейнеры со всех токенов в подпапки destParent. Возвращает прочитанные контейнеры и пути.</summary>
        public List<(RutokenContainer container, string folder)> ExportFromTokens(string destParent, string userPin = null)
        {
            Exporter.UserPin = userPin;
            var tokens = Pkcs11Token.Enumerate(readContainers: false, cancel: Cancel);
            DirectTokenApdu.EnsureBatchSelectionSafe(tokens);
            DirectTokenApdu.EnsureSingleReaderForExplicitPin(tokens, userPin);
            // Все подтверждённые модели исключаются из rtCOMLite: для S/Lite/LT/PRO/ESMART есть прямой
            // APDU, а на ECP/чужом носителе файловый обход либо бессмыслен, либо опасен.
            Exporter.SkipReaders = Pkcs11Token.SmartCardReaders(tokens);
            var saved = new List<(RutokenContainer, string)>();

            foreach (Pkcs11TokenInfo token in tokens)
            {
                if (!DirectTokenApdu.Supports(token.Kind)) continue;
                foreach (DirectTokenContainerRef selected in Direct.ListContainers(token))
                {
                    Cancel.ThrowIfCancellationRequested();
                    var item = ExportDirectContainer(token, selected, destParent, userPin);
                    saved.Add(item);
                }
            }

            // Legacy fallback только для неопознанных старых файловых носителей.
            // Reader, явно похожий на Rutoken S, ShouldWalk не пропустит: на живом S
            // rtCOMLite оказался аварийным, и для него допустим только прямой APDU.
            foreach (var c in Exporter.ReadAllContainers())
            {
                Cancel.ThrowIfCancellationRequested();
                string folder = c.SaveTo(destParent);
                Log(Strings.Format("pipe.saved", c.ContainerName, folder));
                saved.Add((c, folder));
            }
            return saved;
        }

        /// <summary>Снять один выбранный контейнер с доказанного APDU-носителя.</summary>
        public (RutokenContainer container, string folder) ExportDirectContainer(
            Pkcs11TokenInfo token, DirectTokenContainerRef selected,
            string destParent, string userPin = null)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (selected == null) throw new ArgumentNullException(nameof(selected));
            Cancel.ThrowIfCancellationRequested();
            RutokenContainer container = Direct.ReadContainer(token, selected, userPin);
            string folder = container.SaveTo(destParent, selected.OutputName);
            Log(Strings.Format("pipe.saved", container.ContainerName, folder));
            return (container, folder);
        }

        /// <summary>
        /// Сохранить один уже прочитанный через rtCOMLite контейнер. Нужен GUI, где выбранная
        /// строка должна означать ровно один контейнер, а не незаметный обход всех носителей.
        /// </summary>
        public (RutokenContainer container, string folder) ExportContainer(
            RutokenContainer container, string destParent)
        {
            if (container == null) throw new ArgumentNullException(nameof(container));
            Cancel.ThrowIfCancellationRequested();
            string folder = container.SaveTo(destParent);
            Log(Strings.Format("pipe.saved", container.ContainerName, folder));
            return (container, folder);
        }

        /// <summary>
        /// Снять ровно один выбранный контейнер Rutoken Lite через PC/SC APDU. Если PIN не
        /// задан пользователем, заводской PIN применяется лишь по безопасным флагам PKCS#11.
        /// Имя контейнера не используется в имени каталога, чтобы не раскрывать персональные
        /// данные; уникальность каталога обеспечивает <see cref="RutokenLiteApdu"/>.
        /// </summary>
        public (RutokenContainer container, string folder) ExportLiteContainer(
            Pkcs11TokenInfo token, LiteContainerRef selected, string destParent, string userPin = null)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (selected == null) throw new ArgumentNullException(nameof(selected));
            if (token.Kind != RutokenKind.RutokenLite)
                throw new ArgumentException(Pkcs11Token.KindName(token.Kind), nameof(token));

            var direct = new DirectTokenContainerRef
            {
                Kind = RutokenKind.RutokenLite,
                Reader = token.Reader,
                Name = selected.Name,
                OutputName = $"lite_{selected.DfIndex:X2}",
                Index = selected.DfIndex,
                Lite = selected,
            };
            return ExportDirectContainer(token, direct, destParent, userPin);
        }

        /// <summary>Выбрать PIN Lite без подбора и без риска добить счётчик попыток.</summary>
        internal static string ResolveLitePin(Pkcs11TokenInfo token, string userPin)
        {
            if (!string.IsNullOrEmpty(userPin)) return userPin;
            if (token != null && token.PinDefault && !token.PinCountLow &&
                !token.PinFinalTry && !token.PinLocked)
            {
                string factory = StandardPins.AutoFillUserPinFor(RutokenKind.RutokenLite);
                if (!string.IsNullOrEmpty(factory)) return factory;
            }
            throw new LiteApduException(Strings.Format("err.lite.pin", "—"));
        }

        /// <summary>
        /// Полный проход: снять контейнеры с токенов и сделать ключи экспортируемыми.
        /// Сертификат берётся автоматически через CryptoAPI (по имени контейнера, пока токен вставлен);
        /// при неудаче — используются переданные certExchange/certSignature (.cer).
        /// Возвращает отдельно число снятых контейнеров и число полностью исправленных: простой
        /// факт чтения с токена ещё не означает успех, если сертификат не найден или p12utility
        /// завершилась с ошибкой.
        /// </summary>
        public ExportPipelineResult ExportAndMakeExportable(
            string destParent, string certExchange = null, string certSignature = null,
            string userPin = null, string containerPassword = null)
        {
            if (P12 == null)
                throw new FileNotFoundException(Strings.Get("err.p12.unavailable"));

            var result = new ExportPipelineResult();
            foreach (var (container, folder) in ExportFromTokens(destParent, userPin))
            {
                result.Exported++;
                Cancel.ThrowIfCancellationRequested();
                if (MakeSavedContainerExportable(
                    container, folder, certExchange, certSignature, containerPassword))
                    result.Completed++;
            }
            return result;
        }

        /// <summary>Полный цикл для одного заранее выбранного rtCOMLite-контейнера.</summary>
        public ExportPipelineResult ExportAndMakeExportable(
            RutokenContainer container, string destParent,
            string certExchange = null, string certSignature = null,
            string containerPassword = null)
        {
            if (P12 == null)
                throw new FileNotFoundException(Strings.Get("err.p12.unavailable"));
            var saved = ExportContainer(container, destParent);
            return CompleteOne(saved.container, saved.folder,
                certExchange, certSignature, containerPassword);
        }

        /// <summary>Полный цикл для одного выбранного APDU-контейнера Rutoken Lite.</summary>
        public ExportPipelineResult ExportLiteAndMakeExportable(
            Pkcs11TokenInfo token, LiteContainerRef selected, string destParent,
            string userPin = null, string certExchange = null, string certSignature = null,
            string containerPassword = null)
        {
            if (P12 == null)
                throw new FileNotFoundException(Strings.Get("err.p12.unavailable"));
            var saved = ExportLiteContainer(token, selected, destParent, userPin);
            return CompleteOne(saved.container, saved.folder,
                certExchange, certSignature, containerPassword, normalizeLite: true);
        }

        /// <summary>Полный цикл для выбранного Rutoken S/Lite, JaCarta LT/PRO или ESMART.</summary>
        public ExportPipelineResult ExportDirectAndMakeExportable(
            Pkcs11TokenInfo token, DirectTokenContainerRef selected, string destParent,
            string userPin = null, string certExchange = null, string certSignature = null,
            string containerPassword = null)
        {
            if (P12 == null)
                throw new FileNotFoundException(Strings.Get("err.p12.unavailable"));
            var saved = ExportDirectContainer(token, selected, destParent, userPin);
            return CompleteOne(saved.container, saved.folder,
                certExchange, certSignature, containerPassword,
                normalizeLite: token.Kind == RutokenKind.RutokenLite
                    || token.Kind == RutokenKind.JaCartaPro);
        }

        private ExportPipelineResult CompleteOne(
            RutokenContainer container, string folder,
            string certExchange, string certSignature, string containerPassword,
            bool normalizeLite = false)
        {
            var result = new ExportPipelineResult { Exported = 1 };
            if (normalizeLite)
            {
                if (MakeLiteSavedContainerExportable(
                    container, folder, certExchange, certSignature, containerPassword))
                    result.Completed = 1;
                return result;
            }

            if (!MakeSavedContainerExportable(
                container, folder, certExchange, certSignature, containerPassword))
                return result;
            result.Completed = 1;
            return result;
        }

        /// <summary>
        /// Lite требует двухфазного ремонта. Первый cprepair преобразует обёртки ключей;
        /// второй с <c>--normal_header</c> делает итоговую HDIMAGE-копию, из которой certmgr
        /// реально экспортирует PFX. Для контейнера с двумя ключами создаются две
        /// одноключевые копии: так CSP не подменяет одну пару второй.
        /// </summary>
        private bool MakeLiteSavedContainerExportable(
            RutokenContainer container, string folder,
            string certExchange, string certSignature, string containerPassword)
        {
            if (!TryResolveCertificates(container, folder, certExchange, certSignature,
                                        out string ex, out string sg))
                return false;

            var first = P12.MakeExportable(folder, ex, sg, containerPassword, normalHeader: false);
            if (!first.Success)
            {
                Log(Strings.Format("pipe.keyexport.fail", folder,
                    first.Explain(), first.Output));
                return false;
            }

            bool hasExchange = container.Files.ContainsKey("primary.key");
            bool hasSignature = container.Files.ContainsKey("primary2.key");
            var targets = LiteRepairTargets(container, ex, sg);
            string signatureFolder = null;
            try
            {
                if (targets.exchange && targets.signature)
                    signatureFolder = CloneLiteOutput(folder, "signature");

                if (targets.exchange)
                {
                    NormalizeLiteContainer(folder, containerPassword, useCspEnvelope: false);
                    RestoreOriginalHeader(folder);
                    var exchangeRepair = P12.MakeExportable(
                        folder, ex, null, containerPassword, normalHeader: true);
                    if (!exchangeRepair.Success)
                        throw new InvalidOperationException(exchangeRepair.Explain());
                    if (hasSignature)
                    {
                        DeleteIfExists(Path.Combine(folder, "primary2.key"));
                        DeleteIfExists(Path.Combine(folder, "masks2.key"));
                        WriteContainerName(folder, container.ContainerName + " [exchange]");
                    }
                    Log(Strings.Format("pipe.lite.normalized", folder));
                }

                if (targets.signature)
                {
                    string target = signatureFolder ?? folder;
                    NormalizeLiteContainer(target, containerPassword, useCspEnvelope: true);
                    RestoreOriginalHeader(target);
                    // p12utility 4.0.8 в normal-header выбирает подписную пару только
                    // когда видит оба сертифика и обе пары на входе.
                    var signatureRepair = P12.MakeExportable(
                        target, ex, sg, containerPassword, normalHeader: true);
                    if (!signatureRepair.Success)
                        throw new InvalidOperationException(signatureRepair.Explain());
                    if (hasExchange)
                    {
                        DeleteIfExists(Path.Combine(target, "primary.key"));
                        DeleteIfExists(Path.Combine(target, "masks.key"));
                        WriteContainerName(target, container.ContainerName + " [signature]");
                    }
                    Log(Strings.Format("pipe.lite.normalized", target));
                }
                return true;
            }
            catch (Exception e)
            {
                Log(Strings.Format("pipe.lite.normalizefail", folder, e.Message));
                return false;
            }
        }

        /// <summary>
        /// Двухключевой Lite/PRO-контейнер может содержать сертификат только для одной пары.
        /// Ремонтировать можно лишь ветку, где одновременно присутствуют ключ и его сертификат:
        /// иначе p12utility либо падает без --cert, либо привязывает чужой сертификат.
        /// </summary>
        internal static (bool exchange, bool signature) LiteRepairTargets(
            RutokenContainer container, string certExchange, string certSignature)
        {
            if (container == null) return (false, false);
            return (
                container.Files.ContainsKey("primary.key") && !string.IsNullOrEmpty(certExchange),
                container.Files.ContainsKey("primary2.key") && !string.IsNullOrEmpty(certSignature));
        }

        /// <summary>
        /// APDU отдаёт неэкспортируемый primary как <c>SEQUENCE { OCTET STRING A, [0] B }</c>.
        /// После снятия флага HDIMAGE ожидает обычную файловую форму с одним B.
        /// Все шесть файлов перечитываются после p12utility и меняются атомарно, чтобы не
        /// откатить исправленный header.key и не оставить половину пары преобразованной.
        /// </summary>
        internal static void NormalizeLiteContainer(
            string folder, string containerPassword = null, bool useCspEnvelope = false)
        {
            string exchangePath = Path.Combine(folder, "primary.key");
            string signaturePath = Path.Combine(folder, "primary2.key");
            bool hasExchange = File.Exists(exchangePath);
            bool hasSignature = File.Exists(signaturePath);

            // Сначала доказываем пароль и целостность обоих ключей по открытой части.
            if (hasExchange)
                _ = ContainerKeyExtractor.ExtractKey(folder, containerPassword ?? "", signature: false);
            if (hasSignature)
                _ = ContainerKeyExtractor.ExtractKey(folder, containerPassword ?? "", signature: true);
            var blobs = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string file in ContainerStore.ContainerFiles)
            {
                string path = Path.Combine(folder, file);
                if (File.Exists(path)) blobs[file] = File.ReadAllBytes(path);
            }
            if (hasExchange)
                blobs["primary.key"] = useCspEnvelope
                    ? ContainerKeyExtractor.NormalizePrimaryCspEnvelope(File.ReadAllBytes(exchangePath))
                    : ContainerKeyExtractor.NormalizePrimaryForExport(File.ReadAllBytes(exchangePath));
            if (hasSignature)
                blobs["primary2.key"] = useCspEnvelope
                    ? ContainerKeyExtractor.NormalizePrimaryCspEnvelope(File.ReadAllBytes(signaturePath))
                    : ContainerKeyExtractor.NormalizePrimaryForExport(File.ReadAllBytes(signaturePath));
            RutokenLiteApdu.SaveFiles(folder, blobs);
        }

        private static string CloneLiteOutput(string folder, string suffix)
        {
            string parent = Path.GetDirectoryName(folder);
            string clone = RutokenLiteApdu.ReserveOutputDirectory(
                parent, Path.GetFileName(folder) + "_" + suffix);
            foreach (string file in Directory.GetFiles(folder))
                File.Copy(file, Path.Combine(clone, Path.GetFileName(file)));
            return clone;
        }

        private static void RestoreOriginalHeader(string folder)
        {
            string backup = Path.Combine(folder, "header.key.backup");
            if (!File.Exists(backup))
                throw new FileNotFoundException(Strings.Get("err.header.missing"), backup);
            File.Copy(backup, Path.Combine(folder, "header.key"), overwrite: true);
        }

        private static void DeleteIfExists(string path)
        {
            if (File.Exists(path)) File.Delete(path);
        }

        private static void WriteContainerName(string folder, string name)
        {
            File.WriteAllBytes(Path.Combine(folder, "name.key"), NameKey.Build(name));
        }

        private bool MakeSavedContainerExportable(
            RutokenContainer container, string folder,
            string certExchange, string certSignature, string containerPassword,
            bool normalHeader = false)
        {
            if (!TryResolveCertificates(container, folder, certExchange, certSignature,
                                        out string ex, out string sg)) return false;

            var r = P12.MakeExportable(folder, ex, sg, containerPassword,
                normalHeader: normalHeader);
            Log(r.Success
                ? Strings.Format("pipe.keyexport.ok", folder)
                : Strings.Format("pipe.keyexport.fail", folder, r.Explain(), r.Output));
            return r.Success;
        }

        private bool TryResolveCertificates(
            RutokenContainer container, string folder,
            string certExchange, string certSignature,
            out string ex, out string sg)
        {
            Cancel.ThrowIfCancellationRequested();
            ex = certExchange;
            sg = certSignature;
            if ((ex == null || sg == null) && !string.IsNullOrEmpty(container.ContainerName))
            {
                try
                {
                    var found = CertFromContainer.SaveCerts(container.ContainerName, folder);
                    ex ??= found.exchange;
                    sg ??= found.signature;
                    if (found.exchange != null || found.signature != null)
                        Log(Strings.Format("pipe.cert.found", container.ContainerName));
                }
                catch (Exception e) { Log(Strings.Format("pipe.cert.autofail", e.Message)); }
            }
            if (ex == null && sg == null || !HasCertificateForPresentKey(container, ex, sg))
            {
                Log(Strings.Format("pipe.keyexport.skip", folder));
                return false;
            }
            return true;
        }

        /// <summary>
        /// p12utility нужен сертификат только для той пары, которую он ремонтирует. Реальный
        /// контейнер УЦ может содержать обе пары файлов, но сертификат лишь для одной из них;
        /// в таком случае p12utility с одним --cert/--certsg перестраивает заголовок в рабочий
        /// одноключевой HDIMAGE-контейнер. Блокировать такой контейнер нельзя.
        /// </summary>
        internal static bool HasCertificateForPresentKey(RutokenContainer container,
                                                         string certExchange, string certSignature)
        {
            if (container == null) return false;
            bool hasExchange = container.Files.ContainsKey("primary.key");
            bool hasSignature = container.Files.ContainsKey("primary2.key");
            return (hasExchange && !string.IsNullOrEmpty(certExchange))
                || (hasSignature && !string.IsNullOrEmpty(certSignature));
        }
    }
}
