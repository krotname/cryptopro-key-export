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
            set { _cancel = value; Exporter.Cancel = value; if (P12 != null) P12.Cancel = value; }
        }

        private CancellationToken _cancel = CancellationToken.None;

        public ExportPipeline(string p12UtilityPath = null)
        {
            Exporter = new RutokenExporter();
            Exporter.Log = m => Log("[rtCOMLite] " + m);

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
            // Смарт-карточные Рутокены (ЭЦП, Lite) из обхода исключаются: файлов контейнера там нет,
            // а ReadBinary на ЭЦП 3.0 рушит процесс (см. RutokenExporter.ShouldWalk).
            // Лог PKCS#11 пробрасывается по той же причине, что в list и deps: без него сбой
            // драйвера выглядит как «смарт-карточных токенов нет», и обход молча уходит на них.
            Exporter.SkipReaders = Pkcs11Token.SmartCardReaders(
                Pkcs11Token.Enumerate(readContainers: false,
                    log: m => Log("[PKCS#11] " + m), cancel: Cancel));
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

            string pin = ResolveLitePin(token, userPin);
            string folder = RutokenLiteApdu.ReserveOutputDirectory(
                destParent, $"lite_{selected.DfIndex:X2}");
            var lite = new RutokenLiteApdu { Log = m => Log("[APDU] " + m) };
            try
            {
                Cancel.ThrowIfCancellationRequested();
                string actualName = lite.ReadContainer(token.Reader, selected.DfIndex, pin, folder);
                var container = LoadSavedContainer(
                    folder, token.Reader, $"APDU/{selected.DfIndex:X2}", actualName ?? selected.Name);
                Log(Strings.Format("pipe.saved", container.ContainerName, folder));
                return (container, folder);
            }
            catch
            {
                // ReserveOutputDirectory создаёт пустую папку заранее. После отказа карты или
                // отмены не оставляем её как ложный результат; непустой каталог не трогаем.
                try
                {
                    if (Directory.Exists(folder))
                    {
                        using var entries = Directory.EnumerateFileSystemEntries(folder).GetEnumerator();
                        if (!entries.MoveNext()) Directory.Delete(folder);
                    }
                }
                catch (IOException) { }
                throw;
            }
        }

        /// <summary>Выбрать PIN Lite без подбора и без риска добить счётчик попыток.</summary>
        internal static string ResolveLitePin(Pkcs11TokenInfo token, string userPin)
        {
            if (!string.IsNullOrEmpty(userPin)) return userPin;
            if (token != null && token.PinDefault && !token.PinCountLow &&
                !token.PinFinalTry && !token.PinLocked)
                return "12345678";
            throw new LiteApduException(Strings.Format("err.lite.pin", "—"));
        }

        private static RutokenContainer LoadSavedContainer(
            string folder, string tokenName, string tokenDir, string containerName)
        {
            var container = new RutokenContainer
            {
                TokenName = tokenName,
                TokenDir = tokenDir,
                ContainerName = containerName,
            };
            foreach (string file in ContainerStore.ContainerFiles)
            {
                string path = Path.Combine(folder, file);
                if (File.Exists(path)) container.Files[file] = File.ReadAllBytes(path);
            }
            return container;
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
            string signatureFolder = null;
            try
            {
                if (hasExchange && hasSignature)
                    signatureFolder = CloneLiteOutput(folder, "signature");

                if (hasExchange)
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
                        WriteContainerName(folder, NameWithSuffix(container.ContainerName, " [exchange]"));
                    }
                    Log(Strings.Format("pipe.lite.normalized", folder));
                }

                if (hasSignature)
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
                        WriteContainerName(target, NameWithSuffix(container.ContainerName, " [signature]"));
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

        /// <summary>
        /// Имя контейнера с пометкой ключа, укладывающееся в 125 байт name.key. Длина имени
        /// задана УЦ, и на длинном имени «… [signature]» перестаёт помещаться: NameKey.Build
        /// бросал бы «имя слишком длинное», а весь двухключевой экспорт возвращал бы неудачу
        /// из-за подписи. В cp1251 символ = байт, поэтому режется по символам.
        /// </summary>
        internal static string NameWithSuffix(string name, string suffix)
        {
            name ??= string.Empty;
            int room = NameKey.MaxNameLength - suffix.Length;
            if (name.Length > room) name = name.Substring(0, room);
            return name + suffix;
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
            if (ex == null && sg == null || !AllPresentKeysHandled(container, ex, sg))
            {
                Log(Strings.Format("pipe.keyexport.skip", folder));
                return false;
            }
            return true;
        }

        internal static bool AllPresentKeysHandled(RutokenContainer container,
                                                   string certExchange, string certSignature)
        {
            if (container == null) return false;
            bool hasExchange = container.Files.ContainsKey("primary.key");
            bool hasSignature = container.Files.ContainsKey("primary2.key");
            return (hasExchange || hasSignature)
                && (!hasExchange || !string.IsNullOrEmpty(certExchange))
                && (!hasSignature || !string.IsNullOrEmpty(certSignature));
        }
    }
}
