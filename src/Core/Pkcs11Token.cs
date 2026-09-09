using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Threading;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace CryptoProExport
{
    /// <summary>Семейство подключённого токена — по нему выбирается путь снятия контейнера.</summary>
    public enum RutokenKind
    {
        /// <summary>Рутокен S: файловая память читается прямым PC/SC APDU.</summary>
        RutokenS,
        /// <summary>Рутокен Lite: смарт-карточный профиль, файлы через rtCOMLite не видны.</summary>
        RutokenLite,
        /// <summary>
        /// Рутокен ЭЦП: смарт-карточный профиль. Публичные PKCS#11-объекты могут быть доступны,
        /// но аппаратный закрытый ключ приложение не копирует.
        /// </summary>
        RutokenEcp,
        /// <summary>JaCarta LT: пассивный носитель; файлы контейнера читаются прямым APDU.</summary>
        JaCartaLt,
        /// <summary>
        /// eToken PRO (Java) с апплетом PRO: файловые CSP-контейнеры читаются прямым
        /// APDU только после точного подтверждения модели, производителя, reader и ATR.
        /// </summary>
        JaCartaPro,
        /// <summary>
        /// JaCarta-2 ГОСТ (апплет ГОСТ, AID <c>A0 00 00 04 48 01 01 01 06 02</c>, PKCS#11-модель
        /// <c>eToken GOST</c>). <b>Активный носитель:</b> протокол реверсирован прокси-winscard над
        /// csptest 05.09.2026 — закрытый ключ генерируется и используется в чипе, подпись ГОСТ
        /// считается на карте (APDU <c>80 14</c>), а <c>primary.key</c> с карты не отдаётся ни на
        /// одном наблюдённом пути CSP (<c>check</c>, <c>keycopy</c>). Это граница Рутокен ЭЦП, а не
        /// пассивный файловый раздел LT/PRO/ESMART. Поэтому семейство <b>намеренно не входит</b> в
        /// <see cref="DirectTokenApdu.Supports"/> (fail-closed доказан, а не отложен). Заведено оно,
        /// чтобы носитель честно попадал в перечень с верным именем и заводским PIN и никогда не
        /// уходил в файловый обход rtCOMLite или в чужой APDU. Разбор и доказательство —
        /// docs/hardware/jacarta-2-gost.md.
        /// </summary>
        JaCartaGost,
        /// <summary>ESMART Token: пассивный CSP-раздел читается прямым APDU.</summary>
        Esmart,
        /// <summary>
        /// Носитель БИФИТ (MS_KEY K / «АНГАРА», iBank2Key). Своей библиотеки PKCS#11 в системе
        /// нет, поэтому такой носитель виден только через PC/SC и, если его ATR знаком
        /// КриптоПро, через CSP. Прямого APDU у приложения для него нет — семейство заведено,
        /// чтобы носитель честно попадал в перечень и никогда не уходил в файловый обход
        /// rtCOMLite.
        /// </summary>
        Bifit,
        /// <summary>Другой токен (неподдержанный профиль JaCarta, eToken…) — безопасного пути нет.</summary>
        Other,
        /// <summary>Модель не опознана.</summary>
        Unknown,
    }

    /// <summary>
    /// Профиль поколения по фактически объявленным механизмам PKCS#11. Это не идентификатор
    /// модели: PID, ATR, строка модели и версия прошивки сами по себе поколение не доказывают.
    /// </summary>
    public enum RutokenCapabilityProfile
    {
        Unknown,
        Ecp2Capabilities,
        Ecp3Capable,
    }

    /// <summary>Контейнер КриптоПро, увиденный на токене через PKCS#11 (без обращения к CSP).</summary>
    public sealed class Pkcs11Container
    {
        /// <summary>Имя контейнера (метка объекта CKO_DATA / сертификата).</summary>
        public string Name;
        /// <summary>Значение CKA_APPLICATION — у контейнеров КриптоПро это «CryptoPro CSP».</summary>
        public string Application;
        /// <summary>DER сертификата (CKO_CERTIFICATE), если найден. Читается без PIN.</summary>
        public byte[] Certificate;
        /// <summary>Размер внутреннего блоба CKO_DATA (сериализованный контейнер CSP). 0 — не найден.</summary>
        public int RawLength;

        /// <summary>
        /// На токене есть сертификат, но нет объекта CKO_DATA контейнера КриптоПро.
        /// Такой сертификат всё равно читается без PIN и извлекается командой <c>token</c>,
        /// поэтому он попадает в список — просто называть его «контейнером» нельзя.
        /// </summary>
        public bool CertificateOnly;
    }

    /// <summary>Одно PKCS#11-устройство и его состояние (собирается без ввода PIN).</summary>
    public sealed class Pkcs11TokenInfo
    {
        public string Reader;        // описание слота (совпадает с именем считывателя CSP)
        public string Label;         // метка токена
        public string Model;         // модель, напр. «Rutoken ECP»
        public string Manufacturer;  // производитель, напр. «Aktiv Co.», «Aladdin R.D.»
        public string Serial;        // серийный номер
        public string Hardware;      // версия аппаратной платформы из CK_TOKEN_INFO
        public string Firmware;      // версия прошивки
        /// <summary>ATR из независимого пассивного PC/SC-снимка; null, если подтвердить не удалось.</summary>
        public string Atr;
        public RutokenKind Kind = RutokenKind.Unknown;

        /// <summary>Число механизмов PKCS#11; -1 — список получить не удалось.</summary>
        public int MechanismCount = -1;
        /// <summary>Максимум аппаратной генерации RSA в битах; 0 — не объявлена/не прочитана.</summary>
        public int HardwareRsaMaxBits;
        /// <summary>Объявлены ли аппаратные EC keygen/ECDSA.</summary>
        public bool HardwareEcdsa;
        /// <summary>Объявлен ли любой EC/ECDSA/ECDH-механизм, включая software.</summary>
        public bool EcMechanismPresent;
        /// <summary>Объявлены ли аппаратные ГОСТ keygen/sign.</summary>
        public bool HardwareGost;
        /// <summary>Все относящиеся к профилю механизмы прочитаны без ошибки.</summary>
        public bool CapabilitiesKnown;
        /// <summary>
        /// Список публичных объектов носителя прочитан без ошибки. Ложь при
        /// <c>readContainers: false</c> — их и не читали, — а при <c>true</c> означает сбой:
        /// сессия не открылась или поиск объектов упал. Пустой <see cref="Containers"/> тогда
        /// не доказывает, что контейнеров нет (замечание Codex на PR #83).
        /// </summary>
        public bool ContainersKnown;
        public RutokenCapabilityProfile CapabilityProfile;

        /// <summary>Объём памяти токена для публичных объектов, байт; -1 — не объявлен.</summary>
        public long PublicMemoryTotal = -1;
        /// <summary>Свободная память для публичных объектов, байт; -1 — не объявлена.</summary>
        public long PublicMemoryFree = -1;
        /// <summary>Объём памяти токена для приватных объектов, байт; -1 — не объявлен.</summary>
        public long PrivateMemoryTotal = -1;
        /// <summary>Свободная память для приватных объектов, байт; -1 — не объявлена.</summary>
        public long PrivateMemoryFree = -1;

        /// <summary>PIN пользователя заводской (флаг CKF_USER_PIN_TO_BE_CHANGED) — узнаётся без попытки входа.</summary>
        public bool PinDefault;
        /// <summary>Счётчик попыток PIN на исходе (CKF_USER_PIN_COUNT_LOW).</summary>
        public bool PinCountLow;
        /// <summary>Осталась последняя попытка PIN (CKF_USER_PIN_FINAL_TRY).</summary>
        public bool PinFinalTry;
        /// <summary>PIN заблокирован (CKF_USER_PIN_LOCKED).</summary>
        public bool PinLocked;

        /// <summary>Контейнеры КриптоПро на токене (CKO_DATA с CKA_APPLICATION=CryptoPro CSP), прочитанные без PIN.</summary>
        public List<Pkcs11Container> Containers = new List<Pkcs11Container>();
    }

    /// <summary>Успешно прочитанные стадии одного считывателя между PKCS#11-библиотеками.</summary>
    internal readonly struct Pkcs11ReadState
    {
        internal Pkcs11ReadState(int index, bool capabilitiesRead, bool containersRead)
        {
            Index = index;
            CapabilitiesRead = capabilitiesRead;
            ContainersRead = containersRead;
        }

        internal int Index { get; }
        internal bool CapabilitiesRead { get; }
        internal bool ContainersRead { get; }

        internal bool IsComplete(bool readContainers)
            => CapabilitiesRead && (!readContainers || ContainersRead);
    }

    /// <summary>
    /// Работа с токеном по PKCS#11 — параллельно rtCOMLite.
    ///
    /// Зачем отдельный путь: на Рутокен ЭЦП и Lite файловая память через rtCOMLite не видна
    /// (AGENTS п. 20), а PKCS#11 показывает контейнер КриптоПро как объект CKO_DATA и сам
    /// сертификат как CKO_CERTIFICATE — оба публичные и читаются <b>без ввода PIN</b>. Это даёт:
    ///   • надёжную диагностику токена (модель, серийник, семейство, состояние PIN без траты попыток);
    ///   • извлечение сертификата с токена без КриптоПро CSP.
    /// Закрытый аппаратный ключ Рутокен ЭЦП приложение не читает и не экспортирует. Атрибуты
    /// конкретного ключа можно утверждать только когда такой объект действительно найден;
    /// модель токена и набор механизмов не заменяют проверку объекта.
    ///
    /// Библиотека берётся прежде всего из системы (ставится с драйвером носителя): она обновляется
    /// вместе с драйвером и всегда соответствует ему по версии. Если системной нет, в ход идёт
    /// вшитая копия из <see cref="BundledTools"/> — она позволяет прочитать смарт-карточный
    /// носитель на машине без установленных драйверов. Если нет ни той, ни другой — класс молча
    /// сообщает о недоступности.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class Pkcs11Token
    {
        private const string RutokenDll = "rtPKCS11ECP.dll";
        private const string RutokenLegacyDll = "rtPKCS11.dll";
        private const string JaCartaDll = "jcPKCS11-2.dll";
        private const string EsmartDll = "isbc_pkcs11_main.dll";
        private static readonly string[] EsmartBackendDlls =
        {
            "isbc_esmart_token_mod.dll",
            "isbc_esmart_token_192k_mod.dll",
            "esmart_token_gost_mod.dll",
        };
        private const string CryptoProApp = "CryptoPro CSP";

        /// <summary>
        /// Известные библиотеки PKCS#11 и вендор каждой. Библиотека показывает <b>только свои</b>
        /// носители: проверено 13.08.2026 на машине с четырьмя считывателями — rtPKCS11ECP.dll
        /// отдала три слота (все Рутокены) и не увидела JaCarta, jcPKCS11-2.dll отдала один слот
        /// (только JaCarta). 21.08.2026 подтверждено, что isbc_pkcs11_main.dll с модулем
        /// isbc_esmart_token_mod.dll перечисляет считыватели ESMART; модули трёх вендоров
        /// одновременно загружаются в одном x86-процессе. Поэтому увидеть носители разных
        /// вендоров можно лишь загрузив несколько библиотек и объединив слоты
        /// (см. <see cref="Enumerate"/>).
        /// Имена вендоров — торговые марки и не переводятся.
        /// </summary>
        public static readonly IReadOnlyList<(string Vendor, string Dll)> KnownLibraries =
            new (string Vendor, string Dll)[]
            {
                ("Rutoken", RutokenDll),
                // Старый Rutoken S не показывается ECP-библиотеке, но штатный драйвер
                // устанавливает отдельный rtPKCS11.dll. Дедупликация по reader ниже не
                // даст двум Rutoken-библиотекам показать один носитель дважды.
                ("Rutoken S", RutokenLegacyDll),
                ("JaCarta", JaCartaDll),
                ("ESMART", EsmartDll),
            };

        /// <summary>Кандидаты расположения всех известных библиотек — в порядке <see cref="KnownLibraries"/>.</summary>
        internal static IEnumerable<string> LibraryCandidates()
        {
            foreach (var lib in KnownLibraries)
                foreach (var c in LibraryCandidates(lib.Dll))
                    yield return c;
        }

        /// <summary>Кандидаты расположения одной библиотеки: системный каталог по разрядности + каталог установки.</summary>
        internal static IEnumerable<string> LibraryCandidates(string dll)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // %WINDIR%\System32 в 64-битном процессе — это x64, в 32-битном (WOW64) — x86:
            // GetFolderPath(System) уже отдаёт правильную ветку под разрядность процесса.
            foreach (var path in Paths())
                if (!string.IsNullOrEmpty(path) && seen.Add(path))
                    yield return path;

            // Вшитая копия идёт последней и распаковывается только если сюда дошли:
            // перебор прерывается на первом полном наборе (см. AvailableLibraries).
            string bundled = BundledCandidate(dll);
            if (!string.IsNullOrEmpty(bundled) && seen.Add(bundled))
                yield return bundled;

            IEnumerable<string> Paths()
            {
                yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), dll);

                // Явная ветка на случай нестандартного окружения (переопределённый %WINDIR%\System32).
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(win))
                    yield return Path.Combine(win, Environment.Is64BitProcess ? "System32" : "SysWOW64", dll);

                // Program Files проверяется только для обеих библиотек Рутокена. JaCarta
                // Unified Client кладёт jcPKCS11-2.dll в системный каталог, а руководство
                // ESMART требует системную пару isbc_pkcs11_main.dll вместе с
                // isbc_esmart_token_mod.dll той же разрядности. Случайные прикладные копии
                // этих модулей кандидатами не считаются.
                if (!string.Equals(dll, RutokenDll, StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(dll, RutokenLegacyDll, StringComparison.OrdinalIgnoreCase))
                    yield break;

                foreach (var pf in new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                })
                {
                    if (string.IsNullOrEmpty(pf)) continue;
                    yield return Path.Combine(pf, "Aktiv Co", "RutokenControlCenter", dll.ToLowerInvariant());
                    yield return Path.Combine(pf, "Aktiv Co", "Rutoken", dll);
                }
            }
        }

        /// <summary>
        /// Вшитая копия библиотеки, распакованная в кэш, — последний кандидат: системная всегда
        /// приоритетнее, потому что идёт в комплекте с драйвером и соответствует ему по версии.
        /// Возвращает null, если библиотека не вшита, не распаковалась или не совпала по
        /// разрядности с процессом (вшитые копии 32-битные, как и rtCOMLite).
        ///
        /// Распаковка ленивая: перебор кандидатов доходит сюда только тогда, когда системной
        /// копии нет, поэтому на машине с драйверами эти мегабайты на диск не попадают.
        /// </summary>
        internal static string BundledCandidate(string dll)
        {
            string path = BundledTools.TryExtract(BundledTools.ResourceName(dll), dll, out _);
            if (path == null) return null;

            // ESMART без backend-модуля рядом не инициализируется — распаковываем пару целиком,
            // и только потом отдаём entry module кандидатом (полноту проверит IsLibraryComplete).
            if (string.Equals(dll, EsmartDll, StringComparison.OrdinalIgnoreCase))
                foreach (string backend in EsmartBackendDlls)
                    BundledTools.TryExtract(BundledTools.ResourceName(backend), backend, out _);

            return RegFreeCom.MatchesProcess(path, out _) ? path : null;
        }

        /// <summary>
        /// Установленные в системе библиотеки PKCS#11 — по одной (первой найденной) на вендора.
        /// Пустой список означает, что ни одного драйвера с PKCS#11 нет.
        /// </summary>
        public static List<(string Vendor, string Path)> AvailableLibraries()
        {
            var found = new List<(string Vendor, string Path)>();
            foreach (var lib in KnownLibraries)
            {
                foreach (var candidate in LibraryCandidates(lib.Dll))
                {
                    if (!IsLibraryComplete(lib.Dll, candidate)) continue;
                    found.Add((lib.Vendor, candidate));
                    break;
                }
            }
            return found;
        }

        /// <summary>
        /// Полон ли набор файлов для одной PKCS#11 library. Rutoken и JaCarta состоят из
        /// самостоятельного entry module. ESMART требует рядом backend
        /// isbc_esmart_token_mod.dll: один isbc_pkcs11_main.dll инициализируется, но не даёт
        /// рабочей диагностики токена, поэтому такой путь доступным не считается. Оба ESMART
        /// файла должны совпадать по разрядности с текущим процессом.
        /// </summary>
        internal static bool IsLibraryComplete(string dll, string mainPath)
        {
            try
            {
                if (!File.Exists(mainPath)) return false;
                if (!string.Equals(dll, EsmartDll, StringComparison.OrdinalIgnoreCase)) return true;

                string dir = Path.GetDirectoryName(mainPath);
                if (string.IsNullOrEmpty(dir)) return false;

                // Entry module загружает отдельные backend-модули по семействам. Требуем весь
                // проверенный набор, иначе первый системный кандидат скрывает полную вшитую
                // копию и один из подключённых ESMART пропадает из диагностики.
                if (!RegFreeCom.MatchesProcess(mainPath, out _)) return false;
                foreach (string backend in EsmartBackendDlls)
                {
                    string backendPath = Path.Combine(dir, backend);
                    if (!File.Exists(backendPath)
                        || !RegFreeCom.MatchesProcess(backendPath, out _))
                        return false;
                }
                return true;
            }
            catch
            {
                // Недоступный/некорректный путь — это отсутствующая library, а не авария deps/list.
                return false;
            }
        }

        /// <summary>
        /// Имя файла для сертификата, снятого с токена: метка контейнера плюс серийный номер
        /// токена. Серийник в имени обязателен — у контейнеров на разных токенах метки совпадают
        /// (типовая ситуация при сравнении или переносе), и без него один .cer затирал бы другой.
        /// Недопустимые в имени файла символы заменяются подчёркиванием.
        /// </summary>
        public static string CertFileName(string containerName, string tokenSerial)
        {
            string label = Sanitize(string.IsNullOrWhiteSpace(containerName) ? "cert" : containerName);
            string serial = Sanitize(tokenSerial ?? string.Empty);
            return serial.Length == 0 ? label + ".cer" : label + "_" + serial + ".cer";
        }

        /// <summary>
        /// Путь к .cer, не конфликтующий с уже занятыми в этом запуске: при совпадении имени
        /// добавляется числовой суффикс. <paramref name="taken"/> пополняется выбранным путём.
        /// </summary>
        public static string UniqueCertPath(string outDir, string containerName, string tokenSerial,
                                            ISet<string> taken)
        {
            taken ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string name = CertFileName(containerName, tokenSerial);
            string stem = Path.GetFileNameWithoutExtension(name);
            string path = Path.Combine(outDir ?? string.Empty, name);
            for (int n = 2; ; n++)
            {
                // Коллизии бывают не только внутри текущего перечисления: повторный запуск
                // раньше молча затирал сертификат, уже лежащий в папке с прошлого сеанса.
                bool reserved = taken.Add(path);
                if (reserved && !File.Exists(path)) break;
                path = Path.Combine(outDir ?? string.Empty, $"{stem}({n}).cer");
            }
            return path;
        }

        /// <summary>Заменить символы, недопустимые в имени файла, на подчёркивание.</summary>
        private static string Sanitize(string name)
        {
            foreach (char ch in Path.GetInvalidFileNameChars())
                name = name.Replace(ch, '_');
            return name.Trim();
        }

        /// <summary>Установлена ли в системе хотя бы одна известная библиотека PKCS#11.</summary>
        public static bool IsAvailable => AvailableLibraries().Count > 0;

        /// <summary>
        /// Определить семейство токена по строке модели PKCS#11 (CK_TOKEN_INFO.model) и,
        /// если модель ни о чём не говорит, по производителю (CK_TOKEN_INFO.manufacturerID).
        ///
        /// Производитель нужен не для красоты: у живой JaCarta модель — просто <c>PRO</c>,
        /// поэтому статическая классификация требует точную пару model/manufacturer.
        /// Перед прямым APDU этого недостаточно: отдельно проверяются indexed reader и live ATR.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static RutokenKind Classify(string model, string manufacturer = null)
        {
            // Штатный PKCS#11-модуль ESMART сообщает ISBC/ESMART в модели или производителе.
            // Отдельная строгая проверка перед APDU дополнительно требует точное
            // проверенное семейство reader; здесь достаточно корректно назвать вендора.
            if (HasEsmartEvidence(model))
                return RutokenKind.Esmart;

            // БИФИТ проверяется сразу за ESMART: у семейства «АНГАРА» имя пересекается с
            // ESMART Token ANGARA, и первым должно сработать более точное свидетельство ESMART.
            if (HasBifitEvidence(model))
                return RutokenKind.Bifit;

            // У апплета PRO на eToken PRO строка модели слишком общая: ровно "PRO". Поддержанный
            // профиль разрешаем только в точной паре со штатным manufacturerID; похожие
            // Aladdin/PRO-строки остаются Other/Unknown и никогда не получают этот APDU.
            if (string.Equals((model ?? string.Empty).Trim(), "PRO",
                    StringComparison.OrdinalIgnoreCase)
                && string.Equals((manufacturer ?? string.Empty).Trim(), "Aladdin R.D.",
                    StringComparison.OrdinalIgnoreCase))
                return RutokenKind.JaCartaPro;

            // У JaCarta LT маркетинговое имя и модель апплета различаются: живой носитель
            // сообщает model='JaCarta DS', а официальная документация называет апплет
            // Datastore. Проверяем эту пару до общей классификации JaCarta как Other и до
            // эвристики Rutoken Lite. Короткое 'DS' намеренно недостаточно.
            if (IsJaCartaLt(model, manufacturer)) return RutokenKind.JaCartaLt;

            // Апплет ГОСТ семейства JaCarta (PKCS#11-модель «eToken GOST», «JaCarta GOST»,
            // «JaCarta-2 GOST») распознаём до общей классификации, где подстрока «etoken»/«jacarta»
            // увела бы носитель в Other без имени и заводского PIN. Требуется независимое
            // свидетельство вендора Aladdin — одной строки модели, как и у LT/PRO, недостаточно.
            if (IsJaCartaGost(model, manufacturer)) return RutokenKind.JaCartaGost;

            // Маркер LT/Datastore без независимого свидетельства вендора недостаточен:
            // не понижаем безопасный Unknown до общего Other только из-за слова JaCarta
            // внутри самой модели.
            if (IsJaCartaLtCandidate(model)) return RutokenKind.Unknown;

            RutokenKind byModel = ClassifyText(model);
            if (byModel != RutokenKind.Unknown) return byModel;

            // По производителю опознаём только чужих вендоров: «Aktiv Co.» без внятной модели
            // оставляем неопознанным намеренно — иначе носитель попал бы в файловый обход
            // rtCOMLite как Рутокен S (см. RutokenExporter.ShouldWalk).
            RutokenKind byManufacturer = ClassifyText(manufacturer);
            return byManufacturer == RutokenKind.Esmart || byManufacturer == RutokenKind.Bifit
                || byManufacturer == RutokenKind.Other
                ? byManufacturer : RutokenKind.Unknown;
        }

        /// <summary>
        /// Определить семейство считывателя для выбора протокола: достоверная PKCS#11-
        /// классификация имеет приоритет, а отсутствующие или неполные метаданные дополняются
        /// безопасной классификацией по имени считывателя. В частности, известный <see cref="RutokenKind.Other"/>
        /// нельзя превратить в Рутокен Lite вводящим в заблуждение именем reader, а одной
        /// подстроки <c>lite</c> без независимого свидетельства Rutoken/Aktiv недостаточно.
        /// </summary>
        public static RutokenKind ResolveReaderKind(string readerName, Pkcs11TokenInfo metadata)
        {
            if (metadata != null && metadata.Kind != RutokenKind.Unknown)
                return metadata.Kind;

            RutokenKind fallback = Classify(readerName, metadata?.Manufacturer);
            if (fallback != RutokenKind.RutokenLite) return fallback;

            // Явный чужой вендор сильнее совпавшей подстроки lite — смешивать протоколы
            // смарт-карт опасно. Для неопознанного Foo Lite безопасный результат Unknown.
            if (HasForeignVendorEvidence(readerName) || HasForeignVendorEvidence(metadata?.Manufacturer))
                return RutokenKind.Other;

            return HasRutokenVendorEvidence(readerName) || HasRutokenVendorEvidence(metadata?.Manufacturer)
                ? RutokenKind.RutokenLite
                : RutokenKind.Unknown;
        }

        private static bool HasRutokenVendorEvidence(string text)
        {
            string value = (text ?? string.Empty).Trim().ToLowerInvariant();
            return value.Contains("rutoken") || value.Contains("рутокен")
                || value.Contains("aktiv") || value.Contains("актив");
        }

        private static bool HasForeignVendorEvidence(string text)
        {
            string value = (text ?? string.Empty).Trim().ToLowerInvariant();
            return value.Contains("jacarta") || value.Contains("aladdin")
                || value.Contains("etoken") || value.Contains("esmart")
                || HasBifitEvidence(value);
        }

        /// <summary>
        /// Свидетельство носителя БИФИТ. Слово «АНГАРА» само по себе намеренно не признаётся:
        /// оно есть и у ESMART Token ANGARA (в системе лежит модуль
        /// <c>esmart_token_angara_mod.dll</c>), поэтому нужен явный маркер вендора или модели.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        internal static bool HasBifitEvidence(string text)
        {
            string value = (text ?? string.Empty).Trim().ToLowerInvariant();
            if (value.Length == 0) return false;
            if (value.Contains("bifit") || value.Contains("бифит")) return true;
            return value.Contains("ibank2key") || value.Contains("ibank 2 key")
                || value.Contains("ms_key") || value.Contains("mskey") || value.Contains("ms key");
        }

        private static bool HasEsmartEvidence(string text)
        {
            string value = (text ?? string.Empty).Trim().ToLowerInvariant();
            return value.Contains("esmart") || value.Contains("isbc");
        }

        /// <summary>
        /// Достаточны ли метаданные именно для отправки ESMART APDU. Семейство должен
        /// подтвердить штатный PKCS#11-модуль ISBC, а reader — совпасть с одной из двух
        /// физически проверенных моделей с эксклюзивным именем. Числовой индекс reader может
        /// меняться. Третий проверенный носитель — ESMART Token ГОСТ — прячется за
        /// универсальным считывателем, поэтому он допускается только по точным метаданным
        /// и ATR (см. <see cref="EsmartApdu.IsExactGostMetadata"/>).
        /// </summary>
        internal static bool IsConfirmedEsmart(Pkcs11TokenInfo token)
        {
            if (token == null || token.Kind != RutokenKind.Esmart) return false;
            if (!HasEsmartEvidence(token.Manufacturer)) return false;
            return IsValidatedEsmartReader(token.Reader) || EsmartApdu.IsExactGostMetadata(token);
        }

        /// <summary>
        /// Точные PKCS#11/PCSC-метаданные проверенного eToken PRO (Java) / PRO. Это лишь статическая
        /// часть допуска: непосредственно перед APDU backend дополнительно перечитывает
        /// текущий PC/SC reader и ATR через <see cref="JaCartaProApdu.IsExactLiveReader"/>.
        /// </summary>
        internal static bool IsConfirmedJaCartaPro(Pkcs11TokenInfo token)
            => JaCartaProApdu.IsExactMetadata(token);

        private static bool IsValidatedEsmartReader(string reader)
        {
            string value = (reader ?? string.Empty).Trim();
            return IsIndexedReader(value, "ESMART Token USB 64K")
                || IsIndexedReader(value, "ISBC ESMART Token")
                || IsIndexedReader(value, "ESMART Token Nano 192K");
        }

        private static bool IsIndexedReader(string value, string family)
        {
            if (!value.StartsWith(family + " ", StringComparison.OrdinalIgnoreCase)) return false;
            string index = value.Substring(family.Length + 1);
            if (index.Length == 0) return false;
            foreach (char character in index)
                if (character is < '0' or > '9') return false;
            return true;
        }

        private static bool IsJaCartaLt(string model, string manufacturer)
        {
            string m = (model ?? string.Empty).Trim().ToLowerInvariant();
            if (!IsJaCartaLtCandidate(m)) return false;

            string vendor = (manufacturer ?? string.Empty).Trim().ToLowerInvariant();
            bool vendorMetadata = vendor.Contains("aladdin") || vendor.Contains("jacarta");

            // Слово JaCarta входит в названия моделей DS/LT и само по себе ничего не
            // доказывает. В полной строке штатного reader независимое свидетельство вендора —
            // «Aladdin R.D.» (например, «Aladdin R.D. JaCarta LT 0»).
            bool vendorInReaderName = m.Contains("aladdin");
            return vendorMetadata || vendorInReaderName;
        }

        private static bool IsJaCartaLtCandidate(string model)
        {
            string m = (model ?? string.Empty).Trim().ToLowerInvariant();
            return m.Contains("jacarta ds") || m.Contains("jacarta lt")
                || m.Contains("datastore");
        }

        /// <summary>
        /// Апплет ГОСТ семейства JaCarta: живой JaCarta-2 ГОСТ сообщает PKCS#11-модель
        /// <c>eToken GOST</c> (рядом лежит апплет <c>JaCarta Laser</c>), у отдельных ревизий —
        /// <c>JaCarta GOST</c> / <c>JaCarta-2 GOST</c>. Как и у LT/PRO, одной строки модели мало:
        /// слова <c>etoken</c>/<c>jacarta</c> встречаются и у чужих носителей, поэтому требуется
        /// независимое свидетельство вендора Aladdin (в производителе или в имени reader).
        /// Апплет <c>JaCarta Laser</c> — не ГОСТ и сюда намеренно не попадает.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        internal static bool IsJaCartaGost(string model, string manufacturer)
        {
            string m = (model ?? string.Empty).Trim().ToLowerInvariant();
            if (m.Length == 0 || !m.Contains("gost")) return false;
            if (!m.Contains("etoken") && !m.Contains("jacarta")) return false;

            string vendor = (manufacturer ?? string.Empty).Trim().ToLowerInvariant();
            bool vendorMetadata = vendor.Contains("aladdin") || vendor.Contains("jacarta");
            // «jacarta» в модели — само название продукта, не доказательство вендора; как и в
            // IsJaCartaLt, независимым свидетельством в имени reader служит «aladdin».
            bool vendorInReaderName = m.Contains("aladdin");
            return vendorMetadata || vendorInReaderName;
        }

        /// <summary>
        /// Fail-closed признак только для маршрутизации файлового обхода. Он намеренно шире
        /// точной идентификации: bare LT/Datastore остаётся <see cref="RutokenKind.Unknown"/>,
        /// но к такому считывателю нельзя применять файловый API Рутокен S.
        /// </summary>
        internal static bool HasUnsafeForeignFileWalkEvidence(string text)
            => HasForeignVendorEvidence(text) || IsJaCartaLtCandidate(text);

        private static RutokenKind ClassifyText(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return RutokenKind.Unknown;
            string m = text.Trim().ToLowerInvariant();

            if (m.Contains("esmart") || m.Contains("isbc")) return RutokenKind.Esmart;
            if (HasBifitEvidence(m)) return RutokenKind.Bifit;
            if (m.Contains("ecp") || m.Contains("эцп")) return RutokenKind.RutokenEcp;
            if (m.Contains("lite")) return RutokenKind.RutokenLite;
            // «Rutoken S», «Rutoken» без уточнения, «Рутокен S» — файловая память.
            if (m.Contains("rutoken") || m.Contains("рутокен")) return RutokenKind.RutokenS;
            if (m.Contains("jacarta") || m.Contains("aladdin") || m.Contains("etoken"))
                return RutokenKind.Other;
            return RutokenKind.Unknown;
        }

        /// <summary>
        /// Имена считывателей, которые нельзя отдавать rtCOMLite: смарт-карточные Рутокены,
        /// чужие вендоры и Rutoken S, уже подтверждённый PKCS#11. Для S теперь используется
        /// прямой APDU: rtCOMLite на непустом токене либо отвечает Unsupported function,
        /// либо рушит кучу процесса.
        ///
        /// Чужие вендоры обязаны попадать сюда именно из PKCS#11: <c>ShouldWalk</c> получает только
        /// имя считывателя, а оно бывает безликим (<c>ACS ACR38U 0</c>), и тогда классификация по
        /// имени даёт <c>Unknown</c>. PKCS#11 в этот момент уже знает производителя — этот список
        /// и есть способ донести знание до файлового обхода (замечание Codex на PR #25).
        /// Неподтверждённая LT/Datastore-модель намеренно остаётся <c>Unknown</c> и не получает
        /// имя JaCarta LT, но всё равно исключается отсюда по принципу fail-closed: таких данных
        /// уже достаточно, чтобы не применять к безликому считывателю файловый API Рутокен S.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static ISet<string> SmartCardReaders(IEnumerable<Pkcs11TokenInfo> tokens)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in tokens ?? new List<Pkcs11TokenInfo>())
            {
                if (t == null || string.IsNullOrEmpty(t.Reader)) continue;
                if (t.Kind == RutokenKind.RutokenS
                    || t.Kind == RutokenKind.RutokenEcp || t.Kind == RutokenKind.RutokenLite
                    || t.Kind == RutokenKind.JaCartaLt || t.Kind == RutokenKind.JaCartaPro
                    || t.Kind == RutokenKind.JaCartaGost
                    || t.Kind == RutokenKind.Esmart
                    || t.Kind == RutokenKind.Bifit
                    || t.Kind == RutokenKind.Other
                    || HasUnsafeForeignFileWalkEvidence(t.Model))
                    set.Add(t.Reader);
            }
            return set;
        }

        /// <summary>Локализованное название семейства токена.</summary>
        public static string KindName(RutokenKind kind)
        {
            // Название продукта — торговая марка и во всех языках остаётся одинаковым.
            if (kind == RutokenKind.JaCartaLt) return "JaCarta LT";
            if (kind == RutokenKind.JaCartaPro) return "eToken PRO (Java) / PRO";
            if (kind == RutokenKind.JaCartaGost) return "JaCarta-2 GOST";
            if (kind == RutokenKind.Esmart) return "ESMART";
            if (kind == RutokenKind.Bifit) return "BIFIT";
            return Strings.Get(kind switch
            {
                RutokenKind.RutokenS => "kind.rutoken.s",
                RutokenKind.RutokenLite => "kind.rutoken.lite",
                RutokenKind.RutokenEcp => "kind.rutoken.ecp",
                RutokenKind.Other => "kind.other",
                _ => "kind.unknown",
            });
        }

        /// <summary>
        /// Классифицировать поколение только по возможностям, а не по PID/model/ATR/firmware.
        /// Профиль ЭЦП 2.x требует аппаратные ГОСТ и RSA не выше 2048 при полном отсутствии EC/ECDSA;
        /// RSA выше 2048 или аппаратный ECDSA означают ECP3-capable профиль.
        /// </summary>
        public static RutokenCapabilityProfile ClassifyCapabilities(bool capabilitiesKnown,
            int hardwareRsaMaxBits, bool hardwareEcdsa, bool ecMechanismPresent, bool hardwareGost)
        {
            if (!capabilitiesKnown) return RutokenCapabilityProfile.Unknown;
            if (hardwareEcdsa || hardwareRsaMaxBits > 2048)
                return RutokenCapabilityProfile.Ecp3Capable;
            if (ecMechanismPresent)
                return RutokenCapabilityProfile.Unknown;
            if (hardwareGost && hardwareRsaMaxBits > 0 && hardwareRsaMaxBits <= 2048)
                return RutokenCapabilityProfile.Ecp2Capabilities;
            return RutokenCapabilityProfile.Unknown;
        }

        /// <summary>Локализованное имя профиля возможностей.</summary>
        public static string CapabilityProfileName(RutokenCapabilityProfile profile) => Strings.Get(profile switch
        {
            RutokenCapabilityProfile.Ecp2Capabilities => "cap.profile.ecp2",
            RutokenCapabilityProfile.Ecp3Capable => "cap.profile.ecp3",
            _ => "cap.profile.unknown",
        });

        /// <summary>
        /// Профиль возможностей словами. «Не определился» — это два разных случая, и раньше
        /// оба печатались одинаково: список механизмов вовсе не прочитан (носитель его не отдал)
        /// либо прочитан, но по нему поколение не восстанавливается. Второе — норма для чужих
        /// вендоров: поколение 2.x/3.0 существует только у Рутокен ЭЦП.
        /// </summary>
        public static string CapabilityProfileText(Pkcs11TokenInfo info)
        {
            if (info == null) throw new ArgumentNullException(nameof(info));
            return info.CapabilitiesKnown
                ? CapabilityProfileName(info.CapabilityProfile)
                : Strings.Get("cap.profile.unread");
        }

        /// <summary>Одна безопасная строка диагностики возможностей без PIN и серийного номера.</summary>
        public static string CapabilitySummary(Pkcs11TokenInfo info)
        {
            if (info == null) throw new ArgumentNullException(nameof(info));
            string count = info.MechanismCount >= 0
                ? info.MechanismCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : "?";
            // «RSA HW keygen до — бит» читалось как обрывок строки: разряд подставляется только
            // когда он объявлен, иначе печатается сам признак отсутствия.
            string rsa = info.CapabilitiesKnown
                ? info.HardwareRsaMaxBits > 0
                    ? Strings.Format("cli.token.rsa.bits",
                        info.HardwareRsaMaxBits.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    : "−"
                : "?";
            string ecdsa = info.CapabilitiesKnown ? (info.HardwareEcdsa ? "+" : "−") : "?";
            string gost = info.CapabilitiesKnown ? (info.HardwareGost ? "+" : "−") : "?";
            string line = Strings.Format("cli.token.capabilities", info.Hardware ?? "?", count,
                CapabilityProfileText(info), rsa, ecdsa, gost);

            // Объём памяти читается из тех же метаданных, что и версии, — без PIN и без сессии.
            string memory = MemorySummary(info);
            return memory == null ? line : line + "; " + memory;
        }

        /// <summary>
        /// Байты из CK_TOKEN_INFO. Маркер CK_UNAVAILABLE_INFORMATION (все биты CK_ULONG) значит
        /// «токен объёма не сообщает», а не «памяти столько»: его нельзя показывать числом.
        /// Разрядность CK_ULONG зависит от платформы, поэтому неизвестным считается и
        /// 32-битный, и 64-битный вариант маркера. -1 — не объявлено.
        /// </summary>
        internal static long Memory(ulong value) =>
            value == uint.MaxValue || value > long.MaxValue ? -1 : (long)value;

        /// <summary>
        /// Строка с объёмом памяти токена или null, если он не объявлен.
        ///
        /// PKCS#11 даёт два счётчика — для публичных и для приватных объектов — и не сообщает,
        /// один это пул или два. Поэтому счётчики только показываются, а не складываются и не
        /// объявляются общим пулом: сумма завысила бы объём у токена с одним пулом, а показ
        /// одной пары занизил бы его у токена с двумя. Совпали (Рутокен ЭЦП отдаёт именно так,
        /// проверено 31.08.2026 на двух носителях) — печатается одна пара тех же чисел; разошлись —
        /// обе, каждая со своей подписью.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static string MemorySummary(Pkcs11TokenInfo info)
        {
            if (info == null) throw new ArgumentNullException(nameof(info));

            // Молчим, только когда не объявлено ни одно из четырёх чисел: счётчики независимы,
            // и токен, скрывший общий объём, но назвавший свободный, должен показать свободный
            // (замечание Codex на PR #70).
            if (info.PublicMemoryTotal < 0 && info.PublicMemoryFree < 0
                && info.PrivateMemoryTotal < 0 && info.PrivateMemoryFree < 0)
                return null;

            if (info.PublicMemoryTotal == info.PrivateMemoryTotal
                && info.PublicMemoryFree == info.PrivateMemoryFree)
                return Strings.Format("cli.token.memory",
                    Side(info.PublicMemoryTotal, info.PublicMemoryFree));

            return Strings.Format("cli.token.memory.split",
                Side(info.PublicMemoryTotal, info.PublicMemoryFree),
                Side(info.PrivateMemoryTotal, info.PrivateMemoryFree));
        }

        /// <summary>
        /// Одна пара «объём / свободно» словами.
        ///
        /// Раньше нечисло печаталось знаком вопроса («свободно ? КБ»), и строка читалась как
        /// сбой приложения. На деле это ответ носителя: часть моделей (оба ESMART, проверено
        /// 31.08.2026) отдаёт в CK_TOKEN_INFO маркер CK_UNAVAILABLE_INFORMATION вместо числа, и
        /// другого источника свободного объёма в PKCS#11 нет — ни сложить, ни оценить его не из
        /// чего. Поэтому недостающая величина называется прямо: её не сообщает токен.
        /// </summary>
        private static string Side(long total, long free)
        {
            if (total >= 0 && free >= 0)
                return Strings.Format("cli.token.memory.side", Kilobytes(total), Kilobytes(free));
            if (total >= 0) return Strings.Format("cli.token.memory.side.nofree", Kilobytes(total));
            if (free >= 0) return Strings.Format("cli.token.memory.side.nototal", Kilobytes(free));
            return Strings.Get("cli.token.memory.side.none");
        }

        /// <summary>Байты в килобайтах с округлением. Вызывается только для объявленных величин.</summary>
        private static string Kilobytes(long bytes) =>
            ((bytes + 512) / 1024).ToString(System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>Локализованное состояние PIN (без траты попыток входа).</summary>
        public static string PinState(Pkcs11TokenInfo info) => Strings.Get(
            info.PinLocked ? "pin.state.locked"
            : info.PinFinalTry ? "pin.state.finaltry"
            : info.PinCountLow ? "pin.state.countlow"
            : info.PinDefault ? "pin.state.default"
            : "pin.state.ok");

        /// <summary>
        /// Перечислить подключённые токены и их состояние. PIN не запрашивается: метаданные и
        /// публичные объекты (контейнеры, сертификаты) читаются без авторизации.
        /// Никогда не бросает — при любой ошибке возвращает то, что успел собрать, и пишет в <paramref name="log"/>.
        /// </summary>
        public static List<Pkcs11TokenInfo> Enumerate(bool readContainers = true, Action<string> log = null,
                                                      CancellationToken cancel = default)
        {
            log ??= _ => { };
            var result = new List<Pkcs11TokenInfo>();
            cancel.ThrowIfCancellationRequested();

            var libs = AvailableLibraries();
            if (libs.Count == 0)
            {
                log(Strings.Get("pkcs11.nolib"));
                return result;
            }

            // Один считыватель показывается один раз: теоретически носитель может быть виден
            // двум установленным библиотекам, и дважды перечисленный токен запутал бы и вывод,
            // и SkipReaders. Но «уже видели» — не то же самое, что «уже прочитали»: если первая
            // библиотека на этом считывателе сорвалась, второй дают попробовать, и удачное
            // успешные стадии разных библиотек объединяются, пока не собран полный результат.
            // Сбой одной библиотеки не скрывает носители остальных вендоров: EnumerateLibrary
            // сообщает о нём в лог и возвращает управление, цикл продолжается.
            var seen = new Dictionary<string, Pkcs11ReadState>(StringComparer.OrdinalIgnoreCase);
            foreach (var (_, path) in libs)
            {
                cancel.ThrowIfCancellationRequested();
                EnumerateLibrary(path, readContainers, result, seen, log, cancel);
            }
            AttachPcscAtr(result, PcscReaders.List(log));
            return result;
        }

        /// <summary>Привязать ATR только по точному имени reader; slot index не является идентичностью.</summary>
        internal static void AttachPcscAtr(IEnumerable<Pkcs11TokenInfo> tokens,
                                           IEnumerable<PcscReader> readers)
        {
            var byName = new Dictionary<string, PcscReader>(StringComparer.OrdinalIgnoreCase);
            foreach (PcscReader reader in readers ?? Array.Empty<PcscReader>())
                if (reader != null && reader.CardPresent && !string.IsNullOrWhiteSpace(reader.Name))
                    byName[reader.Name.Trim()] = reader;
            foreach (Pkcs11TokenInfo token in tokens ?? Array.Empty<Pkcs11TokenInfo>())
                if (token != null && !string.IsNullOrWhiteSpace(token.Reader)
                    && byName.TryGetValue(token.Reader.Trim(), out PcscReader reader))
                    token.Atr = reader.Atr;
        }

        /// <summary>
        /// Все запрошенные стадии этого считывателя уже прочитаны другой библиотекой — второй
        /// раз к нему не идём. Частичный результат оставляет недостающей стадии возможность
        /// дочитаться через другую установленную библиотеку.
        /// </summary>
        internal static bool AlreadyRead(IReadOnlyDictionary<string, Pkcs11ReadState> seen, string reader,
                                         bool readContainers)
            => !string.IsNullOrEmpty(reader)
            && seen.TryGetValue(reader, out var prev)
            && prev.IsComplete(readContainers);

        /// <summary>
        /// Положить прочитанный токен в список с дедупликацией по имени считывателя.
        /// Успешные стадии чтения возможностей и объектов объединяются независимо. Уже успешно
        /// прочитанная стадия не заменяется более поздней ошибкой, а запись остаётся на прежнем
        /// месте, чтобы порядок не прыгал. Считыватель без имени дедуплицировать нечем — такой
        /// токен просто добавляется.
        ///
        /// Возвращает <c>false</c>, если новая успешная стадия не добавлена. Покрыта тестами.
        /// </summary>
        internal static bool Place(List<Pkcs11TokenInfo> result, Dictionary<string, Pkcs11ReadState> seen,
                                   Pkcs11TokenInfo info, bool capabilitiesRead, bool containersRead,
                                   bool metadataRead = true)
        {
            // Ошибка C_GetTokenInfo не создаёт токен с выдуманным состоянием PIN.
            // Reader остаётся доступным для повторной попытки через другую библиотеку.
            if (!metadataRead) return false;

            if (string.IsNullOrEmpty(info.Reader))
            {
                result.Add(info);
                return true;
            }

            if (seen.TryGetValue(info.Reader, out var prev))
            {
                bool addCapabilities = capabilitiesRead && !prev.CapabilitiesRead;
                bool addContainers = containersRead && !prev.ContainersRead;
                if (!addCapabilities && !addContainers) return false;

                if (!prev.CapabilitiesRead && !prev.ContainersRead)
                {
                    // Прежняя попытка дала только метаданные: первый успешный этап становится
                    // основой записи, как прежняя полная замена неудачного чтения.
                    result[prev.Index] = info;
                }
                else
                {
                    Pkcs11TokenInfo current = result[prev.Index];
                    if (addCapabilities) CopyCapabilities(info, current);
                    if (addContainers) current.Containers = info.Containers;
                }

                // Полнота чтения объектов накапливается вместе с самими объектами: удачная
                // попытка одной библиотеки не должна теряться из-за неудачной другой.
                result[prev.Index].ContainersKnown = prev.ContainersRead || containersRead;
                seen[info.Reader] = new Pkcs11ReadState(prev.Index,
                    prev.CapabilitiesRead || capabilitiesRead,
                    prev.ContainersRead || containersRead);
                return true;
            }

            seen[info.Reader] = new Pkcs11ReadState(result.Count, capabilitiesRead, containersRead);
            result.Add(info);
            return true;
        }

        private static void CopyCapabilities(Pkcs11TokenInfo source, Pkcs11TokenInfo target)
        {
            target.MechanismCount = source.MechanismCount;
            target.HardwareRsaMaxBits = source.HardwareRsaMaxBits;
            target.HardwareEcdsa = source.HardwareEcdsa;
            target.EcMechanismPresent = source.EcMechanismPresent;
            target.HardwareGost = source.HardwareGost;
            target.CapabilitiesKnown = source.CapabilitiesKnown;
            target.CapabilityProfile = source.CapabilityProfile;
        }

        /// <summary>Перечислить токены одной библиотеки PKCS#11, добавляя их в <paramref name="result"/>.</summary>
        private static void EnumerateLibrary(string lib, bool readContainers, List<Pkcs11TokenInfo> result,
                                             Dictionary<string, Pkcs11ReadState> seen,
                                             Action<string> log, CancellationToken cancel)
        {
            Pkcs11InteropFactories factories;
            IPkcs11Library p11;
            try
            {
                factories = new Pkcs11InteropFactories();
                p11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, lib, AppType.MultiThreaded);
            }
            catch (Exception e)
            {
                // Путь в сообщении обязателен: библиотек несколько, и «не загрузилась» без имени
                // не подсказало бы, какой драйвер чинить.
                log(Strings.Format("pkcs11.loadfail", lib + ": " + e.Message));
                return;
            }

            try
            {
                List<ISlot> slots;
                try { slots = p11.GetSlotList(SlotsType.WithTokenPresent); }
                catch (Exception e) { log(Strings.Format("pkcs11.enumfail", lib + ": " + e.Message)); return; }

                foreach (ISlot slot in slots)
                {
                    // Отмена проверяется между слотами и объектами: вызов внутри драйвера
                    // прервать нельзя, поэтому текущий шаг дочитывается (как в RutokenExporter).
                    cancel.ThrowIfCancellationRequested();
                    var info = new Pkcs11TokenInfo();
                    try { info.Reader = slot.GetSlotInfo().SlotDescription?.Trim(); } catch { }

                    // Считыватель, уже прочитанный удачно, второй библиотеке не отдаём: незачем
                    // дёргать драйвер и незачем показывать один носитель дважды.
                    if (AlreadyRead(seen, info.Reader, readContainers)) continue;

                    bool metadataRead = false;
                    bool capabilitiesRead = false;
                    bool containersRead = false;
                    try
                    {
                        ITokenInfo ti = slot.GetTokenInfo();
                        info.Label = ti.Label?.Trim();
                        info.Model = ti.Model?.Trim();
                        info.Manufacturer = ti.ManufacturerId?.Trim();
                        info.Serial = ti.SerialNumber?.Trim();
                        info.Hardware = ti.HardwareVersion;
                        info.Firmware = ti.FirmwareVersion;
                        info.Kind = Classify(info.Model, info.Manufacturer);

                        info.PublicMemoryTotal = Memory(ti.TotalPublicMemory);
                        info.PublicMemoryFree = Memory(ti.FreePublicMemory);
                        info.PrivateMemoryTotal = Memory(ti.TotalPrivateMemory);
                        info.PrivateMemoryFree = Memory(ti.FreePrivateMemory);

                        var f = ti.TokenFlags;
                        info.PinDefault = f.UserPinToBeChanged;
                        info.PinCountLow = f.UserPinCountLow;
                        info.PinFinalTry = f.UserPinFinalTry;
                        info.PinLocked = f.UserPinLocked;
                        metadataRead = true;

                        // C_GetMechanismList/C_GetMechanismInfo не требуют PIN и не читают объекты.
                        // Профиль поколения строится только по этим возможностям.
                        capabilitiesRead = ReadCapabilities(slot, info, log);

                        // Сбой чтения возможностей или объектов — неполное чтение. Оба метода
                        // гасят ошибки сами, чтобы одна библиотека не останавливала остальные,
                        // и сообщают полноту возвращаемым значением.
                        containersRead = readContainers
                            && ReadContainers(slot, factories, info, log, cancel);
                    }
                    catch (OperationCanceledException) { throw; }   // отмена — не ошибка токена
                    catch (Exception e)
                    {
                        // Драйвер может вернуть пустое описание слота. В таком случае
                        // без DLL и SlotId невозможно определить источник живого сбоя.
                        string reader = string.IsNullOrWhiteSpace(info.Reader) ? "?" : info.Reader;
                        log(Strings.Format("pkcs11.tokenfail", reader,
                            $"{lib} [slot {slot.SlotId}]: {e.Message}"));
                    }

                    info.ContainersKnown = containersRead;
                    Place(result, seen, info, capabilitiesRead, containersRead, metadataRead);
                }
            }
            finally
            {
                try { p11.Dispose(); } catch { }
            }
        }

        /// <summary>
        /// Прочитать профиль механизмов без открытия сессии и без C_Login. При сбое оставляет
        /// профиль неизвестным: версия прошивки или строка модели не используются как догадка.
        /// Возвращает <c>true</c> только после полного чтения списка и информации о механизмах.
        /// </summary>
        private static bool ReadCapabilities(ISlot slot, Pkcs11TokenInfo info, Action<string> log)
        {
            try
            {
                List<CKM> mechanisms = slot.GetMechanismList();
                info.MechanismCount = mechanisms.Count;

                foreach (CKM mechanism in mechanisms)
                {
                    if (!IsCapabilityMechanism(mechanism)) continue;
                    IMechanismInfo mi = slot.GetMechanismInfo(mechanism);

                    // Наличие software EC/ECDSA тоже существенно: такой список нельзя честно
                    // называть профилем ЭЦП 2.x только потому, что у механизма нет CKF_HW.
                    if (IsEcMechanism(mechanism)) info.EcMechanismPresent = true;
                    if (!mi.MechanismFlags.Hw) continue;

                    if (mechanism == CKM.CKM_RSA_PKCS_KEY_PAIR_GEN)
                    {
                        int max = mi.MaxKeySize > int.MaxValue ? int.MaxValue : (int)mi.MaxKeySize;
                        info.HardwareRsaMaxBits = Math.Max(info.HardwareRsaMaxBits, max);
                    }
                    if (IsEcdsaMechanism(mechanism)) info.HardwareEcdsa = true;
                    if (IsGostMechanism(mechanism)) info.HardwareGost = true;
                }

                info.CapabilitiesKnown = true;
                info.CapabilityProfile = info.Kind == RutokenKind.RutokenEcp
                    ? ClassifyCapabilities(true, info.HardwareRsaMaxBits,
                        info.HardwareEcdsa, info.EcMechanismPresent, info.HardwareGost)
                    : RutokenCapabilityProfile.Unknown;
                return true;
            }
            catch (Exception e)
            {
                // Частичные флаги не выдаём за полный профиль.
                info.HardwareRsaMaxBits = 0;
                info.HardwareEcdsa = false;
                info.EcMechanismPresent = false;
                info.HardwareGost = false;
                info.CapabilitiesKnown = false;
                info.CapabilityProfile = RutokenCapabilityProfile.Unknown;
                log(Strings.Format("pkcs11.capfail", e.Message));
                return false;
            }
        }

        private static bool IsCapabilityMechanism(CKM mechanism) =>
            mechanism == CKM.CKM_RSA_PKCS_KEY_PAIR_GEN
            || IsEcMechanism(mechanism)
            || IsGostMechanism(mechanism);

        private static bool IsEcMechanism(CKM mechanism) =>
            IsEcdsaMechanism(mechanism)
            || mechanism == CKM.CKM_ECDH1_DERIVE
            || mechanism == CKM.CKM_ECDH1_COFACTOR_DERIVE
            || mechanism == CKM.CKM_ECMQV_DERIVE
            || mechanism == CKM.CKM_ECDH_AES_KEY_WRAP;

        private static bool IsEcdsaMechanism(CKM mechanism) =>
            mechanism == CKM.CKM_EC_KEY_PAIR_GEN
            || mechanism == CKM.CKM_ECDSA_KEY_PAIR_GEN
            || mechanism == CKM.CKM_ECDSA
            || mechanism == CKM.CKM_ECDSA_SHA1
            || mechanism == CKM.CKM_ECDSA_SHA224
            || mechanism == CKM.CKM_ECDSA_SHA256
            || mechanism == CKM.CKM_ECDSA_SHA384
            || mechanism == CKM.CKM_ECDSA_SHA512;

        private static bool IsGostMechanism(CKM mechanism) =>
            mechanism == CKM.CKM_GOSTR3410_KEY_PAIR_GEN
            || mechanism == CKM.CKM_GOSTR3410
            || mechanism == CKM.CKM_GOSTR3410_WITH_GOSTR3411;

        /// <summary>
        /// Прочитать публичные контейнеры КриптоПро (CKO_DATA с приложением «CryptoPro CSP») и
        /// связанные с ними сертификаты (CKO_CERTIFICATE с той же меткой). Без входа по PIN.
        /// Возвращает <c>false</c>, если объекты прочитать не удалось: исключение здесь гасится
        /// (список объектов не должен ронять перечисление токенов), и о неудаче надо сообщить иначе.
        /// </summary>
        private static bool ReadContainers(ISlot slot, Pkcs11InteropFactories factories,
                                           Pkcs11TokenInfo info, Action<string> log, CancellationToken cancel)
        {
            ISession session = null;
            try
            {
                session = slot.OpenSession(SessionType.ReadOnly);

                // Сертификаты токена: метка -> DER. Читаем заранее, чтобы приложить к контейнеру.
                var certs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                foreach (var h in FindByClass(session, factories, CKO.CKO_CERTIFICATE))
                {
                    cancel.ThrowIfCancellationRequested();
                    string label = GetString(session, h, CKA.CKA_LABEL);
                    byte[] der = GetBytes(session, h, CKA.CKA_VALUE);
                    if (!string.IsNullOrEmpty(label) && der != null && !certs.ContainsKey(label))
                        certs[label] = der;
                }

                var containers = new List<Pkcs11Container>();
                foreach (var h in FindByClass(session, factories, CKO.CKO_DATA))
                {
                    cancel.ThrowIfCancellationRequested();
                    string app = GetString(session, h, CKA.CKA_APPLICATION);
                    if (!string.Equals(app, CryptoProApp, StringComparison.OrdinalIgnoreCase))
                        continue; // чужой DATA-объект, не контейнер КриптоПро

                    string label = GetString(session, h, CKA.CKA_LABEL);
                    byte[] raw = GetBytes(session, h, CKA.CKA_VALUE);
                    var container = new Pkcs11Container
                    {
                        Name = label,
                        Application = app,
                        RawLength = raw?.Length ?? 0,
                    };
                    if (!string.IsNullOrEmpty(label) && certs.TryGetValue(label, out var der))
                        container.Certificate = der;
                    containers.Add(container);
                }

                info.Containers.AddRange(Combine(containers, certs));
                return true;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                log(Strings.Format("pkcs11.readfail", e.Message));
                return false;
            }
            finally
            {
                try { session?.CloseSession(); } catch { }
            }
        }

        /// <summary>
        /// Свести контейнеры и сертификаты токена в один список: сначала контейнеры КриптоПро
        /// (CKO_DATA), затем сертификаты, которым контейнер не нашёлся.
        ///
        /// Зачем второй проход: сертификат привязывается к контейнеру по совпадению меток, и
        /// сертификат с непарной меткой раньше исчезал совсем — ни в списке, ни в извлечении
        /// командой <c>token</c>. Между тем он лежит публичным объектом и читается без PIN, то есть
        /// это ровно то, ради чего сделана CSP-free ветка. Случай не выдуманный: контейнеры,
        /// которые кладёт на токен сам CSP, объектами PKCS#11 не становятся (AGENTS п. 25), так
        /// что сертификат вполне может оказаться на токене без парного CKO_DATA.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static List<Pkcs11Container> Combine(IList<Pkcs11Container> containers,
                                                    IDictionary<string, byte[]> certs)
        {
            var result = new List<Pkcs11Container>();
            var used = new HashSet<string>(StringComparer.Ordinal);
            foreach (var c in containers ?? new List<Pkcs11Container>())
            {
                result.Add(c);
                if (c.Certificate != null && !string.IsNullOrEmpty(c.Name)) used.Add(c.Name);
            }

            foreach (var pair in certs ?? new Dictionary<string, byte[]>())
            {
                if (used.Contains(pair.Key)) continue;
                result.Add(new Pkcs11Container
                {
                    Name = pair.Key,
                    Certificate = pair.Value,
                    CertificateOnly = true,
                });
            }
            return result;
        }

        private static List<IObjectHandle> FindByClass(ISession session, Pkcs11InteropFactories factories, CKO cls)
        {
            var template = new List<IObjectAttribute>
            {
                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, (ulong)cls),
            };
            return session.FindAllObjects(template);
        }

        private static string GetString(ISession session, IObjectHandle h, CKA attr)
        {
            try { return session.GetAttributeValue(h, new List<CKA> { attr })[0].GetValueAsString(); }
            catch { return null; }
        }

        private static byte[] GetBytes(ISession session, IObjectHandle h, CKA attr)
        {
            try { return session.GetAttributeValue(h, new List<CKA> { attr })[0].GetValueAsByteArray(); }
            catch { return null; }
        }
    }
}
