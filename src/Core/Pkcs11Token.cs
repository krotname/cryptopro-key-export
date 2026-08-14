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
        /// <summary>Рутокен S / старые: файловая память доступна через rtCOMLite.</summary>
        RutokenS,
        /// <summary>Рутокен Lite: смарт-карточный профиль, файлы через rtCOMLite не видны.</summary>
        RutokenLite,
        /// <summary>Рутокен ЭЦП / ЭЦП 2.0: смарт-карточный профиль; контейнер виден как PKCS#11 CKO_DATA.</summary>
        RutokenEcp,
        /// <summary>Токен другого вендора (JaCarta, eToken…) — распознан, но путь не проверялся.</summary>
        Other,
        /// <summary>Модель не опознана.</summary>
        Unknown,
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
        public string Firmware;      // версия прошивки
        public RutokenKind Kind;

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

    /// <summary>
    /// Работа с токеном по PKCS#11 — параллельно rtCOMLite.
    ///
    /// Зачем отдельный путь: на Рутокен ЭЦП и Lite файловая память через rtCOMLite не видна
    /// (AGENTS п. 20), а PKCS#11 показывает контейнер КриптоПро как объект CKO_DATA и сам
    /// сертификат как CKO_CERTIFICATE — оба публичные и читаются <b>без ввода PIN</b>. Это даёт:
    ///   • надёжную диагностику токена (модель, серийник, семейство, состояние PIN без траты попыток);
    ///   • извлечение сертификата с токена без КриптоПро CSP.
    /// Закрытый ключ через PKCS#11 не извлекается (CKA_EXTRACTABLE=false, аппаратно) — это ограничение
    /// железа, а не кода.
    ///
    /// Библиотеки берутся из системы (ставятся с драйвером носителя), а не вшиваются: они большие
    /// и обновляются вместе с драйвером. Если ни одной нет — класс молча сообщает о недоступности.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class Pkcs11Token
    {
        private const string RutokenDll = "rtPKCS11ECP.dll";
        private const string JaCartaDll = "jcPKCS11-2.dll";
        private const string CryptoProApp = "CryptoPro CSP";

        /// <summary>
        /// Известные библиотеки PKCS#11 и вендор каждой. Библиотека показывает <b>только свои</b>
        /// носители: проверено 13.08.2026 на машине с четырьмя считывателями — rtPKCS11ECP.dll
        /// отдала три слота (все Рутокены) и не увидела JaCarta, jcPKCS11-2.dll отдала один слот
        /// (только JaCarta). Поэтому увидеть носители разных вендоров можно лишь загрузив
        /// несколько библиотек и объединив слоты (см. <see cref="Enumerate"/>).
        /// Имена вендоров — торговые марки и не переводятся.
        /// </summary>
        public static readonly IReadOnlyList<(string Vendor, string Dll)> KnownLibraries =
            new (string Vendor, string Dll)[]
            {
                ("Rutoken", RutokenDll),
                ("JaCarta", JaCartaDll),
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

            IEnumerable<string> Paths()
            {
                yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), dll);

                // Явная ветка на случай нестандартного окружения (переопределённый %WINDIR%\System32).
                string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (!string.IsNullOrEmpty(win))
                    yield return Path.Combine(win, Environment.Is64BitProcess ? "System32" : "SysWOW64", dll);

                // Каталог установки перечисляется только для Рутокена: JaCarta Unified Client
                // кладёт jcPKCS11-2.dll исключительно в системный каталог (проверено на машине,
                // где клиент установлен, — в Program Files библиотеки нет).
                if (!string.Equals(dll, RutokenDll, StringComparison.OrdinalIgnoreCase)) yield break;

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
                    bool exists;
                    try { exists = File.Exists(candidate); }
                    catch { continue; }   // недоступный путь — пропускаем
                    if (!exists) continue;
                    found.Add((lib.Vendor, candidate));
                    break;
                }
            }
            return found;
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
        /// Производитель нужен не для красоты: у живой JaCarta модель — просто <c>PRO</c>
        /// (проверено 13.08.2026), и по одной модели носитель попадал бы в «не опознан».
        /// Производитель там <c>Aladdin R.D.</c>, чего достаточно.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static RutokenKind Classify(string model, string manufacturer = null)
        {
            RutokenKind byModel = ClassifyText(model);
            if (byModel != RutokenKind.Unknown) return byModel;

            // По производителю опознаём только чужих вендоров: «Aktiv Co.» без внятной модели
            // оставляем неопознанным намеренно — иначе носитель попал бы в файловый обход
            // rtCOMLite как Рутокен S (см. RutokenExporter.ShouldWalk).
            return ClassifyText(manufacturer) == RutokenKind.Other ? RutokenKind.Other : RutokenKind.Unknown;
        }

        private static RutokenKind ClassifyText(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return RutokenKind.Unknown;
            string m = text.Trim().ToLowerInvariant();

            if (m.Contains("ecp") || m.Contains("эцп")) return RutokenKind.RutokenEcp;
            if (m.Contains("lite")) return RutokenKind.RutokenLite;
            // «Rutoken S», «Rutoken» без уточнения, «Рутокен S» — файловая память.
            if (m.Contains("rutoken") || m.Contains("рутокен")) return RutokenKind.RutokenS;
            if (m.Contains("jacarta") || m.Contains("aladdin") || m.Contains("etoken")
                || m.Contains("esmart")) return RutokenKind.Other;
            return RutokenKind.Unknown;
        }

        /// <summary>
        /// Имена считывателей, чью файловую память обходить нельзя: смарт-карточные Рутокены
        /// (ЭЦП, Lite) и носители чужих вендоров — см. <see cref="RutokenExporter.ShouldWalk"/>.
        ///
        /// Чужие вендоры обязаны попадать сюда именно из PKCS#11: <c>ShouldWalk</c> получает только
        /// имя считывателя, а оно бывает безликим (<c>ACS ACR38U 0</c>), и тогда классификация по
        /// имени даёт <c>Unknown</c>. PKCS#11 в этот момент уже знает производителя — этот список
        /// и есть способ донести знание до файлового обхода (замечание Codex на PR #25).
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static ISet<string> SmartCardReaders(IEnumerable<Pkcs11TokenInfo> tokens)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var t in tokens ?? new List<Pkcs11TokenInfo>())
            {
                if (t == null || string.IsNullOrEmpty(t.Reader)) continue;
                if (t.Kind == RutokenKind.RutokenEcp || t.Kind == RutokenKind.RutokenLite
                    || t.Kind == RutokenKind.Other)
                    set.Add(t.Reader);
            }
            return set;
        }

        /// <summary>Локализованное название семейства токена.</summary>
        public static string KindName(RutokenKind kind) => Strings.Get(kind switch
        {
            RutokenKind.RutokenS => "kind.rutoken.s",
            RutokenKind.RutokenLite => "kind.rutoken.lite",
            RutokenKind.RutokenEcp => "kind.rutoken.ecp",
            RutokenKind.Other => "kind.other",
            _ => "kind.unknown",
        });

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
            // чтение заменяет неудачную запись (замечание Codex на PR #25).
            // Сбой одной библиотеки не скрывает носители остальных вендоров: EnumerateLibrary
            // сообщает о нём в лог и возвращает управление, цикл продолжается.
            var seen = new Dictionary<string, (int Index, bool Ok)>(StringComparer.OrdinalIgnoreCase);
            foreach (var (_, path) in libs)
            {
                cancel.ThrowIfCancellationRequested();
                EnumerateLibrary(path, readContainers, result, seen, log, cancel);
            }
            return result;
        }

        /// <summary>
        /// Этот считыватель уже прочитан удачно другой библиотекой — второй раз к нему не идём.
        /// Неудачная попытка «прочитанным» не считается: сбой драйвера одного вендора не должен
        /// прятать данные, которые отдаёт другой (замечание Codex на PR #25).
        /// </summary>
        internal static bool AlreadyRead(IReadOnlyDictionary<string, (int Index, bool Ok)> seen, string reader)
            => !string.IsNullOrEmpty(reader) && seen.TryGetValue(reader, out var prev) && prev.Ok;

        /// <summary>
        /// Положить прочитанный токен в список с дедупликацией по имени считывателя.
        /// Удачное чтение заменяет прежнюю неудачную запись того же считывателя — на его месте,
        /// чтобы порядок не прыгал; неудачное поверх неудачной не кладётся, иначе один носитель
        /// занял бы в списке две строки. Считыватель без имени дедуплицировать нечем — такой
        /// токен просто добавляется.
        ///
        /// Возвращает <c>false</c>, если запись отброшена. Чистая функция: покрыта тестами.
        /// </summary>
        internal static bool Place(List<Pkcs11TokenInfo> result, Dictionary<string, (int Index, bool Ok)> seen,
                                   Pkcs11TokenInfo info, bool ok)
        {
            if (string.IsNullOrEmpty(info.Reader))
            {
                result.Add(info);
                return true;
            }

            if (seen.TryGetValue(info.Reader, out var prev))
            {
                if (prev.Ok || !ok) return false;
                result[prev.Index] = info;
                seen[info.Reader] = (prev.Index, true);
                return true;
            }

            seen[info.Reader] = (result.Count, ok);
            result.Add(info);
            return true;
        }

        /// <summary>Перечислить токены одной библиотеки PKCS#11, добавляя их в <paramref name="result"/>.</summary>
        private static void EnumerateLibrary(string lib, bool readContainers, List<Pkcs11TokenInfo> result,
                                             Dictionary<string, (int Index, bool Ok)> seen,
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
                    if (AlreadyRead(seen, info.Reader)) continue;

                    bool ok = false;
                    try
                    {
                        ITokenInfo ti = slot.GetTokenInfo();
                        info.Label = ti.Label?.Trim();
                        info.Model = ti.Model?.Trim();
                        info.Manufacturer = ti.ManufacturerId?.Trim();
                        info.Serial = ti.SerialNumber?.Trim();
                        info.Firmware = ti.FirmwareVersion;
                        info.Kind = Classify(info.Model, info.Manufacturer);

                        var f = ti.TokenFlags;
                        info.PinDefault = f.UserPinToBeChanged;
                        info.PinCountLow = f.UserPinCountLow;
                        info.PinFinalTry = f.UserPinFinalTry;
                        info.PinLocked = f.UserPinLocked;

                        // Сбой чтения объектов — тоже неполное чтение: ReadContainers гасит
                        // исключение сам (список объектов не должен ронять перечисление токенов),
                        // поэтому об успехе он сообщает возвращаемым значением.
                        ok = !readContainers || ReadContainers(slot, factories, info, log, cancel);
                    }
                    catch (OperationCanceledException) { throw; }   // отмена — не ошибка токена
                    catch (Exception e)
                    {
                        log(Strings.Format("pkcs11.tokenfail", info.Reader ?? "?", e.Message));
                    }

                    Place(result, seen, info, ok);
                }
            }
            finally
            {
                try { p11.Dispose(); } catch { }
            }
        }

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
