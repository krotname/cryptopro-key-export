using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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
    }

    /// <summary>Одно PKCS#11-устройство и его состояние (собирается без ввода PIN).</summary>
    public sealed class Pkcs11TokenInfo
    {
        public string Reader;    // описание слота (совпадает с именем считывателя CSP)
        public string Label;     // метка токена
        public string Model;     // модель, напр. «Rutoken ECP»
        public string Serial;    // серийный номер
        public string Firmware;  // версия прошивки
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
    /// Работа с Рутокеном по PKCS#11 (rtPKCS11ECP.dll) — параллельно rtCOMLite.
    ///
    /// Зачем отдельный путь: на Рутокен ЭЦП и Lite файловая память через rtCOMLite не видна
    /// (AGENTS п. 20), а PKCS#11 показывает контейнер КриптоПро как объект CKO_DATA и сам
    /// сертификат как CKO_CERTIFICATE — оба публичные и читаются <b>без ввода PIN</b>. Это даёт:
    ///   • надёжную диагностику токена (модель, серийник, семейство, состояние PIN без траты попыток);
    ///   • извлечение сертификата с токена без КриптоПро CSP.
    /// Закрытый ключ через PKCS#11 не извлекается (CKA_EXTRACTABLE=false, аппаратно) — это ограничение
    /// железа, а не кода.
    ///
    /// Библиотека берётся из системы (ставится с драйвером Рутокена), а не вшивается: она большая
    /// и обновляется вместе с драйвером. Если её нет — класс молча сообщает о недоступности.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class Pkcs11Token
    {
        private const string DllName = "rtPKCS11ECP.dll";
        private const string CryptoProApp = "CryptoPro CSP";

        /// <summary>Кандидаты расположения rtPKCS11ECP.dll: системный каталог по разрядности + установка Рутокена.</summary>
        internal static IEnumerable<string> LibraryCandidates()
        {
            // %WINDIR%\System32 в 64-битном процессе — это x64, в 32-битном (WOW64) — x86:
            // GetFolderPath(System) уже отдаёт правильную ветку под разрядность процесса.
            string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            yield return Path.Combine(sys, DllName);

            // Явные ветки на случай нестандартного окружения.
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            yield return Path.Combine(win, Environment.Is64BitProcess ? "System32" : "SysWOW64", DllName);

            foreach (var pf in new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            })
            {
                if (string.IsNullOrEmpty(pf)) continue;
                yield return Path.Combine(pf, "Aktiv Co", "RutokenControlCenter", DllName.ToLowerInvariant());
                yield return Path.Combine(pf, "Aktiv Co", "Rutoken", DllName);
            }
        }

        /// <summary>Путь к библиотеке PKCS#11 Рутокена или null, если она не установлена.</summary>
        public static string LibraryPath()
        {
            foreach (var c in LibraryCandidates())
            {
                try { if (File.Exists(c)) return c; }
                catch { /* недоступный путь — пропускаем */ }
            }
            return null;
        }

        /// <summary>Установлена ли библиотека PKCS#11 Рутокена в системе.</summary>
        public static bool IsAvailable => LibraryPath() != null;

        /// <summary>
        /// Определить семейство токена по строке модели PKCS#11 (CKA/CK_TOKEN_INFO.model).
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static RutokenKind Classify(string model)
        {
            if (string.IsNullOrWhiteSpace(model)) return RutokenKind.Unknown;
            string m = model.Trim().ToLowerInvariant();

            if (m.Contains("ecp") || m.Contains("эцп")) return RutokenKind.RutokenEcp;
            if (m.Contains("lite")) return RutokenKind.RutokenLite;
            // «Rutoken S», «Rutoken» без уточнения, «Рутокен S» — файловая память.
            if (m.Contains("rutoken") || m.Contains("рутокен")) return RutokenKind.RutokenS;
            if (m.Contains("jacarta") || m.Contains("etoken") || m.Contains("esmart")) return RutokenKind.Other;
            return RutokenKind.Unknown;
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
        public static List<Pkcs11TokenInfo> Enumerate(bool readContainers = true, Action<string> log = null)
        {
            log ??= _ => { };
            var result = new List<Pkcs11TokenInfo>();

            string lib = LibraryPath();
            if (lib == null)
            {
                log(Strings.Get("pkcs11.nolib"));
                return result;
            }

            Pkcs11InteropFactories factories;
            IPkcs11Library p11 = null;
            try
            {
                factories = new Pkcs11InteropFactories();
                p11 = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, lib, AppType.MultiThreaded);
            }
            catch (Exception e)
            {
                log(Strings.Format("pkcs11.loadfail", e.Message));
                return result;
            }

            try
            {
                List<ISlot> slots;
                try { slots = p11.GetSlotList(SlotsType.WithTokenPresent); }
                catch (Exception e) { log(Strings.Format("pkcs11.enumfail", e.Message)); return result; }

                foreach (ISlot slot in slots)
                {
                    var info = new Pkcs11TokenInfo();
                    try
                    {
                        try { info.Reader = slot.GetSlotInfo().SlotDescription?.Trim(); } catch { }

                        ITokenInfo ti = slot.GetTokenInfo();
                        info.Label = ti.Label?.Trim();
                        info.Model = ti.Model?.Trim();
                        info.Serial = ti.SerialNumber?.Trim();
                        info.Firmware = ti.FirmwareVersion;
                        info.Kind = Classify(info.Model);

                        var f = ti.TokenFlags;
                        info.PinDefault = f.UserPinToBeChanged;
                        info.PinCountLow = f.UserPinCountLow;
                        info.PinFinalTry = f.UserPinFinalTry;
                        info.PinLocked = f.UserPinLocked;

                        if (readContainers)
                            ReadContainers(slot, factories, info, log);
                    }
                    catch (Exception e)
                    {
                        log(Strings.Format("pkcs11.tokenfail", info.Reader ?? "?", e.Message));
                    }
                    result.Add(info);
                }
            }
            finally
            {
                try { p11.Dispose(); } catch { }
            }
            return result;
        }

        /// <summary>
        /// Прочитать публичные контейнеры КриптоПро (CKO_DATA с приложением «CryptoPro CSP») и
        /// связанные с ними сертификаты (CKO_CERTIFICATE с той же меткой). Без входа по PIN.
        /// </summary>
        private static void ReadContainers(ISlot slot, Pkcs11InteropFactories factories,
                                           Pkcs11TokenInfo info, Action<string> log)
        {
            ISession session = null;
            try
            {
                session = slot.OpenSession(SessionType.ReadOnly);

                // Сертификаты токена: метка -> DER. Читаем заранее, чтобы приложить к контейнеру.
                var certs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
                foreach (var h in FindByClass(session, factories, CKO.CKO_CERTIFICATE))
                {
                    string label = GetString(session, h, CKA.CKA_LABEL);
                    byte[] der = GetBytes(session, h, CKA.CKA_VALUE);
                    if (!string.IsNullOrEmpty(label) && der != null && !certs.ContainsKey(label))
                        certs[label] = der;
                }

                foreach (var h in FindByClass(session, factories, CKO.CKO_DATA))
                {
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
                    info.Containers.Add(container);
                }
            }
            catch (Exception e)
            {
                log(Strings.Format("pkcs11.readfail", e.Message));
            }
            finally
            {
                try { session?.CloseSession(); } catch { }
            }
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
