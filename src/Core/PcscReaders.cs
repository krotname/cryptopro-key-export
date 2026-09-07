using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace CryptoProExport
{
    /// <summary>Считыватель PC/SC и состояние вставленной карты (снимается пассивно, без подключения).</summary>
    public sealed class PcscReader
    {
        /// <summary>Имя считывателя, как его отдаёт winscard (совпадает с именем слота PKCS#11 и CSP).</summary>
        public string Name;
        /// <summary>В считывателе есть карта (флаг SCARD_STATE_PRESENT).</summary>
        public bool CardPresent;
        /// <summary>ATR карты в hex через пробел (верхний регистр); <c>null</c>, если карты нет.</summary>
        public string Atr;
    }

    /// <summary>
    /// Пассивное перечисление считывателей PC/SC поверх системного <c>winscard.dll</c>.
    ///
    /// Зачем это отдельно от <see cref="Pkcs11Token"/>: библиотека PKCS#11 показывает токен
    /// только для <b>своих</b> носителей. Карта, которую не обслуживает ни одна установленная
    /// библиотека (например, JaCarta на платформе Athena IDProtect — она работает через
    /// минидрайвер Microsoft, а её ATR нет в списках vendor-библиотек), в PKCS#11 не видна вовсе,
    /// и команды <c>list</c>/<c>token</c> тогда сообщали «токенов нет», хотя карта физически стоит.
    /// Пассивный опрос PC/SC даёт честную картину: какие карты реально вставлены, чтобы отличить
    /// «носитель не вставлен» от «носитель есть, но не является поддерживаемым контейнером».
    ///
    /// Строго только чтение: используется <c>SCardGetStatusChange</c> с нулевым тайм-аутом —
    /// он читает состояние и ATR, <b>не подключаясь</b> к карте и не открывая транзакцию, поэтому
    /// не мешает ни CSP, ни другому агенту, работающему с соседним токеном. Класс никогда не
    /// бросает: при любой ошибке возвращает то, что успел собрать.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class PcscReaders
    {
        private const uint SCARD_SCOPE_SYSTEM = 2;
        private const uint SCARD_STATE_UNAWARE = 0x0000;
        private const uint SCARD_STATE_PRESENT = 0x0020;
        private const int SCARD_ATR_LENGTH = 36;
        private const uint SCARD_S_SUCCESS = 0;
        /// <summary>Считывателей нет — это норма, а не сбой опроса.</summary>
        private const uint SCARD_E_NO_READERS_AVAILABLE = 0x8010002E;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SCARD_READERSTATE
        {
            public string szReader;
            public IntPtr pvUserData;
            public uint dwCurrentState;
            public uint dwEventState;
            public uint cbAtr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = SCARD_ATR_LENGTH)]
            public byte[] rgbAtr;
        }

        [DllImport("winscard.dll", SetLastError = true)]
        private static extern uint SCardEstablishContext(uint scope, IntPtr r1, IntPtr r2, out IntPtr ctx);

        [DllImport("winscard.dll")]
        private static extern uint SCardReleaseContext(IntPtr ctx);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardListReadersW")]
        private static extern uint SCardListReaders(IntPtr ctx, string groups, char[] readers, ref uint len);

        [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardGetStatusChangeW")]
        private static extern uint SCardGetStatusChange(IntPtr ctx, uint timeout,
            [In, Out] SCARD_READERSTATE[] states, uint count);

        /// <summary>
        /// Перечислить считыватели PC/SC и состояние карты в каждом. Никогда не бросает:
        /// при любой ошибке (нет службы смарт-карт, нет считывателей, сбой winscard) пишет причину
        /// в <paramref name="log"/> и возвращает то, что удалось собрать (возможно, пустой список).
        /// </summary>
        public static List<PcscReader> List(Action<string> log = null) => List(log, out _);

        /// <summary>
        /// То же перечисление, но с признаком полноты: <paramref name="complete"/> равен
        /// <c>false</c>, если опрос сорвался (нет контекста, winscard вернул ошибку, упало
        /// исключение). Пустой список тогда не означает «носителей нет» — он означает
        /// «неизвестно», и звать вставить носитель по нему нельзя (замечание Codex на PR #83).
        /// Отсутствие считывателей ошибкой не считается: это обычное состояние машины.
        /// </summary>
        public static List<PcscReader> List(Action<string> log, out bool complete)
        {
            log ??= _ => { };
            var result = new List<PcscReader>();
            complete = true;

            IntPtr ctx = IntPtr.Zero;
            try
            {
                uint rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out ctx);
                if (rv != SCARD_S_SUCCESS)
                {
                    // Служба смарт-карт может быть остановлена — это не ошибка приложения,
                    // просто «карт нет». Код полезен в диагностике.
                    log(Strings.Format("pcsc.contextfail", "0x" + rv.ToString("X8")));
                    complete = false;
                    return result;
                }

                string[] names = ListReaderNames(ctx, log, out bool namesComplete);
                complete &= namesComplete;
                if (names.Length == 0) return result;

                var states = new SCARD_READERSTATE[names.Length];
                for (int i = 0; i < names.Length; i++)
                    states[i] = new SCARD_READERSTATE
                    {
                        szReader = names[i],
                        dwCurrentState = SCARD_STATE_UNAWARE,
                        rgbAtr = new byte[SCARD_ATR_LENGTH],
                    };

                // Тайм-аут 0: вернуться немедленно с текущим состоянием и ATR, ничего не ожидая.
                uint sc = SCardGetStatusChange(ctx, 0, states, (uint)states.Length);
                if (sc != SCARD_S_SUCCESS)
                {
                    // Состояния всё равно частично заполнены; но честнее сообщить о сбое, чем
                    // выдать неполную картину за полную.
                    log(Strings.Format("pcsc.statusfail", "0x" + sc.ToString("X8")));
                    complete = false;
                }

                foreach (var st in states)
                {
                    bool present = (st.dwEventState & SCARD_STATE_PRESENT) != 0;
                    result.Add(new PcscReader
                    {
                        Name = st.szReader,
                        CardPresent = present,
                        Atr = present ? Hex(st.rgbAtr, (int)st.cbAtr) : null,
                    });
                }
            }
            catch (DllNotFoundException e)
            {
                complete = false;
                log(Strings.Format("pcsc.contextfail", e.Message));
            }
            catch (Exception e)
            {
                complete = false;
                log(Strings.Format("pcsc.statusfail", e.Message));
            }
            finally
            {
                if (ctx != IntPtr.Zero) { try { SCardReleaseContext(ctx); } catch { } }
            }

            return result;
        }

        private static string[] ListReaderNames(IntPtr ctx, Action<string> log, out bool complete)
        {
            complete = true;
            uint len = 0;
            uint rv = SCardListReaders(ctx, null, null, ref len);
            if (rv != SCARD_S_SUCCESS || len == 0)
            {
                // Считывателей нет — норма; любая другая ошибка означает, что список не получен,
                // и пустота не доказана (замечание Codex на PR #83).
                complete = rv == SCARD_S_SUCCESS || IsNoReaders(rv);
                if (!complete) log(Strings.Format("pcsc.statusfail", "0x" + rv.ToString("X8")));
                return Array.Empty<string>();
            }

            var buf = new char[len];
            rv = SCardListReaders(ctx, null, buf, ref len);
            if (rv != SCARD_S_SUCCESS)
            {
                complete = IsNoReaders(rv);
                log(Strings.Format("pcsc.statusfail", "0x" + rv.ToString("X8")));
                return Array.Empty<string>();
            }

            return SplitMultiString(buf, (int)len);
        }

        /// <summary>
        /// «Считывателей нет» — обычное состояние машины, а не сбой опроса. Отдельно от прочих
        /// кодов: по ним пустой список означает «неизвестно», а не «носителей нет».
        /// </summary>
        internal static bool IsNoReaders(uint rv) => rv == SCARD_E_NO_READERS_AVAILABLE;

        /// <summary>Разобрать двойной-нуль-терминированный список строк (multi-string) winscard в массив имён.</summary>
        internal static string[] SplitMultiString(char[] buffer, int length)
        {
            var names = new List<string>();
            int start = 0;
            int limit = Math.Min(length, buffer?.Length ?? 0);
            for (int i = 0; i < limit; i++)
            {
                if (buffer[i] != '\0') continue;
                if (i > start) names.Add(new string(buffer, start, i - start));
                start = i + 1;
                // Двойной ноль — конец списка.
                if (i + 1 < limit && buffer[i + 1] == '\0') break;
            }
            return names.ToArray();
        }

        private static string Hex(byte[] b, int n)
        {
            if (b == null || n <= 0) return "";
            var sb = new StringBuilder(n * 3);
            for (int i = 0; i < n && i < b.Length; i++)
            {
                if (sb.Length > 0) sb.Append(' ');
                sb.Append(b[i].ToString("X2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Карты, присутствующие в PC/SC, которых нет среди перечисленных PKCS#11-токенов.
        /// Такой считыватель показывает вставленную карту, но ни одна установленная библиотека
        /// PKCS#11 не считает его токеном — типичный признак носителя, работающего только через
        /// минидрайвер (JaCarta IDProtect и подобные), либо чужой смарт-карты. Сопоставление —
        /// по имени считывателя (оно едино у PC/SC, PKCS#11 и CSP).
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static List<PcscReader> Uncovered(IEnumerable<PcscReader> readers,
                                                 IEnumerable<string> pkcs11Readers)
        {
            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in pkcs11Readers ?? Array.Empty<string>())
                if (!string.IsNullOrEmpty(r)) covered.Add(r.Trim());

            var result = new List<PcscReader>();
            foreach (var r in readers ?? Array.Empty<PcscReader>())
            {
                if (r == null || !r.CardPresent || string.IsNullOrEmpty(r.Name)) continue;
                if (covered.Contains(r.Name.Trim())) continue;
                result.Add(r);
            }
            return result;
        }

        /// <summary>
        /// Почему число устройств PKCS#11 не сходится с числом считывателей.
        ///
        /// Это разные величины, и раньше их печатали рядом без единого связывающего слова:
        /// PnP считает <b>считыватели</b>, а PKCS#11 показывает только те носители, которые
        /// показала хотя бы одна загруженная библиотека. Носитель, которого не показал никто
        /// (проверено 31.08.2026 на BIFIT ANGARA и BIFIT iBank2Key), физически стоит в
        /// считывателе, виден в PC/SC и, если его ATR знаком КриптоПро, работает через CSP —
        /// но в перечне PKCS#11 его нет вовсе, и разница выглядела как ошибка приложения.
        ///
        /// Формулировка намеренно говорит «не показала ни одна», а не «библиотеки нет»:
        /// установленный модуль может не загрузиться или не перечислить слоты, и тогда совет
        /// «поставьте драйвер» увёл бы в сторону от настоящей причины. Сама причина уже есть в
        /// журнале — <see cref="Pkcs11Token.Enumerate"/> пишет туда ошибку модуля (замечание
        /// Codex на PR #72).
        ///
        /// Возвращает готовые строки журнала: сводку и перечень непокрытых носителей. Пустой
        /// список — когда считывателей нет вообще.
        ///
        /// Чистая функция: покрыта тестами без обращения к железу.
        /// </summary>
        public static List<string> CoverageLines(IEnumerable<PcscReader> readers,
                                                 IEnumerable<string> pkcs11Readers)
        {
            var all = new List<PcscReader>();
            foreach (var r in readers ?? Array.Empty<PcscReader>())
                if (r != null && !string.IsNullOrEmpty(r.Name)) all.Add(r);

            var lines = new List<string>();
            if (all.Count == 0) return lines;

            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in pkcs11Readers ?? Array.Empty<string>())
                if (!string.IsNullOrEmpty(name)) covered.Add(name.Trim());

            int withCard = 0;
            int shown = 0;
            foreach (var r in all)
            {
                if (r.CardPresent) withCard++;
                if (covered.Contains(r.Name.Trim())) shown++;
            }
            lines.Add(Strings.Format("cli.pcsc.count", all.Count, withCard, shown));

            var uncovered = Uncovered(all, covered);
            if (uncovered.Count == 0) return lines;

            lines.Add(Strings.Get("cli.pcsc.uncovered"));
            foreach (var r in uncovered)
                lines.Add("  " + Strings.Format("cli.pcsc.line",
                    r.Name, Strings.Get(CarrierHintKey(r.Name, r.Atr)), r.Atr ?? "?"));
            return lines;
        }

        /// <summary>
        /// Ключ локализованной подсказки о вендоре по имени считывателя. Только для сообщения
        /// диагностики — не влияет на выбор пути снятия ключа. Имена вендоров в значениях — торговые
        /// марки, не переводятся; переводится лишь слово «неизвестный носитель».
        ///
        /// Чистая функция: покрыта тестами.
        /// </summary>
        public static string CarrierHintKey(string readerName)
        {
            string n = (readerName ?? string.Empty).ToLowerInvariant();
            if (n.Contains("jacarta") || n.Contains("aladdin")) return "carrier.jacarta";
            if (n.Contains("rutoken") || n.Contains("aktiv")) return "carrier.rutoken";
            if (n.Contains("esmart") || n.Contains("isbc")) return "carrier.esmart";
            if (n.Contains("etoken") || n.Contains("safenet")) return "carrier.etoken";
            // YubiKey 5 (PIV/FIDO) вообще не носитель КриптоПро: ГОСТ-апплета нет, ISO-файловой
            // системы нет (SELECT 3F00 → 6D 00), ATR не совпал ни с одной из 83 записей
            // KeyCarriers CSP. Имя всё равно называем — строка «неизвестный носитель» толкает
            // владельца искать несуществующий драйвер. См. docs/hardware/yubikey-5c-nano.md.
            if (n.Contains("yubikey") || n.Contains("yubico")) return "carrier.yubikey";
            // БИФИТ проверяется после ESMART: «ANGARA» носят обе линейки, и точное
            // свидетельство ESMART должно сработать первым.
            if (Pkcs11Token.HasBifitEvidence(n)) return "carrier.bifit";
            return "carrier.unknown";
        }

        /// <summary>
        /// То же, но с запасным признаком по ATR карты, когда имя считывателя ничего не говорит.
        /// Нужно для универсальных ридеров: их имя принадлежит самому ридеру, а не вставленной
        /// карте (тот же случай, что у ESMART Token ГОСТ в <c>Feitian SCR301</c>).
        ///
        /// Порядок жёсткий: сначала имя, и только на <c>carrier.unknown</c> смотрим ATR. Так у
        /// уже распознаваемых вендоров поведение не меняется ни в одном случае, а ATR лишь
        /// закрывает пробел. Обратный порядок был бы опаснее: имя ридера известного вендора —
        /// более сильное свидетельство, чем печатный хвост чужого ATR.
        ///
        /// Чистая функция: покрыта тестами.
        /// </summary>
        public static string CarrierHintKey(string readerName, string atrHex)
        {
            string byName = CarrierHintKey(readerName);
            if (byName != "carrier.unknown") return byName;
            // Historical bytes YubiKey 5 несут ASCII `YubiKey` (живой ATR
            // `3B FD 13 00 00 81 31 FE 15 80 73 C0 21 C0 57 59 75 62 69 4B 65 79 40`).
            if (AtrPrintable(atrHex).Contains("yubikey")) return "carrier.yubikey";
            return "carrier.unknown";
        }

        /// <summary>
        /// Печатные ASCII-байты ATR в нижнем регистре, непечатные выброшены. Из «3B FD … 59 75 62
        /// 69 4B 65 79 40» получается «yubikey» — по такому хвосту и опознаются семейства,
        /// которые пишут модель прямо в historical bytes.
        /// </summary>
        private static string AtrPrintable(string atrHex)
        {
            if (string.IsNullOrWhiteSpace(atrHex)) return string.Empty;
            // Разделители в дампах ATR бывают разные, а бывает, что их нет вовсе: «3B FD 13»,
            // «3B:FD:13» и «3BFD13» — одна и та же карта. Внутри проекта строка всегда приходит
            // от Hex() через пробел, но метод публичный, и молча не узнать носитель из-за формы
            // записи — худший исход, чем лишние три Replace.
            string compact = atrHex.Replace(" ", "").Replace("\t", "").Replace(":", "").Replace("-", "");
            // Непарный хвост означает, что это не ATR: догадок по обрубку не строим.
            if (compact.Length < 2 || compact.Length % 2 != 0) return string.Empty;
            var sb = new StringBuilder(compact.Length / 2);
            for (int i = 0; i < compact.Length; i += 2)
            {
                if (!byte.TryParse(compact.AsSpan(i, 2), NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture, out byte value)) return string.Empty;
                if (value >= 0x20 && value <= 0x7E) sb.Append(char.ToLowerInvariant((char)value));
            }
            return sb.ToString();
        }
    }
}
