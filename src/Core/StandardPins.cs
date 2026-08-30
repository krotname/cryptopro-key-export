using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace CryptoProExport
{
    /// <summary>
    /// Заводской (стандартный) PIN одной модели носителя — как его публикует производитель.
    /// Значения не секретны: они напечатаны в документации вендора и одинаковы для всей партии,
    /// пока владелец не сменил PIN.
    /// </summary>
    public sealed class StandardPin
    {
        /// <summary>Отображаемое имя модели или семейства.</summary>
        public string Model { get; set; }
        /// <summary>Производитель носителя.</summary>
        public string Vendor { get; set; }
        /// <summary>Заводской PIN Пользователя; <c>null</c> — вендор его не задаёт.</summary>
        public string UserPin { get; set; }
        /// <summary>Заводской PIN Администратора (или PUK); <c>null</c> — не задан.</summary>
        public string AdminPin { get; set; }
        /// <summary>Модель уже поддержана приложением (иначе — из плана, см. ROADMAP).</summary>
        public bool Supported { get; set; }
        /// <summary>
        /// Значение можно подставлять в поле PIN автоматически. Выключено там, где промах
        /// стоит дороже обычной попытки: у PRO-апплета PIN проверяется challenge-response,
        /// а часть моделей вообще не имеет заводского PIN Пользователя.
        /// </summary>
        public bool AutoFill { get; set; }
        /// <summary>Страница производителя, откуда взято значение.</summary>
        public string Source { get; set; }
        /// <summary>
        /// Ключ локализованного уточнения (апплет, ревизия, особенность PUK) или <c>null</c>.
        /// Здесь именно ключ, а не текст: вывод реестра идёт на языке интерфейса.
        /// </summary>
        public string NoteKey { get; set; }
    }

    /// <summary>
    /// Реестр заводских PIN-кодов носителей — один источник правды для CLI, GUI и APDU-путей.
    /// Значения сверены со страницами производителей (см. <see cref="StandardPin.Source"/>) и
    /// продублированы в <c>docs/standard-pins.md</c>.
    ///
    /// Зачем реестр в коде: до этого «12345678» и «1234567890» были рассыпаны по четырём файлам,
    /// и добавление модели требовало правки каждого. Подставлять заводской PIN разрешено только
    /// при чистом счётчике попыток — промах по PIN расходует попытку, а третий промах блокирует
    /// носитель. Решение о подстановке принимают вызывающие (<c>DirectTokenApdu.ResolvePin</c>,
    /// GUI), реестр отвечает только за значения.
    /// </summary>
    public static class StandardPins
    {
        private const string RutokenSource = "https://dev.rutoken.ru/pages/viewpage.action?pageId=72451342";
        private const string AladdinSource = "https://kbp.aladdin-rd.ru/index.php?View=entry&EntryID=85";
        private const string EsmartSource = "https://esmart.ru/tech-support/faq/";

        private static readonly StandardPin[] Registry =
        {
            new StandardPin
            {
                Model = "Рутокен S / DS", Vendor = "Актив",
                UserPin = "12345678", AdminPin = "87654321",
                Supported = true, AutoFill = true, Source = RutokenSource,
            },
            new StandardPin
            {
                Model = "Рутокен Lite", Vendor = "Актив",
                UserPin = "12345678", AdminPin = "87654321",
                Supported = true, AutoFill = true, Source = RutokenSource,
            },
            new StandardPin
            {
                Model = "Рутокен ЭЦП / 2.0 / 3.0", Vendor = "Актив",
                UserPin = "12345678", AdminPin = "87654321",
                Supported = true, AutoFill = true, Source = RutokenSource,
                NoteKey = "pins.note.diagnostic",
            },
            new StandardPin
            {
                Model = "JaCarta LT", Vendor = "Аладдин Р.Д.",
                UserPin = "1234567890", AdminPin = null,
                Supported = true, AutoFill = true, Source = AladdinSource,
                NoteKey = "pins.note.noadmin",
            },
            new StandardPin
            {
                Model = "eToken PRO (Java) / JaCarta PRO", Vendor = "Аладдин Р.Д.",
                UserPin = "1234567890", AdminPin = null,
                Supported = true, AutoFill = false, Source = AladdinSource,
                NoteKey = "pins.note.challenge",
            },
            new StandardPin
            {
                Model = "ESMART Token / ESMART Token ГОСТ", Vendor = "ESMART (ИСБК)",
                UserPin = "12345678", AdminPin = "12345678",
                Supported = true, AutoFill = true, Source = EsmartSource,
                NoteKey = "pins.note.sopin",
            },
            new StandardPin
            {
                Model = "JaCarta PKI", Vendor = "Аладдин Р.Д.",
                UserPin = "11111111", AdminPin = "00000000",
                Supported = false, Source = AladdinSource,
            },
            new StandardPin
            {
                Model = "JaCarta ГОСТ", Vendor = "Аладдин Р.Д.",
                UserPin = null, AdminPin = "1234567890",
                Supported = false, Source = AladdinSource,
                NoteKey = "pins.note.nouser",
            },
            new StandardPin
            {
                Model = "JaCarta-2 ГОСТ", Vendor = "Аладдин Р.Д.",
                UserPin = "1234567890", AdminPin = "0987654321",
                Supported = false, Source = AladdinSource,
                NoteKey = "pins.note.puk",
            },
            new StandardPin
            {
                Model = "JaCarta-2 SE (JC-267), ГОСТ-апплет", Vendor = "Аладдин Р.Д.",
                UserPin = "0987654321", AdminPin = null,
                Supported = false, Source = AladdinSource,
                NoteKey = "pins.note.applets",
            },
            new StandardPin
            {
                Model = "eToken ГОСТ", Vendor = "Аладдин Р.Д.",
                UserPin = null, AdminPin = "1234567890",
                Supported = false, Source = AladdinSource,
                NoteKey = "pins.note.nouser",
            },
        };

        /// <summary>Весь реестр: поддержанные модели идут первыми, дальше — запланированные.</summary>
        public static IReadOnlyList<StandardPin> All { get; } =
            new ReadOnlyCollection<StandardPin>(Registry);

        /// <summary>
        /// Запись реестра для распознанной приложением модели. Комбинированные апплеты
        /// (PKI/ГОСТ, SE) сюда не попадают: их классификация отдельного вида не имеет.
        /// </summary>
        public static StandardPin ForKind(RutokenKind kind)
        {
            switch (kind)
            {
                case RutokenKind.RutokenS: return Find("Рутокен S / DS");
                case RutokenKind.RutokenLite: return Find("Рутокен Lite");
                case RutokenKind.RutokenEcp: return Find("Рутокен ЭЦП / 2.0 / 3.0");
                case RutokenKind.JaCartaLt: return Find("JaCarta LT");
                case RutokenKind.JaCartaPro: return Find("eToken PRO (Java) / JaCarta PRO");
                case RutokenKind.Esmart: return Find("ESMART Token / ESMART Token ГОСТ");
                default: return null;
            }
        }

        /// <summary>
        /// Справочный заводской PIN Пользователя модели или <c>null</c>, если вендор его не
        /// задаёт либо модель не опознана. Для подстановки нужен <see cref="AutoFillUserPinFor"/>.
        /// </summary>
        public static string UserPinFor(RutokenKind kind)
        {
            StandardPin pin = ForKind(kind);
            return pin == null ? null : pin.UserPin;
        }

        /// <summary>
        /// PIN, который допустимо подставить за пользователя, или <c>null</c>. Счётчик попыток
        /// проверяет вызывающий: реестр не знает состояния конкретного носителя.
        /// </summary>
        public static string AutoFillUserPinFor(RutokenKind kind)
        {
            StandardPin pin = ForKind(kind);
            return pin != null && pin.AutoFill ? pin.UserPin : null;
        }

        /// <summary>
        /// Что можно подставить в поле PIN для текущего набора подключённых носителей, или
        /// <c>null</c>. Правило намеренно узкое: носитель должен быть ровно один, драйвер
        /// должен подтверждать заводское состояние PIN при чистом счётчике попыток, а модель —
        /// допускать подстановку.
        ///
        /// Одного «все дают одинаковое значение» мало: подставленный текст уходит дальше как
        /// явный PIN и минует проверку в <c>DirectTokenApdu.ResolvePin</c>, поэтому при двух и
        /// более носителях выбранной может оказаться строка того из них, чей PIN уже сменён, —
        /// и попытка сгорит на заведомо неверном значении.
        /// </summary>
        public static StandardPin SuggestFor(IEnumerable<Pkcs11TokenInfo> tokens)
        {
            if (tokens == null) return null;
            Pkcs11TokenInfo single = null;
            foreach (Pkcs11TokenInfo token in tokens)
            {
                if (token == null) continue;
                if (single != null) return null;
                single = token;
            }
            if (single == null) return null;
            if (!single.PinDefault || single.PinCountLow || single.PinFinalTry || single.PinLocked)
                return null;
            StandardPin pin = ForKind(single.Kind);
            return pin != null && pin.AutoFill && !string.IsNullOrEmpty(pin.UserPin) ? pin : null;
        }

        private static StandardPin Find(string model)
        {
            foreach (StandardPin pin in Registry)
                if (string.Equals(pin.Model, model, StringComparison.Ordinal))
                    return pin;
            throw new InvalidOperationException(model);
        }
    }
}
