using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Строки интерфейса на 20 языках. Каждый язык — отдельный файл <c>i18n/&lt;код&gt;.txt</c>
    /// в формате <c>ключ = значение</c>, вшитый в сборку ресурсом (как guide.txt).
    /// Добавить язык = добавить файл: список языков строится по вшитым ресурсам.
    ///
    /// Выбор языка: явное значение (<c>--lang xx</c> или выбор в окне) → запомненный выбор
    /// (<see cref="Remember"/>) → <see cref="CultureInfo.CurrentUICulture"/> с подъёмом по
    /// родительским культурам (ru-RU → ru, zh-CN → zh-Hans) → английский.
    ///
    /// Отсутствующий ключ не молчит: <see cref="Get"/> возвращает заметный маркер
    /// <c>[!ключ!]</c>. Его ловят юнит-тесты и самопроверка формы (<c>--selftest</c>).
    /// </summary>
    public static class Strings
    {
        /// <summary>Язык, на который откатывается всё остальное.</summary>
        public const string Fallback = "en";

        /// <summary>Маркер отсутствующего ключа — он должен быть виден, а не съеден.</summary>
        public const string MissingMarkerStart = "[!";

        private const string ResourcePrefix = "CryptoProExport.i18n.";
        private const string ResourceSuffix = ".txt";

        private static readonly object Gate = new object();
        private static readonly Dictionary<string, ReadOnlyDictionary<string, string>> Loaded =
            new Dictionary<string, ReadOnlyDictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        private static string _current;

        /// <summary>Коды доступных языков, по алфавиту. Пусто — ресурсы не вшиты в сборку.</summary>
        public static IReadOnlyList<string> Available { get; } = Discover();

        /// <summary>Действующий язык интерфейса.</summary>
        public static string Current
        {
            get
            {
                lock (Gate) return _current ??= FromCulture(CultureInfo.CurrentUICulture) ?? Fallback;
            }
        }

        /// <summary>Название языка на нём самом — для списка выбора.</summary>
        public static string NativeName(string code) =>
            Table(code).TryGetValue("lang.name", out string name) ? name : code;

        /// <summary>Языки с письмом справа налево (ar, ur, fa): им нужен зеркальный интерфейс.</summary>
        public static bool IsRightToLeft(string code) =>
            Table(code).TryGetValue("lang.rtl", out string rtl) &&
            string.Equals(rtl.Trim(), "yes", StringComparison.OrdinalIgnoreCase);

        /// <summary>Письмо справа налево у действующего языка.</summary>
        public static bool CurrentIsRightToLeft => IsRightToLeft(Current);

        /// <summary>Строка по ключу. Нет ключа ни в языке, ни в английском — вернётся <c>[!ключ!]</c>.</summary>
        public static string Get(string key)
        {
            if (string.IsNullOrEmpty(key)) return MissingMarkerStart + "?!]";
            if (Table(Current).TryGetValue(key, out string value)) return value;
            if (Table(Fallback).TryGetValue(key, out value)) return value;
            return MissingMarkerStart + key + "!]";
        }

        /// <summary>Строка с подстановкой. Кривой шаблон в переводе не должен ронять программу.</summary>
        public static string Format(string key, params object[] args)
        {
            string pattern = Get(key);
            if (args == null || args.Length == 0) return pattern;
            try { return string.Format(CultureInfo.CurrentCulture, pattern, args); }
            catch (FormatException) { return pattern; }
        }

        /// <summary>Все пары «ключ — значение» языка. Пустой словарь — такого языка нет.</summary>
        public static IReadOnlyDictionary<string, string> Table(string code)
        {
            if (string.IsNullOrEmpty(code)) return Empty;
            lock (Gate)
            {
                if (Loaded.TryGetValue(code, out var table)) return table;
                table = new ReadOnlyDictionary<string, string>(Parse(Read(code)));
                Loaded[code] = table;
                return table;
            }
        }

        /// <summary>
        /// Подобрать вшитый язык под запрос: точное совпадение → родительские культуры
        /// (pt-BR → pt) → любой вариант того же языка (zh-TW → zh-Hans). <c>null</c> — не нашли.
        /// </summary>
        public static string Resolve(string requested)
        {
            if (string.IsNullOrWhiteSpace(requested)) return null;
            requested = requested.Trim();

            string exact = Available.FirstOrDefault(l => string.Equals(l, requested, StringComparison.OrdinalIgnoreCase));
            if (exact != null) return exact;

            CultureInfo culture;
            try { culture = CultureInfo.GetCultureInfo(requested); }
            catch (CultureNotFoundException) { return null; }
            return FromCulture(culture);
        }

        /// <summary>Установить язык. Неизвестный код игнорируется — остаётся прежний.</summary>
        public static bool Use(string code)
        {
            string resolved = Resolve(code);
            if (resolved == null) return false;
            lock (Gate) _current = resolved;
            ApplyToThreadCulture(resolved);
            return true;
        }

        /// <summary>
        /// Определить язык на старте: явный код (<c>--lang</c>) → запомненный выбор → системная
        /// культура → английский. Возвращает <c>false</c>, если явный код не опознан.
        /// </summary>
        public static bool Init(string explicitCode)
        {
            bool ok = string.IsNullOrWhiteSpace(explicitCode) || Use(explicitCode);
            if (!ok || string.IsNullOrWhiteSpace(explicitCode))
            {
                string saved = Saved;
                if (!string.IsNullOrWhiteSpace(saved)) Use(saved);
                else ApplyToThreadCulture(Current);
            }
            return ok;
        }

        /// <summary>Файл с запомненным выбором языка (рядом с журналами).</summary>
        public static string SettingsPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoProExport", "language.txt");

        /// <summary>Запомненный выбор языка или <c>null</c>.</summary>
        public static string Saved
        {
            get
            {
                try
                {
                    return File.Exists(SettingsPath) ? File.ReadAllText(SettingsPath, Encoding.UTF8).Trim() : null;
                }
                catch (IOException) { return null; }
                catch (UnauthorizedAccessException) { return null; }
            }
        }

        /// <summary>Запомнить выбор языка на следующие запуски. Ошибка записи не мешает работе.</summary>
        public static void Remember(string code)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath));
                File.WriteAllText(SettingsPath, code ?? "", Encoding.UTF8);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        /// <summary>Временно переключить язык (для тестов и для вывода на заданном языке).</summary>
        public static IDisposable Scope(string code)
        {
            string previous;
            lock (Gate) previous = _current;
            Use(code);
            return new Restore(previous);
        }

        // ---------- внутреннее ----------

        private static readonly ReadOnlyDictionary<string, string> Empty =
            new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal));

        private static IReadOnlyList<string> Discover()
        {
            var codes = typeof(Strings).Assembly.GetManifestResourceNames()
                .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal) &&
                            n.EndsWith(ResourceSuffix, StringComparison.Ordinal))
                .Select(n => n.Substring(ResourcePrefix.Length, n.Length - ResourcePrefix.Length - ResourceSuffix.Length))
                .Where(c => c.Length > 0)
                .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return new ReadOnlyCollection<string>(codes);
        }

        private static string FromCulture(CultureInfo culture)
        {
            for (var c = culture; c != null && c.Name.Length > 0; c = c.Parent)
            {
                string hit = Available.FirstOrDefault(l => string.Equals(l, c.Name, StringComparison.OrdinalIgnoreCase));
                if (hit != null) return hit;
                if (ReferenceEquals(c, c.Parent)) break;
            }

            // zh-TW → zh-Hant → zh: точного варианта нет, но упрощённый китайский ближе английского
            string two = culture?.TwoLetterISOLanguageName;
            if (string.IsNullOrEmpty(two)) return null;
            return Available.FirstOrDefault(l =>
                l.StartsWith(two + "-", StringComparison.OrdinalIgnoreCase));
        }

        private static string Read(string code)
        {
            string exact = Available.FirstOrDefault(l => string.Equals(l, code, StringComparison.OrdinalIgnoreCase));
            if (exact == null) return null;
            using var stream = typeof(Strings).Assembly.GetManifestResourceStream(ResourcePrefix + exact + ResourceSuffix);
            if (stream == null) return null;
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }

        /// <summary>
        /// Формат намеренно простой: строки <c>ключ = значение</c>, комментарии с <c>#</c>,
        /// перевод строки внутри значения — <c>\n</c>. Так файл читается и правится глазами.
        /// </summary>
        internal static Dictionary<string, string> Parse(string text)
        {
            var map = new Dictionary<string, string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(text)) return map;

            foreach (string raw in text.Replace("\r\n", "\n").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == '#') continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line.Substring(0, eq).Trim();
                if (key.Length == 0) continue;
                map[key] = Unescape(line.Substring(eq + 1).Trim());
            }
            return map;
        }

        private static string Unescape(string value)
        {
            if (value.IndexOf('\\') < 0) return value;
            var sb = new StringBuilder(value.Length);
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] != '\\' || i + 1 >= value.Length) { sb.Append(value[i]); continue; }
                switch (value[i + 1])
                {
                    case 'n': sb.Append('\n'); i++; break;
                    case 't': sb.Append('\t'); i++; break;
                    case '\\': sb.Append('\\'); i++; break;
                    default: sb.Append('\\'); break;   // незнакомая последовательность остаётся как есть
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Сообщения самого .NET тоже пробуем перевести. Сателлиты вшиты только русские
        /// (<c>SatelliteResourceLanguages</c>), для остальных языков .NET сам откатится
        /// на английский — это осознанный размен на 2,3 МБ в портативном exe.
        /// </summary>
        private static void ApplyToThreadCulture(string code)
        {
            try
            {
                var culture = CultureInfo.GetCultureInfo(code);
                CultureInfo.DefaultThreadCurrentUICulture = culture;
                CultureInfo.CurrentUICulture = culture;
            }
            catch (CultureNotFoundException) { }
        }

        private sealed class Restore : IDisposable
        {
            private readonly string _previous;
            public Restore(string previous) => _previous = previous;

            public void Dispose()
            {
                lock (Gate) _current = _previous;
                ApplyToThreadCulture(_previous ?? Fallback);
            }
        }
    }
}
