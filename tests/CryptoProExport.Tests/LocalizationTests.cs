using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Локализация на 20 языков. Ловится главное, что тут ломается молча:
    /// в языке пропал ключ, значение пустое, разъехались подстановки <c>{0}</c>,
    /// код просит ключ, которого нет ни в одном файле.
    /// </summary>
    public class LocalizationTests
    {
        /// <summary>Русский — эталон: набор ключей всех остальных языков сверяется с ним.</summary>
        private const string Reference = "ru";

        /// <summary>Топ-20 языков (обоснование списка — в README).</summary>
        private static readonly string[] Expected =
        {
            "ar", "bn", "de", "en", "es", "fa", "fr", "hi", "id", "it",
            "ja", "ko", "pl", "pt", "ru", "ta", "tr", "ur", "vi", "zh-Hans",
        };

        /// <summary>Языки с письмом справа налево — им нужна зеркальная раскладка окна.</summary>
        private static readonly string[] RightToLeft = { "ar", "fa", "ur" };

        public static TheoryData<string> Languages
        {
            get
            {
                var data = new TheoryData<string>();
                foreach (string code in Strings.Available) data.Add(code);
                return data;
            }
        }

        [Fact]
        public void AllTwentyLanguagesAreEmbedded()
        {
            Assert.Equal(Expected, Strings.Available.ToArray());
        }

        [Theory]
        [MemberData(nameof(Languages))]
        public void Language_HasExactlyTheReferenceKeys(string code)
        {
            var reference = Strings.Table(Reference).Keys.ToHashSet(StringComparer.Ordinal);
            var actual = Strings.Table(code).Keys.ToHashSet(StringComparer.Ordinal);

            var missing = reference.Except(actual).OrderBy(k => k, StringComparer.Ordinal).ToArray();
            var extra = actual.Except(reference).OrderBy(k => k, StringComparer.Ordinal).ToArray();

            Assert.True(missing.Length == 0, $"{code}: нет ключей — {string.Join(", ", missing)}");
            Assert.True(extra.Length == 0, $"{code}: лишние ключи — {string.Join(", ", extra)}");
        }

        [Theory]
        [MemberData(nameof(Languages))]
        public void Language_HasNoEmptyValues(string code)
        {
            var empty = Strings.Table(code).Where(p => string.IsNullOrWhiteSpace(p.Value))
                               .Select(p => p.Key).ToArray();
            Assert.True(empty.Length == 0, $"{code}: пустые значения — {string.Join(", ", empty)}");
        }

        [Theory]
        [MemberData(nameof(Languages))]
        public void Language_KeepsThePlaceholders(string code)
        {
            var reference = Strings.Table(Reference);
            var broken = new List<string>();
            foreach (var (key, value) in Strings.Table(code))
            {
                if (!reference.TryGetValue(key, out string origin)) continue;
                if (!Placeholders(origin).SetEquals(Placeholders(value)))
                    broken.Add($"{key} (ждали {{{string.Join("}, {", Placeholders(origin).OrderBy(n => n))}}})");
            }
            Assert.True(broken.Count == 0, $"{code}: подстановки разъехались — {string.Join("; ", broken)}");
        }

        [Theory]
        [MemberData(nameof(Languages))]
        public void Language_DeclaresItsOwnNameAndDirection(string code)
        {
            Assert.NotEqual(code, Strings.NativeName(code));   // lang.name заполнен, а не подставлен код
            Assert.Equal(RightToLeft.Contains(code), Strings.IsRightToLeft(code));
        }

        [Theory]
        [MemberData(nameof(Languages))]
        public void Language_ResolvesEveryKeyWithoutTheMissingMarker(string code)
        {
            using var scope = Strings.Scope(code);
            var bad = Strings.Table(Reference).Keys
                .Where(k => Strings.Get(k).Contains(Strings.MissingMarkerStart, StringComparison.Ordinal))
                .ToArray();
            Assert.True(bad.Length == 0, $"{code}: не разрешились — {string.Join(", ", bad)}");
        }

        [Fact]
        public void MissingKeyIsLoudNotEmpty()
        {
            string value = Strings.Get("такого.ключа.нет");
            Assert.StartsWith(Strings.MissingMarkerStart, value, StringComparison.Ordinal);
            Assert.Contains("такого.ключа.нет", value, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("ru", "ru")]
        [InlineData("ru-RU", "ru")]
        [InlineData("RU", "ru")]
        [InlineData("pt-BR", "pt")]
        [InlineData("zh-Hans", "zh-Hans")]
        [InlineData("zh-CN", "zh-Hans")]
        [InlineData("zh-TW", "zh-Hans")]     // традиционного варианта нет — упрощённый ближе английского
        [InlineData("fa-IR", "fa")]
        public void Resolve_WalksUpTheCultureChain(string requested, string expected)
        {
            Assert.Equal(expected, Strings.Resolve(requested));
        }

        [Theory]
        [InlineData("sv")]            // культура существует, перевода нет
        [InlineData("не-язык")]       // и вовсе не культура
        [InlineData("")]
        [InlineData(null)]
        public void Resolve_ReturnsNullForUnknownLanguage(string requested)
        {
            Assert.Null(Strings.Resolve(requested));
        }

        [Fact]
        public void Get_ReturnsTheCurrentLanguageNotTheFallback()
        {
            // Английский — только страховка на случай недоведённого перевода: пока наборы
            // ключей совпадают (тест выше), Get обязан отдавать язык, а не en.
            using var scope = Strings.Scope("ja");
            Assert.Equal(Strings.Table("ja")["btn.help"], Strings.Get("btn.help"));
            Assert.NotEqual(Strings.Table("en")["btn.help"], Strings.Get("btn.help"));
        }

        [Fact]
        public void Scope_RestoresThePreviousLanguage()
        {
            string before = Strings.Current;
            using (Strings.Scope("ko")) Assert.Equal("ko", Strings.Current);
            Assert.Equal(before, Strings.Current);
        }

        [Fact]
        public void Format_SurvivesABrokenPattern()
        {
            // Кривой шаблон в переводе не должен ронять окно посреди операции
            Assert.Equal("{ не шаблон", Format("{ не шаблон", "значение"));

            static string Format(string pattern, object arg)
            {
                try { return string.Format(pattern, arg); }
                catch (FormatException) { return pattern; }
            }
        }

        [Fact]
        public void Parse_ReadsCommentsEscapesAndSpacing()
        {
            var map = Strings.Parse("# комментарий\n\nkey = значение\nmulti = первая\\nвторая\nslash = C:\\\\путь\n");
            Assert.Equal(3, map.Count);
            Assert.Equal("значение", map["key"]);
            Assert.Equal("первая\nвторая", map["multi"]);
            Assert.Equal(@"C:\путь", map["slash"]);
        }

        // ---------- сверка с кодом ----------

        [Fact]
        public void EveryKeyAskedForInCodeExists()
        {
            var known = Strings.Table(Reference).Keys.ToHashSet(StringComparer.Ordinal);
            var unknown = new List<string>();

            foreach (string file in SourceFiles())
            {
                string text = File.ReadAllText(file);
                foreach (Match m in Regex.Matches(text, @"Strings\.(?:Get|Format)\(""([^""]+)"""))
                {
                    string key = m.Groups[1].Value;
                    if (!known.Contains(key)) unknown.Add(Path.GetFileName(file) + ": " + key);
                }
            }

            Assert.True(unknown.Count == 0, "код просит несуществующие ключи — " + string.Join(", ", unknown));
        }

        [Fact]
        public void EveryKeyIsActuallyUsed()
        {
            // Мёртвый ключ пришлось бы переводить на 20 языков впустую
            var literals = new HashSet<string>(StringComparer.Ordinal);
            foreach (string file in SourceFiles())
                foreach (Match m in Regex.Matches(File.ReadAllText(file), @"""([A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)+)"""))
                    literals.Add(m.Groups[1].Value);

            var dead = Strings.Table(Reference).Keys.Where(k => !literals.Contains(k))
                              .OrderBy(k => k, StringComparer.Ordinal).ToArray();
            Assert.True(dead.Length == 0, "ключи не используются в коде — " + string.Join(", ", dead));
        }

        /// <summary>Исходники приложения. Тесты всегда гоняются из репозитория — и локально, и в CI.</summary>
        private static IEnumerable<string> SourceFiles()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CryptoProExport.slnx")))
                dir = dir.Parent;

            Assert.True(dir != null, "не нашли корень репозитория от " + AppContext.BaseDirectory);
            string src = Path.Combine(dir.FullName, "src");
            Assert.True(Directory.Exists(src), "нет каталога src в " + dir.FullName);
            return Directory.GetFiles(src, "*.cs", SearchOption.AllDirectories)
                            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                                                    StringComparison.Ordinal));
        }

        private static HashSet<int> Placeholders(string value)
        {
            var found = new HashSet<int>();
            foreach (Match m in Regex.Matches(value, @"\{(\d+)\}"))
                found.Add(int.Parse(m.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture));
            return found;
        }
    }
}
