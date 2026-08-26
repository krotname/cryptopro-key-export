using System;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Встроенное руководство. Если оно перестанет вшиваться или потеряет раздел,
    /// портативный exe останется без документации — это ловится здесь.
    ///
    /// Руководство переведено на два языка (ru + en), остальные 18 языков интерфейса
    /// откатываются на английский — см. AGENTS.md. Проверки одинаковы для обоих.
    /// </summary>
    public class GuideTests
    {
        private static string Ru => GuideText.For("ru");
        private static string En => GuideText.For("en");

        [Fact]
        public void Guide_IsTranslatedIntoRussianAndEnglish()
        {
            Assert.Equal(new[] { "en", "ru" }, GuideText.Available.ToArray());
        }

        [Theory]
        [InlineData("ru")]
        [InlineData("en")]
        public void Guide_IsEmbedded(string language)
        {
            string guide = GuideText.For(language);
            Assert.False(string.IsNullOrWhiteSpace(guide), $"руководство {language} не вшито в сборку");
            Assert.True(guide.Length > 3000, $"руководство {language} подозрительно короткое");
        }

        [Theory]
        [InlineData("ja", "en")]        // перевода нет — показываем английский
        [InlineData("zh-Hans", "en")]
        [InlineData("ru", "ru")]
        [InlineData("en", "en")]
        public void Guide_FallsBackToEnglish(string language, string expected)
        {
            Assert.Equal(expected, GuideText.Pick(language));
        }

        [Fact]
        public void Guide_FollowsTheInterfaceLanguage()
        {
            using (Strings.Scope("ru")) Assert.Equal(Ru, GuideText.Value);
            using (Strings.Scope("tr")) Assert.Equal(En, GuideText.Value);
        }

        [Theory]
        [InlineData("ЧТО НУЖНО НА МАШИНЕ")]
        [InlineData("КЛЮЧ ЕЩЁ НА ТОКЕНЕ")]
        [InlineData("КОНТЕЙНЕР УЖЕ СНЯТ В ПАПКУ")]
        [InlineData("КНОПКИ")]
        [InlineData("КОМАНДНАЯ СТРОКА")]
        [InlineData("ЕСЛИ ЧТО-ТО НЕ ПОЛУЧАЕТСЯ")]
        [InlineData("БЕЗОПАСНОСТЬ")]
        public void Guide_Ru_HasSection(string section)
        {
            Assert.Contains(section, Ru, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("WHAT YOU NEED ON THE MACHINE")]
        [InlineData("THE KEY IS STILL ON THE TOKEN")]
        [InlineData("THE CONTAINER IS ALREADY IN A FOLDER")]
        [InlineData("BUTTONS")]
        [InlineData("COMMAND LINE")]
        [InlineData("IF SOMETHING GOES WRONG")]
        [InlineData("SECURITY")]
        public void Guide_En_HasSection(string section)
        {
            Assert.Contains(section, En, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("deps")]
        [InlineData("list")]
        [InlineData("token")]
        [InlineData("extractcert")]
        [InlineData("checkexport")]
        [InlineData("export")]
        [InlineData("tokenexport")]
        [InlineData("tokenfull")]
        [InlineData("keyexport")]
        [InlineData("install")]
        [InlineData("installed")]
        [InlineData("uninstall")]
        [InlineData("topfx")]
        [InlineData("extractkey")]
        [InlineData("extractpfx")]
        [InlineData("liteexport")]
        [InlineData("full")]
        [InlineData("help")]
        [InlineData("--lang")]
        public void Guide_DocumentsCommand(string command)
        {
            Assert.Contains(command, Ru, StringComparison.Ordinal);
            Assert.Contains(command, En, StringComparison.Ordinal);
        }

        [Fact]
        public void Guide_Ru_DocumentsCheckexportExitCodes()
        {
            // У checkexport коды отличаются от общего контракта — на них опираются скрипты
            int codes = Ru.IndexOf("Коды возврата", StringComparison.Ordinal);
            Assert.True(codes > 0, "раздел про коды возврата пропал");
            string tail = Ru.Substring(codes);
            Assert.Contains("checkexport", tail, StringComparison.Ordinal);
            Assert.Contains("3 — хотя бы один", tail, StringComparison.Ordinal);
        }

        [Fact]
        public void Guide_En_DocumentsCheckexportExitCodes()
        {
            int codes = En.IndexOf("Exit codes", StringComparison.Ordinal);
            Assert.True(codes > 0, "раздел про коды возврата пропал в английском руководстве");
            string tail = En.Substring(codes);
            Assert.Contains("checkexport", tail, StringComparison.Ordinal);
            Assert.Contains("3 — at least one", tail, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("ru")]
        [InlineData("en")]
        public void Guide_MentionsLogsAndSecurity(string language)
        {
            string guide = GuideText.For(language);
            Assert.Contains(@"%LOCALAPPDATA%\CryptoProExport\logs", guide, StringComparison.Ordinal);
            Assert.Contains(language == "ru" ? "закрытый ключ" : "private key", guide, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("ru")]
        [InlineData("en")]
        public void Guide_FitsConsoleWidth(string language)
        {
            // Руководство печатается в консоль как есть — строки не должны разъезжаться
            var tooLong = GuideText.For(language).Replace("\r", "").Split('\n')
                                   .Where(l => l.Length > 78).ToArray();
            Assert.True(tooLong.Length == 0,
                $"{language}: строки длиннее 78 символов: " + string.Join(" | ", tooLong.Take(3)));
        }
    }
}
