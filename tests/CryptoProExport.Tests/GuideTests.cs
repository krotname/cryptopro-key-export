using System;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Встроенное руководство. Если оно перестанет вшиваться или потеряет раздел,
    /// портативный exe останется без документации — это ловится здесь.
    /// </summary>
    public class GuideTests
    {
        private static readonly string Guide = GuideText.Value;

        [Fact]
        public void Guide_IsEmbedded()
        {
            Assert.False(string.IsNullOrWhiteSpace(Guide), "руководство не вшито в сборку");
            Assert.True(Guide.Length > 3000, "руководство подозрительно короткое");
        }

        [Theory]
        [InlineData("ЧТО НУЖНО НА МАШИНЕ")]
        [InlineData("КЛЮЧ ЕЩЁ НА ТОКЕНЕ")]
        [InlineData("КОНТЕЙНЕР УЖЕ СНЯТ В ПАПКУ")]
        [InlineData("КНОПКИ")]
        [InlineData("КОМАНДНАЯ СТРОКА")]
        [InlineData("ЕСЛИ ЧТО-ТО НЕ ПОЛУЧАЕТСЯ")]
        [InlineData("БЕЗОПАСНОСТЬ")]
        public void Guide_HasSection(string section)
        {
            Assert.Contains(section, Guide, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("deps")]
        [InlineData("list")]
        [InlineData("extractcert")]
        [InlineData("checkexport")]
        [InlineData("keyexport")]
        [InlineData("install")]
        [InlineData("installed")]
        [InlineData("uninstall")]
        [InlineData("topfx")]
        [InlineData("full")]
        [InlineData("help")]
        public void Guide_DocumentsCommand(string command)
        {
            Assert.Contains(command, Guide, StringComparison.Ordinal);
        }

        [Fact]
        public void Guide_MentionsLogsAndSecurity()
        {
            Assert.Contains(@"%LOCALAPPDATA%\CryptoProExport\logs", Guide, StringComparison.Ordinal);
            Assert.Contains("закрытый ключ", Guide, StringComparison.Ordinal);
        }

        [Fact]
        public void Guide_FitsConsoleWidth()
        {
            // Руководство печатается в консоль как есть — строки не должны разъезжаться
            var tooLong = Guide.Replace("\r", "").Split('\n').Where(l => l.Length > 78).ToArray();
            Assert.True(tooLong.Length == 0,
                "строки длиннее 78 символов: " + string.Join(" | ", tooLong.Take(3)));
        }
    }
}
