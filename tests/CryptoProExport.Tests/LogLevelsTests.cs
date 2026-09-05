using Xunit;

namespace CryptoProExport.Tests
{
    public sealed class LogLevelsTests
    {
        [Theory]
        [InlineData(LogLevel.Debug, LogLevel.Information, false)]
        [InlineData(LogLevel.Information, LogLevel.Information, true)]
        [InlineData(LogLevel.Warning, LogLevel.Information, true)]
        [InlineData(LogLevel.Error, LogLevel.Warning, true)]
        [InlineData(LogLevel.Information, LogLevel.Warning, false)]
        public void IsVisible_UsesMinimumSeverity(LogLevel entry, LogLevel minimum, bool expected)
        {
            Assert.Equal(expected, LogLevels.IsVisible(entry, minimum));
        }

        [Theory]
        [InlineData(LogLevel.Information, LogLevel.Debug)]
        [InlineData(LogLevel.Debug, LogLevel.Warning)]
        [InlineData(LogLevel.Warning, LogLevel.Error)]
        [InlineData(LogLevel.Error, LogLevel.Information)]
        public void Next_FollowsUserFacingCycle(LogLevel current, LogLevel expected)
        {
            Assert.Equal(expected, LogLevels.Next(current));
        }

        [Theory]
        [InlineData(LogLevel.Debug, "DEBUG", "log.level.debug")]
        [InlineData(LogLevel.Information, "INFO", "log.level.information")]
        [InlineData(LogLevel.Warning, "WARN", "log.level.warning")]
        [InlineData(LogLevel.Error, "ERROR", "log.level.error")]
        public void Metadata_IsStable(LogLevel level, string tag, string nameKey)
        {
            Assert.Equal(tag, LogLevels.Tag(level));
            Assert.Equal(nameKey, LogLevels.NameKey(level));
        }
    }
}
