using System;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Реестр заводских PIN. Тесты держат две вещи: значения производителей не «поплыли»
    /// при рефакторинге и автоподстановка не расширилась на модели, где промах дорог.
    /// </summary>
    public class StandardPinsTests
    {
        [Theory]
        [InlineData(RutokenKind.RutokenS, "12345678", "87654321")]
        [InlineData(RutokenKind.RutokenLite, "12345678", "87654321")]
        [InlineData(RutokenKind.RutokenEcp, "12345678", "87654321")]
        [InlineData(RutokenKind.JaCartaLt, "1234567890", null)]
        [InlineData(RutokenKind.JaCartaPro, "1234567890", null)]
        [InlineData(RutokenKind.Esmart, "12345678", "12345678")]
        public void ForKind_KeepsTheVendorPublishedValues(
            RutokenKind kind, string user, string admin)
        {
            StandardPin pin = StandardPins.ForKind(kind);

            Assert.NotNull(pin);
            Assert.Equal(user, pin.UserPin);
            Assert.Equal(admin, pin.AdminPin);
            Assert.True(pin.Supported);
        }

        [Theory]
        [InlineData(RutokenKind.Other)]
        [InlineData(RutokenKind.Unknown)]
        public void ForKind_StaysSilentForUnclassifiedCarriers(RutokenKind kind)
        {
            Assert.Null(StandardPins.ForKind(kind));
            Assert.Null(StandardPins.UserPinFor(kind));
            Assert.Null(StandardPins.AutoFillUserPinFor(kind));
        }

        /// <summary>
        /// У PRO-апплета PIN проверяется challenge-response, поэтому значение в реестре есть,
        /// а подставлять его за пользователя нельзя — это подтверждает и DirectTokenApduTests.
        /// </summary>
        [Fact]
        public void AutoFill_IsOffForJaCartaProButValueStaysAvailable()
        {
            Assert.Equal("1234567890", StandardPins.UserPinFor(RutokenKind.JaCartaPro));
            Assert.Null(StandardPins.AutoFillUserPinFor(RutokenKind.JaCartaPro));
        }

        [Theory]
        [InlineData(RutokenKind.RutokenS, "12345678")]
        [InlineData(RutokenKind.RutokenLite, "12345678")]
        [InlineData(RutokenKind.JaCartaLt, "1234567890")]
        [InlineData(RutokenKind.Esmart, "12345678")]
        public void AutoFill_IsOnForCarriersWithAPlainVerifyPin(RutokenKind kind, string expected)
        {
            Assert.Equal(expected, StandardPins.AutoFillUserPinFor(kind));
        }

        [Fact]
        public void Registry_CoversTheModelsThatAreOnlyPlannedYet()
        {
            var planned = StandardPins.All.Where(p => !p.Supported).Select(p => p.Model).ToArray();

            Assert.Contains("JaCarta PKI", planned);
            Assert.Contains("JaCarta ГОСТ", planned);
            Assert.Contains("JaCarta-2 ГОСТ", planned);
            Assert.Contains("eToken ГОСТ", planned);
        }

        [Fact]
        public void Registry_EntriesAreUsableAndTraceableToTheVendor()
        {
            Assert.NotEmpty(StandardPins.All);
            foreach (StandardPin pin in StandardPins.All)
            {
                Assert.False(string.IsNullOrWhiteSpace(pin.Model));
                Assert.False(string.IsNullOrWhiteSpace(pin.Vendor));
                Assert.StartsWith("https://", pin.Source, StringComparison.Ordinal);
                // Запись без единого значения бесполезна: хотя бы один PIN вендор публикует.
                Assert.True(!string.IsNullOrEmpty(pin.UserPin) || !string.IsNullOrEmpty(pin.AdminPin));
                foreach (string value in new[] { pin.UserPin, pin.AdminPin })
                {
                    if (string.IsNullOrEmpty(value)) continue;
                    Assert.InRange(value.Length, 4, 16);
                    Assert.All(value, c => Assert.InRange(c, '0', '9'));
                }
                // Подставлять нечего, если PIN Пользователя вендор не задаёт.
                if (pin.AutoFill) Assert.False(string.IsNullOrEmpty(pin.UserPin));
            }
        }

        [Fact]
        public void Registry_HasNoDuplicateModels()
        {
            var models = StandardPins.All.Select(p => p.Model).ToArray();

            Assert.Equal(models.Length, models.Distinct(StringComparer.Ordinal).Count());
        }
    }
}
