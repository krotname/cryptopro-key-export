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
        public void ForKind_MapsJaCartaGostToRecognisedButUnsupportedEntry()
        {
            // JaCarta-2 ГОСТ распознаётся (имя, PIN в справке), но прямого APDU-пути ещё нет,
            // поэтому запись помечена Supported=false и заводской PIN не подставляется автоматически.
            StandardPin pin = StandardPins.ForKind(RutokenKind.JaCartaGost);

            Assert.NotNull(pin);
            Assert.Equal("JaCarta-2 GOST", pin.Model);
            Assert.Equal("1234567890", pin.UserPin);
            Assert.Equal("0987654321", pin.AdminPin);
            Assert.False(pin.Supported);
            Assert.Null(StandardPins.AutoFillUserPinFor(RutokenKind.JaCartaGost));
        }

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
        public void SuggestFor_OffersTheFactoryPinOfASingleFactoryStateCarrier()
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenLite, PinDefault = true },
            };

            Assert.Equal("12345678", StandardPins.SuggestFor(tokens)?.UserPin);
        }

        /// <summary>
        /// Второй носитель делает подстановку небезопасной: подставленное значение уходит
        /// дальше как явный PIN и минует проверку в ResolvePin, а выбрана может оказаться
        /// строка того носителя, чей PIN уже сменён.
        /// </summary>
        [Fact]
        public void SuggestFor_StaysSilentWhenMoreThanOneCarrierIsConnected()
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenLite, PinDefault = true },
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenS, PinDefault = true },
            };

            Assert.Null(StandardPins.SuggestFor(tokens));
        }

        [Theory]
        [InlineData(false, false, false, false)]
        [InlineData(true, true, false, false)]
        [InlineData(true, false, true, false)]
        [InlineData(true, false, false, true)]
        public void SuggestFor_NeedsConfirmedFactoryStateAndACleanCounter(
            bool isDefault, bool countLow, bool finalTry, bool locked)
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo
                {
                    Kind = RutokenKind.RutokenLite,
                    PinDefault = isDefault,
                    PinCountLow = countLow,
                    PinFinalTry = finalTry,
                    PinLocked = locked,
                },
            };

            Assert.Null(StandardPins.SuggestFor(tokens));
        }

        [Theory]
        [InlineData(RutokenKind.JaCartaPro)]
        [InlineData(RutokenKind.Unknown)]
        public void SuggestFor_SkipsCarriersWhereAutofillIsNotAllowed(RutokenKind kind)
        {
            var tokens = new[] { new Pkcs11TokenInfo { Kind = kind, PinDefault = true } };

            Assert.Null(StandardPins.SuggestFor(tokens));
        }

        [Fact]
        public void SuggestFor_HandlesAnEmptyOrMissingList()
        {
            Assert.Null(StandardPins.SuggestFor(null));
            Assert.Null(StandardPins.SuggestFor(Array.Empty<Pkcs11TokenInfo>()));
        }

        [Fact]
        public void Registry_CoversTheModelsThatAreOnlyPlannedYet()
        {
            var planned = StandardPins.All.Where(p => !p.Supported).Select(p => p.Model).ToArray();

            Assert.Contains("JaCarta PKI", planned);
            Assert.Contains("JaCarta GOST", planned);
            Assert.Contains("JaCarta-2 GOST", planned);
            Assert.Contains("eToken GOST", planned);
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

        /// <summary>
        /// Примечания хранятся ключами, иначе `pins --lang en` печатал бы русскую прозу
        /// вперемешку с переведёнными заголовками.
        /// </summary>
        [Fact]
        public void Registry_NotesAreStoredAsTranslatableKeys()
        {
            foreach (StandardPin pin in StandardPins.All)
            {
                if (string.IsNullOrEmpty(pin.NoteKey)) continue;
                Assert.StartsWith("pins.note.", pin.NoteKey, StringComparison.Ordinal);
                foreach (string language in Strings.Available)
                    Assert.True(Strings.Table(language).ContainsKey(pin.NoteKey),
                                $"{language}: нет перевода {pin.NoteKey}");
            }
        }

        /// <summary>
        /// Имена моделей и вендоров — торговые марки латиницей: они попадают в вывод `pins`
        /// и в подсказку GUI на любом языке, поэтому русской прозы в них быть не должно.
        /// </summary>
        [Fact]
        public void Registry_NamesStayLanguageNeutral()
        {
            foreach (StandardPin pin in StandardPins.All)
            {
                Assert.DoesNotContain(pin.Model, c => c >= 'А' && c <= 'я');
                Assert.DoesNotContain(pin.Vendor, c => c >= 'А' && c <= 'я');
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
