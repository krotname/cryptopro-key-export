using System;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Чистая логика поддержки Рутокен ЭЦП/Lite через PKCS#11: классификация модели,
    /// локализованные названия семейств и состояний PIN, поиск библиотеки.
    /// Обращения к железу тут нет — оно проверяется e2e на живом токене.
    /// </summary>
    public class Pkcs11TokenTests
    {
        [Theory]
        [InlineData("Rutoken ECP", RutokenKind.RutokenEcp)]      // реальная модель нашего токена
        [InlineData("Rutoken ECP 2.0", RutokenKind.RutokenEcp)]
        [InlineData("Rutoken lite", RutokenKind.RutokenLite)]
        [InlineData("Rutoken Lite", RutokenKind.RutokenLite)]
        [InlineData("Rutoken S", RutokenKind.RutokenS)]
        [InlineData("Rutoken", RutokenKind.RutokenS)]            // без уточнения — файловый профиль
        [InlineData("Рутокен ЭЦП", RutokenKind.RutokenEcp)]      // кириллическая метка тоже опознаётся
        [InlineData("JaCarta GOST", RutokenKind.Other)]
        [InlineData("eToken PRO", RutokenKind.Other)]
        [InlineData("", RutokenKind.Unknown)]
        [InlineData(null, RutokenKind.Unknown)]
        [InlineData("SomeCard 42", RutokenKind.Unknown)]
        public void Classify_MapsModelToFamily(string model, RutokenKind expected)
        {
            Assert.Equal(expected, Pkcs11Token.Classify(model));
        }

        [Fact]
        public void Classify_IsCaseInsensitive()
        {
            Assert.Equal(RutokenKind.RutokenEcp, Pkcs11Token.Classify("RUTOKEN ecp"));
            Assert.Equal(RutokenKind.RutokenLite, Pkcs11Token.Classify("rutoken LITE"));
        }

        [Theory]
        [InlineData(RutokenKind.RutokenS)]
        [InlineData(RutokenKind.RutokenLite)]
        [InlineData(RutokenKind.RutokenEcp)]
        [InlineData(RutokenKind.Other)]
        [InlineData(RutokenKind.Unknown)]
        public void KindName_IsLocalizedForEveryFamily(RutokenKind kind)
        {
            string name = Pkcs11Token.KindName(kind);
            Assert.False(string.IsNullOrWhiteSpace(name));
            Assert.DoesNotContain(Strings.MissingMarkerStart, name, StringComparison.Ordinal);
        }

        [Fact]
        public void PinState_PrefersMostSevereFlag()
        {
            // Заблокированный PIN важнее «последней попытки», та — важнее «счётчик на исходе».
            string locked = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinLocked = true, PinFinalTry = true });
            string final = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinFinalTry = true, PinCountLow = true });
            string low = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinCountLow = true });
            string def = Pkcs11Token.PinState(new Pkcs11TokenInfo { PinDefault = true });
            string ok = Pkcs11Token.PinState(new Pkcs11TokenInfo());

            Assert.Equal(Strings.Get("pin.state.locked"), locked);
            Assert.Equal(Strings.Get("pin.state.finaltry"), final);
            Assert.Equal(Strings.Get("pin.state.countlow"), low);
            Assert.Equal(Strings.Get("pin.state.default"), def);
            Assert.Equal(Strings.Get("pin.state.ok"), ok);
        }

        [Fact]
        public void LibraryCandidates_AreRootedAndNamed()
        {
            var candidates = Pkcs11Token.LibraryCandidates().ToArray();
            Assert.NotEmpty(candidates);
            Assert.All(candidates, c => Assert.True(System.IO.Path.IsPathRooted(c), c));
            Assert.Contains(candidates, c => c.EndsWith("rtPKCS11ECP.dll", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public void Enumerate_NeverThrows_WhenLibraryMissingOrNoToken()
        {
            // На машине без драйвера Рутокена / без токена перечисление обязано
            // тихо вернуть пустой список, а не свалить приложение.
            var ex = Record.Exception(() => Pkcs11Token.Enumerate(readContainers: true, log: _ => { }));
            Assert.Null(ex);
        }
    }
}
