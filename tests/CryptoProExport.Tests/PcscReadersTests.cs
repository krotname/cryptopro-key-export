using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Чистая логика диагностики PC/SC: разбор multi-string списка считывателей, отбор карт,
    /// не показанных PKCS#11, и подсказка о вендоре по имени считывателя. Обращения к железу
    /// (winscard) тут нет — оно проверяется e2e на живом носителе.
    /// </summary>
    public class PcscReadersTests
    {
        // ---------- SplitMultiString ----------

        [Fact]
        public void SplitMultiString_ParsesDoubleNullTerminatedList()
        {
            // Как отдаёт SCardListReadersW: строки через \0, двойной \0 в конце.
            var buf = "Aladdin R.D. JaCarta 0\0Aktiv Rutoken ECP 0\0\0".ToCharArray();
            var names = PcscReaders.SplitMultiString(buf, buf.Length);
            Assert.Equal(new[] { "Aladdin R.D. JaCarta 0", "Aktiv Rutoken ECP 0" }, names);
        }

        [Fact]
        public void SplitMultiString_EmptyOrNull_ReturnsEmpty()
        {
            Assert.Empty(PcscReaders.SplitMultiString(new char[0], 0));
            Assert.Empty(PcscReaders.SplitMultiString(null, 0));
            // Длина больше буфера не должна выходить за границы.
            Assert.Empty(PcscReaders.SplitMultiString("\0\0".ToCharArray(), 999));
        }

        [Fact]
        public void SplitMultiString_HonoursLength_NotBufferCapacity()
        {
            // Буфер выделяется с запасом, реальная длина меньше: хвост игнорируется.
            var buf = new char[64];
            var s = "R1\0R2\0\0";
            for (int i = 0; i < s.Length; i++) buf[i] = s[i];
            var names = PcscReaders.SplitMultiString(buf, s.Length);
            Assert.Equal(new[] { "R1", "R2" }, names);
        }

        // ---------- Uncovered ----------

        private static PcscReader Card(string name, bool present, string atr = "3B 00") =>
            new PcscReader { Name = name, CardPresent = present, Atr = present ? atr : null };

        [Fact]
        public void Uncovered_CardPresentWithoutPkcs11Token_IsReported()
        {
            var pcsc = new[]
            {
                Card("Aladdin R.D. JaCarta 0", true),      // карта есть, но PKCS#11 её не показал
                Card("Aktiv Rutoken ECP 0", true),          // карта есть и PKCS#11 её видит
                Card("Empty Reader 0", false),              // карты нет
            };
            var pkcs11 = new[] { "Aktiv Rutoken ECP 0" };

            var result = PcscReaders.Uncovered(pcsc, pkcs11);

            Assert.Single(result);
            Assert.Equal("Aladdin R.D. JaCarta 0", result[0].Name);
        }

        [Fact]
        public void Uncovered_MatchesReaderNameCaseInsensitivelyAndTrimmed()
        {
            var pcsc = new[] { Card("Aladdin R.D. JaCarta 0", true) };
            var pkcs11 = new[] { "  aladdin r.d. jacarta 0  " };
            Assert.Empty(PcscReaders.Uncovered(pcsc, pkcs11));
        }

        [Fact]
        public void Uncovered_IgnoresEmptyOrAbsentCards_AndNullInputs()
        {
            var pcsc = new[]
            {
                Card("No Card Reader", false),
                new PcscReader { Name = null, CardPresent = true, Atr = "3B" },
            };
            Assert.Empty(PcscReaders.Uncovered(pcsc, null));
            Assert.Empty(PcscReaders.Uncovered(null, null));
        }

        // ---------- CarrierHintKey ----------

        [Theory]
        [InlineData("Aladdin R.D. JaCarta 0", "carrier.jacarta")]
        [InlineData("ARDS JaCarta Reader", "carrier.jacarta")]
        [InlineData("Aktiv Rutoken ECP 0", "carrier.rutoken")]
        [InlineData("Aktiv Co. ruToken", "carrier.rutoken")]
        [InlineData("ESMART Token 0", "carrier.esmart")]
        [InlineData("ISBC reader", "carrier.esmart")]
        [InlineData("SafeNet eToken 5110", "carrier.etoken")]
        [InlineData("ACS ACR38U 0", "carrier.unknown")]
        [InlineData("", "carrier.unknown")]
        [InlineData(null, "carrier.unknown")]
        public void CarrierHintKey_ClassifiesByReaderName(string reader, string expected)
        {
            Assert.Equal(expected, PcscReaders.CarrierHintKey(reader));
        }

        [Fact]
        public void CarrierHintKey_AllHintsHaveLocalizedValues()
        {
            // Каждый ключ подсказки должен существовать в таблице строк (иначе в выводе появится
            // маркер отсутствующего перевода). Проверяем на эталонном языке.
            foreach (var reader in new[] { "JaCarta", "Rutoken", "ESMART", "eToken", "ACS" })
            {
                string key = PcscReaders.CarrierHintKey(reader);
                string value = Strings.Get(key);
                Assert.False(value.Contains(Strings.MissingMarkerStart, System.StringComparison.Ordinal),
                    $"нет перевода для {key}");
            }
        }
    }
}
