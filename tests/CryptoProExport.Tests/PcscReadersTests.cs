using System;
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
        // Реальное имя считывателя проверенного 07.09.2026 YubiKey 5C Nano. Носителем
        // КриптоПро он не является, но названный вендор честнее «неизвестного носителя».
        [InlineData("Yubico YubiKey OTP+FIDO+CCID 0", "carrier.yubikey")]
        [InlineData("ACS ACR38U 0", "carrier.unknown")]
        [InlineData("", "carrier.unknown")]
        [InlineData(null, "carrier.unknown")]
        public void CarrierHintKey_ClassifiesByReaderName(string reader, string expected)
        {
            Assert.Equal(expected, PcscReaders.CarrierHintKey(reader));
        }

        [Theory]
        [InlineData("BIFIT ANGARA 0")]
        [InlineData("BIFIT iBank2Key 0")]
        [InlineData("MS_KEY K 0")]
        public void CarrierHintKey_NamesBifitCarriers(string reader)
        {
            // Оба носителя стоят в PC/SC, но своей библиотеки PKCS#11 в системе не имеют —
            // без имени вендора строка в журнале была бы «неизвестный носитель».
            Assert.Equal("carrier.bifit", PcscReaders.CarrierHintKey(reader));
        }

        [Fact]
        public void CarrierHintKey_EsmartAngaraStaysEsmart()
        {
            // «ANGARA» носят обе линейки: ESMART Token ANGARA и БИФИТ MS_KEY K «АНГАРА».
            // Точное свидетельство ESMART обязано сработать первым.
            Assert.Equal("carrier.esmart", PcscReaders.CarrierHintKey("ESMART Token ANGARA 0"));
        }

        // ---------- CoverageLines ----------

        [Fact]
        public void CoverageLines_ExplainsWhyPkcs11CountIsSmaller()
        {
            using var language = Strings.Scope("ru");
            var readers = new List<PcscReader>
            {
                new PcscReader { Name = "Aktiv Rutoken lite 0", CardPresent = true, Atr = "3B 8B" },
                new PcscReader { Name = "BIFIT ANGARA 0", CardPresent = true, Atr = "3B 9E" },
                new PcscReader { Name = "BIFIT iBank2Key 0", CardPresent = true, Atr = "3B 98" },
            };

            var lines = PcscReaders.CoverageLines(readers, new[] { "Aktiv Rutoken lite 0" });

            // Сводка не утверждает, что библиотеки нет: модуль бывает установлен и при этом
            // не грузится или не перечисляет слоты (замечание Codex на PR #72).
            Assert.Equal("считывателей 3, из них с носителем 3; носитель показала библиотека "
                         + "PKCS#11 у 1 — остальных не показала ни одна из установленных",
                         lines[0]);
            Assert.Contains(lines, l => l.Contains("BIFIT ANGARA 0", StringComparison.Ordinal));
            Assert.Contains(lines, l => l.Contains("BIFIT iBank2Key 0", StringComparison.Ordinal));
            Assert.DoesNotContain(lines, l => l.Contains("Rutoken lite", StringComparison.Ordinal));
        }

        [Fact]
        public void CoverageLines_SilentWithoutReaders()
        {
            Assert.Empty(PcscReaders.CoverageLines(null, null));
            Assert.Empty(PcscReaders.CoverageLines(new List<PcscReader>(), new[] { "any" }));
        }

        [Fact]
        public void CoverageLines_CountsOnlyTheSummaryWhenEverythingIsCovered()
        {
            using var language = Strings.Scope("en");
            var readers = new List<PcscReader>
            {
                new PcscReader { Name = "Aktiv Rutoken lite 0", CardPresent = true, Atr = "3B 8B" },
            };

            var lines = PcscReaders.CoverageLines(readers, new[] { "Aktiv Rutoken lite 0" });

            Assert.Single(lines);
            Assert.DoesNotContain(Strings.MissingMarkerStart, lines[0], StringComparison.Ordinal);
        }

        [Fact]
        public void CarrierHintKey_AllHintsHaveLocalizedValues()
        {
            // Каждый ключ подсказки должен существовать в таблице строк (иначе в выводе появится
            // маркер отсутствующего перевода). Проверяем на эталонном языке.
            foreach (var reader in new[] { "JaCarta", "Rutoken", "ESMART", "eToken", "BIFIT", "ACS" })
            {
                string key = PcscReaders.CarrierHintKey(reader);
                string value = Strings.Get(key);
                Assert.False(value.Contains(Strings.MissingMarkerStart, System.StringComparison.Ordinal),
                    $"нет перевода для {key}");
            }
        }
        /// <summary>
        /// «Считывателей нет» — обычное состояние машины, а не сбой опроса. Любой другой код
        /// winscard означает, что список не получен, и пустота не доказана: звать вставить
        /// носитель по такому опросу нельзя (замечание Codex на PR #83).
        /// </summary>
        [Theory]
        [InlineData(0x8010002Eu, true)]    // SCARD_E_NO_READERS_AVAILABLE
        [InlineData(0x8010001Du, false)]   // SCARD_E_NO_SERVICE
        [InlineData(0x80100017u, false)]   // SCARD_E_READER_UNAVAILABLE
        [InlineData(0x00000000u, false)]   // успех — отдельная ветка, «нет считывателей» не он
        public void NoReaders_IsTheOnlyNormalFailure(uint code, bool normal)
        {
            Assert.Equal(normal, PcscReaders.IsNoReaders(code));
        }

    }
}
