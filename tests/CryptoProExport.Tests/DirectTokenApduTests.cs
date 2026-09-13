using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    public sealed class DirectTokenApduTests
    {
        [Theory]
        [InlineData(RutokenKind.RutokenS, "12345678")]
        [InlineData(RutokenKind.RutokenLite, "12345678")]
        [InlineData(RutokenKind.JaCartaLt, "1234567890")]
        [InlineData(RutokenKind.Esmart, "12345678")]
        public void ResolvePin_UsesFamilySpecificFactoryPinOnlyWhenDriverConfirmsIt(
            RutokenKind kind, string expected)
        {
            var token = new Pkcs11TokenInfo { Kind = kind, PinDefault = true };

            Assert.Equal(expected, DirectTokenApdu.ResolvePin(token, null));
        }

        [Fact]
        public void ResolvePin_ExplicitValueWinsEvenWhenCounterFlagsAreUnsafe()
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaLt,
                PinLocked = true,
                PinFinalTry = true,
            };

            Assert.Equal("entered", DirectTokenApdu.ResolvePin(token, "entered"));
        }

        [Theory]
        [InlineData(false, false, false)]
        [InlineData(true, true, false)]
        [InlineData(true, false, true)]
        public void ResolvePin_DoesNotGuessWithoutCleanDefaultEvidence(
            bool isDefault, bool countLow, bool locked)
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaLt,
                PinDefault = isDefault,
                PinCountLow = countLow,
                PinLocked = locked,
            };

            Assert.Throws<LiteApduException>(() => DirectTokenApdu.ResolvePin(token, null));
        }

        [Fact]
        public void ResolvePin_NeverGuessesAFactoryCredentialForJaCartaPro()
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaPro,
                PinDefault = true,
            };

            Assert.Throws<LiteApduException>(() => DirectTokenApdu.ResolvePin(token, null));
            Assert.Equal("entered", DirectTokenApdu.ResolvePin(token, "entered"));
        }

        [Fact]
        public void ExplicitPin_IsRejectedBeforeItCanReachTwoReaders()
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenS, Reader = "Reader S" },
                new Pkcs11TokenInfo { Kind = RutokenKind.JaCartaLt, Reader = "Reader LT" },
            };

            Assert.Throws<LiteApduException>(() =>
                DirectTokenApdu.EnsureSingleReaderForExplicitPin(tokens, "entered"));
            DirectTokenApdu.EnsureSingleReaderForExplicitPin(tokens, null);
        }

        [Fact]
        public void JaCartaTable_ParsesAndGroupsOneCompleteContainer()
        {
            byte[] table =
            {
                0x00, 0x00, 0x3F, 0x3F, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x03, 0xF6, 0x00, 0x01, 0x28,
                0x00, 0x05, 0x03, 0xF3, 0x00, 0x10, 0x00,
                0x00, 0x06, 0x03, 0xF2, 0x01, 0x00, 0x50,
                0x00, 0x07, 0x03, 0xF1, 0x01, 0x00, 0x58,
                0x00, 0x08, 0x03, 0xF5, 0x01, 0x00, 0x50,
                0x00, 0x09, 0x03, 0xF4, 0x01, 0x00, 0x58,
            };

            var entries = JaCartaLtApdu.ParseObjectTable(table);
            var group = Assert.Single(JaCartaLtApdu.GroupContainers(entries));

            Assert.Equal(0x04, group.ByCode[0xF6].Index);
            Assert.Equal(new byte[] { 0x01, 0x00, 0x50 }, group.ByCode[0xF2].Metadata);
            Assert.Equal(6, group.ByCode.Count);
        }

        [Fact]
        public void JaCartaTable_GroupsTwoContainersWithDifferentTypeBytes()
        {
            // Реальная раскладка носителя с двумя контейнерами (снята с ARDS ZAO JaCarta LT):
            // у каждого контейнера свой общий Type (0x03 и 0x0E), Code F1..F6 задаёт файл.
            // Регрессия: раньше тип был захардкожен 0x03 и второй контейнер терялся целиком.
            byte[] table =
            {
                0x00, 0x00, 0x3F, 0x3F, 0x00, 0x00, 0x00,
                0x00, 0x04, 0x03, 0xF6, 0x00, 0x01, 0x28,
                0x00, 0x05, 0x03, 0xF3, 0x00, 0x10, 0x00,
                0x00, 0x06, 0x03, 0xF2, 0x01, 0x00, 0x50,
                0x00, 0x07, 0x03, 0xF1, 0x01, 0x00, 0x58,
                0x00, 0x08, 0x03, 0xF5, 0x01, 0x00, 0x50,
                0x00, 0x09, 0x03, 0xF4, 0x01, 0x00, 0x58,
                0x00, 0x0A, 0x44, 0x44, 0x00, 0x00, 0x00,
                0x00, 0x0F, 0x0E, 0xF6, 0x00, 0x01, 0x28,
                0x00, 0x10, 0x0E, 0xF3, 0x00, 0x10, 0x00,
                0x00, 0x11, 0x0E, 0xF2, 0x01, 0x00, 0x50,
                0x00, 0x12, 0x0E, 0xF1, 0x01, 0x00, 0x58,
                0x00, 0x13, 0x0E, 0xF5, 0x01, 0x00, 0x50,
                0x00, 0x14, 0x0E, 0xF4, 0x01, 0x00, 0x58,
            };

            var entries = JaCartaLtApdu.ParseObjectTable(table);
            var groups = JaCartaLtApdu.GroupContainers(entries);

            Assert.Equal(2, groups.Count);
            Assert.Equal(0x04, groups[0].ByCode[0xF6].Index);
            Assert.Equal(6, groups[0].ByCode.Count);
            Assert.Equal(0x0F, groups[1].ByCode[0xF6].Index);
            Assert.Equal(6, groups[1].ByCode.Count);
            // Файлы второго контейнера не должны утекать в первый и наоборот.
            Assert.Equal(0x11, groups[1].ByCode[0xF2].Index);
            Assert.Equal(0x06, groups[0].ByCode[0xF2].Index);
        }

        [Fact]
        public void JaCartaTable_DropsIncompletePairsAndRejectsMalformedPages()
        {
            var entries = new[]
            {
                new JaCartaLtApdu.ObjectEntry(4, 3, 0xF6, new byte[3]),
                new JaCartaLtApdu.ObjectEntry(5, 3, 0xF3, new byte[3]),
                new JaCartaLtApdu.ObjectEntry(6, 3, 0xF2, new byte[3]),
            };

            Assert.Empty(JaCartaLtApdu.GroupContainers(entries));
            Assert.ThrowsAny<Exception>(() => JaCartaLtApdu.ParseObjectTable(new byte[8]));
        }

        [Theory]
        [InlineData(new byte[] { 0x30, 0x0C, 0x16, 0x0A }, 14)]
        [InlineData(new byte[] { 0x30, 0x81, 0xC4, 0x30 }, 199)]
        [InlineData(new byte[] { 0x30, 0x82, 0x01, 0x00 }, 260)]
        public void JaCartaDerLength_UsesCanonicalShortAndLongLengths(byte[] header, int expected)
        {
            Assert.Equal(expected, JaCartaLtApdu.DerLength(header));
        }

        [Theory]
        [InlineData(new byte[] { 0x30, 0x0D }, 15)]
        [InlineData(new byte[] { 0x30, 0x81, 0xC4 }, 199)]
        [InlineData(new byte[] { 0x30, 0x82, 0x01, 0x00 }, 260)]
        public void JaCartaProDerLength_UsesTheObservedDerEnvelope(byte[] header, int expected)
        {
            Assert.Equal(expected, JaCartaProApdu.DerLength(header));
        }

        [Fact]
        public void JaCartaProEmptyPublicSlot_RequiresOnlyNonEmptyAllZeroPayload()
        {
            Assert.True(JaCartaProApdu.IsEmptySlot(new byte[256]));
            Assert.False(JaCartaProApdu.IsEmptySlot(Array.Empty<byte>()));
            Assert.False(JaCartaProApdu.IsEmptySlot(null));
            Assert.False(JaCartaProApdu.IsEmptySlot(new byte[] { 0, 0, 1, 0 }));
        }

        [Fact]
        public void JaCartaProAuthentication_MatchesIndependentPublicVector()
        {
            byte[] salt = Enumerable.Range(0, 20).Select(value => (byte)value).ToArray();
            byte[] key = JaCartaProApdu.DeriveKey("public-test", salt);
            byte[] cryptogram = JaCartaProApdu.EncryptChallenge(
                key, Convert.FromHexString("0011223344556677"));

            Assert.Equal("914E419E89810EDEA2F6D8C9E68507F53FEA14B0520FDA70",
                Convert.ToHexString(key));
            Assert.Equal("E53775610CAF052C", Convert.ToHexString(cryptogram));
        }

        [Fact]
        public void JaCartaProFailureCleanup_ZeroesEveryCollectedBlob()
        {
            byte[] primary = { 1, 2, 3 };
            byte[] mask = { 4, 5, 6 };
            var blobs = new Dictionary<string, byte[]>
            {
                ["primary.key"] = primary,
                ["masks.key"] = mask,
            };

            JaCartaProApdu.ZeroBlobs(blobs);

            Assert.Empty(blobs);
            Assert.All(primary, value => Assert.Equal(0, value));
            Assert.All(mask, value => Assert.Equal(0, value));
        }

        [Fact]
        public void JaCartaProSelection_RequiresOneExactTechnicalOutputName()
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaPro,
                Reader = "Aladdin Token JC 0",
            };
            var containers = new[]
            {
                DirectRef(token, 1, "synthetic-one"),
                DirectRef(token, 7, "personal-looking-name"),
            };

            DirectTokenContainerRef selected = Assert.Single(
                DirectTokenApdu.SelectContainers(token, containers, "jacartapro_01"));

            Assert.Equal(1, selected.Index);
            Assert.Equal("jacartapro_01", selected.OutputName);
            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, null));
            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, "synthetic-one"));
            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, "jacartapro_0"));
            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, "jacartapro_07-extra"));
        }

        [Fact]
        public void ExistingDirectBackends_KeepBatchSelectionWhenOptionIsAbsent()
        {
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.RutokenLite,
                Reader = "Aktiv Rutoken lite 0",
            };
            var containers = new[]
            {
                DirectRef(token, 1, "first"),
                DirectRef(token, 2, "second"),
            };

            Assert.Equal(2, DirectTokenApdu.SelectContainers(token, containers, null).Count);
            Assert.Equal("lite_02", Assert.Single(
                DirectTokenApdu.SelectContainers(token, containers, "lite_02")).OutputName);
        }

        [Fact]
        public void NonProBackends_AlsoSelectByVisibleContainerName()
        {
            // UX-фикс: у не-PRO семейств --container принимает и видимое имя контейнера, а не
            // только технический OutputName. Совпадение по имени работает лишь когда оно
            // однозначно и по OutputName ничего не нашлось.
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.RutokenLite,
                Reader = "Aktiv Rutoken lite 0",
            };
            var containers = new[]
            {
                DirectRef(token, 1, "Иванов И.И."),
                DirectRef(token, 2, "second"),
            };

            // Видимое имя приводит к нужной строке.
            Assert.Equal("lite_01", Assert.Single(
                DirectTokenApdu.SelectContainers(token, containers, "Иванов И.И.")).OutputName);
            // Технический OutputName по-прежнему работает.
            Assert.Equal("lite_02", Assert.Single(
                DirectTokenApdu.SelectContainers(token, containers, "second")).OutputName);
            // Неизвестное имя — по-прежнему ошибка.
            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, "нет такого"));
        }

        [Fact]
        public void JaCartaProSelection_NeverMatchesByVisibleName()
        {
            // Для eToken PRO/PRO имя из name.key намеренно не участвует в выборе: защищённые
            // файлы читаются только у явно выбранного технического индекса.
            var token = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.JaCartaPro,
                Reader = "Aladdin Token JC 0",
            };
            var containers = new[]
            {
                DirectRef(token, 1, "synthetic-one"),
                DirectRef(token, 7, "personal-looking-name"),
            };

            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.SelectContainers(token, containers, "synthetic-one"));
        }

        [Fact]
        public void GlobalBatch_RejectsJaCartaProBeforeAnyContainerCanBeRead()
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenLite, Reader = "Lite" },
                new Pkcs11TokenInfo { Kind = RutokenKind.JaCartaPro, Reader = "PRO" },
            };

            Assert.Throws<ArgumentException>(() =>
                DirectTokenApdu.EnsureBatchSelectionSafe(tokens));
        }

        [Fact]
        public void GlobalBatch_RemainsAvailableForEarlierPassiveBackends()
        {
            var tokens = new[]
            {
                new Pkcs11TokenInfo { Kind = RutokenKind.RutokenS, Reader = "S" },
                new Pkcs11TokenInfo { Kind = RutokenKind.JaCartaLt, Reader = "LT" },
                new Pkcs11TokenInfo { Kind = RutokenKind.Esmart, Reader = "ESMART" },
            };

            DirectTokenApdu.EnsureBatchSelectionSafe(tokens);
        }

        [Fact]
        public void PcscAtrMatch_RequiresExactConnectedHandleAtr()
        {
            byte[] exact = Convert.FromHexString(JaCartaProApdu.ExactAtr.Replace(" ", ""));

            Assert.True(PcscApduSession.AtrMatches(
                JaCartaProApdu.ExactAtr.ToLowerInvariant(), exact, exact.Length));
            exact[^1] ^= 0x01;
            Assert.False(PcscApduSession.AtrMatches(
                JaCartaProApdu.ExactAtr, exact, exact.Length));
            Assert.False(PcscApduSession.AtrMatches(
                JaCartaProApdu.ExactAtr, exact, exact.Length + 1));
        }

        [Fact]
        public void RutokenSFcp_UsesLittleEndianSizeAndFindsNestedTags()
        {
            byte[] fcp = { 0x62, 0x08, 0x82, 0x01, 0x01, 0x80, 0x02, 0x2C, 0x01, 0x00 };

            Assert.Equal(300, RutokenSApdu.FcpSize(fcp));
            Assert.Equal(new byte[] { 0x2C, 0x01 }, RutokenSApdu.FindTag(fcp, 0x80));
        }

        [Fact]
        public void EsmartFcp_UsesBigEndianSizeInsideFciTemplate()
        {
            byte[] fcp = { 0x6F, 0x08, 0x83, 0x02, 0xF1, 0x06, 0x80, 0x02, 0x01, 0x00 };

            Assert.Equal(256, EsmartApdu.FcpSize(fcp));
            Assert.Equal(new byte[] { 0x01, 0x00 }, EsmartApdu.FindTag(fcp, 0x80));
        }

        [Fact]
        public void EsmartFileIds_FollowObservedNineSlotLayout()
        {
            Assert.Equal(0xF106, EsmartApdu.FileId(1, 0x06));
            Assert.Equal(0xF103, EsmartApdu.FileId(1, 0x03));
            Assert.Equal(0xF112, EsmartApdu.FileId(1, 0x12));
            Assert.Equal(0xF906, EsmartApdu.FileId(9, 0x06));
            Assert.Throws<ArgumentOutOfRangeException>(() => EsmartApdu.FileId(0, 0x06));
            Assert.Throws<ArgumentOutOfRangeException>(() => EsmartApdu.FileId(10, 0x06));
        }

        [Fact]
        public void EsmartPayload_StripsObservedMarkerAndFixedFilePadding()
        {
            byte[] raw = { 0x01, 0x30, 0x03, 0x16, 0x01, 0x41, 0x00, 0x00, 0x00 };

            Assert.Equal(new byte[] { 0x30, 0x03, 0x16, 0x01, 0x41 },
                EsmartApdu.NormalizePayload(raw));
        }

        [Theory]
        [InlineData(RutokenKind.RutokenS, true)]
        [InlineData(RutokenKind.RutokenLite, true)]
        [InlineData(RutokenKind.JaCartaLt, true)]
        [InlineData(RutokenKind.JaCartaPro, true)]
        [InlineData(RutokenKind.Esmart, true)]
        [InlineData(RutokenKind.Bifit, true)]
        [InlineData(RutokenKind.RutokenEcp, false)]
        // JaCartaGost — доказанно АКТИВНЫЙ носитель (подпись на чипе, primary.key не читается;
        // реверс 05.09.2026, docs/hardware/jacarta-2-gost.md). Как и RutokenEcp, остаётся вне
        // Supports НЕ из-за незавершённого реверса, а потому что ключ из чипа не выходит.
        [InlineData(RutokenKind.JaCartaGost, false)]
        [InlineData(RutokenKind.Other, false)]
        public void Supports_ListsOnlyProvenPassiveBackends(RutokenKind kind, bool expected)
        {
            Assert.Equal(expected, DirectTokenApdu.Supports(kind));
        }

        private static DirectTokenContainerRef DirectRef(Pkcs11TokenInfo token, int index,
                                                         string name)
            => new DirectTokenContainerRef
            {
                Kind = token.Kind,
                Reader = token.Reader,
                Name = name,
                OutputName = token.Kind == RutokenKind.JaCartaPro
                    ? $"jacartapro_{index:X2}" : $"lite_{index:X2}",
                Index = index,
            };

        [Theory]
        [InlineData("Feitian SCR301 0", true)]
        [InlineData("Feitian SCR301 12", true)]
        [InlineData("Feitian SCR301", false)]        // нет индекса
        [InlineData("Feitian SCR301 0A", false)]     // нечисловой индекс
        [InlineData("ISBC ESMART Token 0", false)]   // эксклюзивное имя — не универсальный ридер
        [InlineData("", false)]
        public void EsmartGostReader_IsOnlyTheIndexedUniversalCcidName(string reader, bool expected)
        {
            Assert.Equal(expected, EsmartApdu.IsGostReader(reader));
        }

        [Fact]
        public void EsmartGostExpectedAtr_PinsUniversalReaderButNotExclusiveNames()
        {
            // За универсальным Feitian SCR301 может стоять любая карта — сессия открывается
            // только при совпадении ATR. У эксклюзивных ESMART-имён модель задаёт сам ридер.
            Assert.Equal(EsmartApdu.GostExactAtr, EsmartApdu.ExpectedAtr("Feitian SCR301 0"));
            Assert.Null(EsmartApdu.ExpectedAtr("ISBC ESMART Token 0"));
        }

        private static Pkcs11TokenInfo GostToken() => new Pkcs11TokenInfo
        {
            Kind = RutokenKind.Esmart,
            Reader = "Feitian SCR301 0",
            Model = "ESMARTToken GOST",
            Manufacturer = "ISBC",
            Atr = EsmartApdu.GostExactAtr,
        };

        [Fact]
        public void EsmartGostMetadata_RequiresExactModelManufacturerReaderAndAtr()
        {
            Assert.True(EsmartApdu.IsExactGostMetadata(GostToken()));

            var wrongModel = GostToken(); wrongModel.Model = "ESMART Token GOST 2";
            Assert.False(EsmartApdu.IsExactGostMetadata(wrongModel));

            var wrongVendor = GostToken(); wrongVendor.Manufacturer = "Contoso";
            Assert.False(EsmartApdu.IsExactGostMetadata(wrongVendor));

            var wrongAtr = GostToken(); wrongAtr.Atr = "3B 00";
            Assert.False(EsmartApdu.IsExactGostMetadata(wrongAtr));

            var exclusiveReader = GostToken(); exclusiveReader.Reader = "ISBC ESMART Token 0";
            Assert.False(EsmartApdu.IsExactGostMetadata(exclusiveReader));
        }

        [Fact]
        public void IsConfirmedEsmart_AdmitsGostOnlyThroughExactMetadata()
        {
            // ГОСТ-носитель за универсальным ридером проходит допуск лишь по точной паре
            // model/manufacturer и ATR — имени считывателя здесь недостаточно.
            Assert.True(Pkcs11Token.IsConfirmedEsmart(GostToken()));

            var noAtr = GostToken(); noAtr.Atr = null;
            Assert.False(Pkcs11Token.IsConfirmedEsmart(noAtr));

            var bareReader = new Pkcs11TokenInfo
            {
                Kind = RutokenKind.Esmart,
                Reader = "Feitian SCR301 0",
                Manufacturer = "ISBC",
            };
            Assert.False(Pkcs11Token.IsConfirmedEsmart(bareReader));
        }

        [Fact]
        public void EsmartGostLiveReader_RequiresExactlyOneMatchingAtrOnTheSameReader()
        {
            var token = GostToken();
            var present = new[]
            {
                new PcscReader { Name = "Feitian SCR301 0", CardPresent = true, Atr = EsmartApdu.GostExactAtr },
            };
            Assert.True(EsmartApdu.IsExactLiveGostReader(token, present));

            var swapped = new[]
            {
                new PcscReader { Name = "Feitian SCR301 0", CardPresent = true, Atr = "3B 00" },
            };
            Assert.False(EsmartApdu.IsExactLiveGostReader(token, swapped));

            var absent = new[]
            {
                new PcscReader { Name = "Feitian SCR301 0", CardPresent = false, Atr = EsmartApdu.GostExactAtr },
            };
            Assert.False(EsmartApdu.IsExactLiveGostReader(token, absent));
            Assert.False(EsmartApdu.IsExactLiveGostReader(token, Array.Empty<PcscReader>()));
        }

        [Fact]
        public void EsmartGostFileIds_AreFlatUnderTheSelectedContainer()
        {
            // Раскладка ГОСТ: суффиксы 1..6 = masks/primary/header/masks2/primary2/name,
            // слоты идут группами F01x, F02x ... внутри общего DF 8F01/7F01.
            Assert.Equal(0xF011, EsmartGostApdu.FileId(1, 0x01));
            Assert.Equal(0xF016, EsmartGostApdu.FileId(1, 0x06));
            Assert.Equal(0xF023, EsmartGostApdu.FileId(2, 0x03));
            Assert.Equal(0xF0F3, EsmartGostApdu.FileId(15, 0x03));
            Assert.Equal(0xF113, EsmartGostApdu.FileId(16, 0x03));
            Assert.Equal(0xF193, EsmartGostApdu.FileId(24, 0x03));
            Assert.Throws<ArgumentOutOfRangeException>(() => EsmartGostApdu.FileId(0, 0x01));
            Assert.Throws<ArgumentOutOfRangeException>(() => EsmartGostApdu.FileId(25, 0x01));
        }

        [Fact]
        public void EsmartGostOutputName_PreservesFirstSlotAndDisambiguatesFollowingSlots()
        {
            Assert.Equal("esmartgost_7F01", EsmartGostApdu.OutputName(1));
            Assert.Equal("esmartgost_7F01_F020", EsmartGostApdu.OutputName(2));
            Assert.Equal("esmartgost_7F01_F0F0", EsmartGostApdu.OutputName(15));
            Assert.Equal("esmartgost_7F01_F110", EsmartGostApdu.OutputName(16));
            Assert.Equal("esmartgost_7F01_F190", EsmartGostApdu.OutputName(24));
            Assert.Throws<ArgumentOutOfRangeException>(() => EsmartGostApdu.OutputName(25));
        }
    }
}
