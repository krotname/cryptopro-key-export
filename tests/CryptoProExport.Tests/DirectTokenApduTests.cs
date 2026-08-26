using System;
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

        [Fact]
        public void RutokenSFcp_UsesLittleEndianSizeAndFindsNestedTags()
        {
            byte[] fcp = { 0x62, 0x08, 0x82, 0x01, 0x01, 0x80, 0x02, 0x2C, 0x01, 0x00 };

            Assert.Equal(300, RutokenSApdu.FcpSize(fcp));
            Assert.Equal(new byte[] { 0x2C, 0x01 }, RutokenSApdu.FindTag(fcp, 0x80));
        }

        [Theory]
        [InlineData(RutokenKind.RutokenS, true)]
        [InlineData(RutokenKind.RutokenLite, true)]
        [InlineData(RutokenKind.JaCartaLt, true)]
        [InlineData(RutokenKind.RutokenEcp, false)]
        [InlineData(RutokenKind.Other, false)]
        public void Supports_ListsOnlyProvenPassiveBackends(RutokenKind kind, bool expected)
        {
            Assert.Equal(expected, DirectTokenApdu.Supports(kind));
        }
    }
}
