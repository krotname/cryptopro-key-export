using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Xunit;

namespace CryptoProExport.Tests
{
    public sealed class ExportPipelineTests
    {
        [Fact]
        public void HasCertificateForPresentKey_AllowsOneCertifiedPairInTwoKeyFiles()
        {
            var both = new RutokenContainer();
            both.Files["primary.key"] = new byte[] { 1 };
            both.Files["primary2.key"] = new byte[] { 2 };

            Assert.True(ExportPipeline.HasCertificateForPresentKey(both, "exchange.cer", null));
            Assert.True(ExportPipeline.HasCertificateForPresentKey(both, null, "signature.cer"));
            Assert.True(ExportPipeline.HasCertificateForPresentKey(
                both, "exchange.cer", "signature.cer"));
        }

        [Fact]
        public void HasCertificateForPresentKey_RequiresMatchingPresentPair()
        {
            var exchangeOnly = new RutokenContainer();
            exchangeOnly.Files["primary.key"] = new byte[] { 1 };
            var signatureOnly = new RutokenContainer();
            signatureOnly.Files["primary2.key"] = new byte[] { 2 };

            Assert.True(ExportPipeline.HasCertificateForPresentKey(
                exchangeOnly, "exchange.cer", null));
            Assert.False(ExportPipeline.HasCertificateForPresentKey(
                exchangeOnly, null, "signature.cer"));
            Assert.False(ExportPipeline.HasCertificateForPresentKey(
                signatureOnly, "exchange.cer", null));
            Assert.True(ExportPipeline.HasCertificateForPresentKey(
                signatureOnly, null, "signature.cer"));
        }

        [Fact]
        public void HasCertificateForPresentKey_RejectsContainerWithoutRecognizedKey()
        {
            Assert.False(ExportPipeline.HasCertificateForPresentKey(new RutokenContainer(),
                                                                     "exchange.cer", "signature.cer"));
        }

        [Theory]
        [InlineData(true, false, true, false)]
        [InlineData(false, true, false, true)]
        [InlineData(true, true, true, true)]
        [InlineData(false, false, false, false)]
        public void LiteRepairTargets_SelectsOnlyKeysWithMatchingCertificates(
            bool hasExchangeCert, bool hasSignatureCert,
            bool expectExchange, bool expectSignature)
        {
            var both = new RutokenContainer();
            both.Files["primary.key"] = new byte[] { 1 };
            both.Files["primary2.key"] = new byte[] { 2 };

            var targets = ExportPipeline.LiteRepairTargets(
                both,
                hasExchangeCert ? "exchange.cer" : null,
                hasSignatureCert ? "signature.cer" : null);

            Assert.Equal(expectExchange, targets.exchange);
            Assert.Equal(expectSignature, targets.signature);
        }

        [Fact]
        public void ResolveLitePin_UsesExplicitPinWithoutInspectingTokenFlags()
        {
            var token = new Pkcs11TokenInfo { PinLocked = true, PinFinalTry = true };

            Assert.Equal("user-entered", ExportPipeline.ResolveLitePin(token, "user-entered"));
        }

        [Fact]
        public void ResolveLitePin_UsesFactoryPinOnlyForCleanDefaultToken()
        {
            var token = new Pkcs11TokenInfo { PinDefault = true };

            Assert.Equal("12345678", ExportPipeline.ResolveLitePin(token, null));
        }

        [Theory]
        [InlineData(false, false, false, false)]
        [InlineData(true, true, false, false)]
        [InlineData(true, false, true, false)]
        [InlineData(true, false, false, true)]
        public void ResolveLitePin_RefusesGuessingOrUnsafeCounter(
            bool isDefault, bool countLow, bool finalTry, bool locked)
        {
            var token = new Pkcs11TokenInfo
            {
                PinDefault = isDefault,
                PinCountLow = countLow,
                PinFinalTry = finalTry,
                PinLocked = locked,
            };

            Assert.Throws<LiteApduException>(() => ExportPipeline.ResolveLitePin(token, null));
        }

        [Fact]
        public void ExportLiteContainer_RejectsJaCartaLtBeforeApduOrFilesystemWrite()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-jacarta-lt-" + Guid.NewGuid().ToString("N"));
            var token = new Pkcs11TokenInfo
            {
                Reader = "Aladdin R.D. JaCarta LT 0",
                Kind = RutokenKind.JaCartaLt,
            };
            var selected = new LiteContainerRef();
            var pipeline = new ExportPipeline();

            var error = Assert.Throws<ArgumentException>(
                () => pipeline.ExportLiteContainer(token, selected, dir, "not-used"));

            Assert.Contains("JaCarta LT", error.Message, StringComparison.Ordinal);
            Assert.False(Directory.Exists(dir));
        }

        [Fact]
        public void NormalizeLiteContainer_ConvertsBothPrimaryFilesAndPreservesHeader()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-normalize-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, 23, "");
                File.WriteAllBytes(Path.Combine(dir, "name.key"), NameKey.Build("normalize"));
                byte[] encrypted = ContainerKeyExtractor.ParsePrimary(
                    File.ReadAllBytes(Path.Combine(dir, "primary.key")));
                byte[] cspEnvelope = new byte[32];
                for (int i = 0; i < cspEnvelope.Length; i++) cspEnvelope[i] = (byte)(i + 1);
                File.WriteAllBytes(Path.Combine(dir, "primary.key"), new DerSequence(
                    new DerOctetString(cspEnvelope),
                    new DerTaggedObject(false, 0, new DerOctetString(encrypted))).GetEncoded());
                byte[] header = File.ReadAllBytes(Path.Combine(dir, "header.key"));

                ExportPipeline.NormalizeLiteContainer(dir);

                Assert.Equal(header, File.ReadAllBytes(Path.Combine(dir, "header.key")));
                Assert.Equal(36, new FileInfo(Path.Combine(dir, "primary.key")).Length);
                Assert.Equal(encrypted, ContainerKeyExtractor.ParsePrimary(
                    File.ReadAllBytes(Path.Combine(dir, "primary.key"))));
            }
            finally { Directory.Delete(dir, recursive: true); }
        }
    }
}
