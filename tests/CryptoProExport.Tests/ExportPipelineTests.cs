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
        public void AllPresentKeysHandled_RequiresCertificateForEveryPresentKey()
        {
            var both = new RutokenContainer();
            both.Files["primary.key"] = new byte[] { 1 };
            both.Files["primary2.key"] = new byte[] { 2 };

            Assert.False(ExportPipeline.AllPresentKeysHandled(both, "exchange.cer", null));
            Assert.False(ExportPipeline.AllPresentKeysHandled(both, null, "signature.cer"));
            Assert.True(ExportPipeline.AllPresentKeysHandled(both, "exchange.cer", "signature.cer"));
        }

        [Fact]
        public void NameWithSuffix_FitsNameKeyEvenForTheLongestContainerName()
        {
            string tooLong = new string('и', NameKey.MaxNameLength);

            string exchange = ExportPipeline.NameWithSuffix(tooLong, " [exchange]");
            string signature = ExportPipeline.NameWithSuffix(tooLong, " [signature]");

            Assert.EndsWith(" [exchange]", exchange);
            Assert.EndsWith(" [signature]", signature);
            // Раньше здесь падало «имя слишком длинное», и весь экспорт возвращал неудачу
            Assert.Equal(exchange, NameKey.Parse(NameKey.Build(exchange)));
            Assert.Equal(signature, NameKey.Parse(NameKey.Build(signature)));
        }

        [Fact]
        public void NameWithSuffix_LeavesShortNamesAsIs()
        {
            Assert.Equal("Андрей ФНС [exchange]",
                ExportPipeline.NameWithSuffix("Андрей ФНС", " [exchange]"));
        }

        [Fact]
        public void AllPresentKeysHandled_AllowsSingleKeyContainer()
        {
            var exchangeOnly = new RutokenContainer();
            exchangeOnly.Files["primary.key"] = new byte[] { 1 };

            Assert.True(ExportPipeline.AllPresentKeysHandled(exchangeOnly, "exchange.cer", null));
        }

        [Fact]
        public void AllPresentKeysHandled_RejectsContainerWithoutRecognizedKey()
        {
            Assert.False(ExportPipeline.AllPresentKeysHandled(new RutokenContainer(),
                                                               "exchange.cer", "signature.cer"));
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
