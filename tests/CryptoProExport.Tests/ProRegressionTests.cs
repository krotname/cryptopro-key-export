using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Math;
using Xunit;

namespace CryptoProExport.Tests
{
    public class ProRegressionTests
    {
        [Fact]
        public void ExtractAll_RejectsSignaturePairStoredAsExchange()
        {
            var source = SyntheticContainer.BuildDual(120, "");
            source.FileBytes["primary.key"] = source.FileBytes["primary2.key"];
            source.FileBytes["masks.key"] = source.FileBytes["masks2.key"];

            Assert.Throws<ContainerKeyException>(() => ContainerKeyExtractor.ExtractAll(source.Files()));
        }

        [Fact]
        public void ExtractAll_UsesExchangeFingerprintWhenBothCiphertextsMatchHeader()
        {
            var source = SyntheticContainer.BuildDual(130, "");
            var (mask, salt) = ContainerKeyExtractor.ParseMasks(source.FileBytes["masks.key"]);
            var header = ContainerKeyExtractor.ParseHeader(source.FileBytes["header.key"]);
            var q = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(header.CurveOid)).N;
            var m = new BigInteger(1, ContainerKeyExtractor.Reverse(mask));
            var d = new BigInteger(1, source.Signature.PrivateKey);
            byte[] plain = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(d.Multiply(m).Mod(q)));
            byte[] key = GostContainerCrypto.DeriveStorageKey("", salt);
            byte[] sibling = GostContainerCrypto.EcbEncrypt(key, plain);
            byte[] exchange = ContainerKeyExtractor.ParsePrimary(source.FileBytes["primary.key"]);
            source.FileBytes["primary.key"] = new DerSequence(
                new DerOctetString(exchange),
                new DerTaggedObject(false, 0, new DerOctetString(sibling))).GetEncoded();

            var extracted = ContainerKeyExtractor.ExtractAll(source.Files());
            try
            {
                Assert.Equal(source.Exchange.PrivateKey, extracted.Single(k =>
                    k.Usage == ContainerKeyExtractor.KeyUsage.Exchange).Result.PrivateKey);
                Assert.Equal(source.Signature.PrivateKey, extracted.Single(k =>
                    k.Usage == ContainerKeyExtractor.KeyUsage.Signature).Result.PrivateKey);
            }
            finally { ContainerKeyExtractor.Wipe(extracted); }
        }

        [Fact]
        public void ProRepair_PreservesBothPairsAndRejectsWrongPasswordBeforeWriting()
        {
            var source = SyntheticContainer.BuildDual(140, "secret");
            string folder = Path.Combine(Path.GetTempPath(), "cpx-pro-regression-" + Guid.NewGuid().ToString("N"));
            try
            {
                source.Files().WriteTo(folder);
                Assert.Throws<ContainerKeyException>(() =>
                    ExportPipeline.MakeProSavedContainerExportable(folder, "wrong"));
                foreach (var item in source.FileBytes)
                    Assert.Equal(item.Value, File.ReadAllBytes(Path.Combine(folder, item.Key)));

                ExportPipeline.MakeProSavedContainerExportable(folder, "secret");

                foreach (string name in new[] { "primary.key", "masks.key", "primary2.key", "masks2.key", "name.key" })
                    Assert.Equal(source.FileBytes[name], File.ReadAllBytes(Path.Combine(folder, name)));
                CryptoProHeaderExportability.RequireExportable(
                    File.ReadAllBytes(Path.Combine(folder, "header.key")), exchange: true, signature: true);
                var keys = ContainerKeyExtractor.ExtractAll(folder, "secret");
                try
                {
                    Assert.Equal(source.Exchange.PrivateKey, keys[0].Result.PrivateKey);
                    Assert.Equal(source.Signature.PrivateKey, keys[1].Result.PrivateKey);
                }
                finally { ContainerKeyExtractor.Wipe(keys); }
            }
            finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
        }
    }
}
