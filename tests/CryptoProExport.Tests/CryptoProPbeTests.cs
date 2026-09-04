using System;
using System.IO;
using CryptoProExport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Xunit;

namespace CryptoProExport.Tests
{
    public class CryptoProPbeTests
    {
        private const string Password = "pbe-test-2026";

        [Fact]
        public void DerivePbeKey_MatchesCryptoProReferenceVector()
        {
            byte[] salt = Convert.FromHexString("30B445CF1BBF4150E57A544C970EF3BE");

            byte[] key = CryptoProPbe.DerivePbeKey(Password, salt, 2000);

            Assert.Equal(
                "6EBA4D1A27E015C01244BC9856B559A25BF89F6A5FD7C180D97D16E95D8C1D20",
                Convert.ToHexString(key));
        }

        [Fact]
        public void Shroud_RoundTripsSyntheticContainer()
        {
            WithContainer(signature: false, result =>
            {
                var encrypted = Shroud(result);

                Assert.Equal(CryptoProPbe.Oid, encrypted.EncryptionAlgorithm.Algorithm.Id);
                Assert.Equal(ContainerKeyExtractor.Reverse(result.PrivateKey),
                             CryptoProPbe.Unshroud(encrypted, Password));
                Assert.Equal("1.2.643.7.1.1.6.1", InnerAlgorithm(encrypted));
            });
        }

        [Fact]
        public void Shroud_UsesSignatureAlgorithmForPrimary2()
        {
            WithContainer(signature: true, result =>
            {
                var encrypted = Shroud(result);

                Assert.Equal(ContainerKeyExtractor.Reverse(result.PrivateKey),
                             CryptoProPbe.Unshroud(encrypted, Password));
                Assert.Equal("1.2.643.7.1.1.1.1", InnerAlgorithm(encrypted));
            });
        }

        [Fact]
        public void Unshroud_RejectsWrongPasswordAndTampering()
        {
            WithContainer(signature: false, result =>
            {
                var encrypted = Shroud(result);
                Assert.ThrowsAny<Exception>(() => CryptoProPbe.Unshroud(encrypted, "wrong"));

                byte[] damaged = encrypted.GetEncryptedData();
                damaged[damaged.Length / 2] ^= 0x40;
                var tampered = new EncryptedPrivateKeyInfo(encrypted.EncryptionAlgorithm, damaged);
                Assert.ThrowsAny<Exception>(() => CryptoProPbe.Unshroud(tampered, Password));
            });
        }

        [Fact]
        public void ParseHeader_ReadsPbeMetadata()
        {
            byte[] expiration = new DerSequence(
                new DerTaggedObject(false, 1, new DerGeneralizedTime("20300102030405Z")))
                .GetEncoded();
            byte[] headerDer = new DerSequence(
                new DerSequence(
                    new DerObjectIdentifier("1.2.643.7.1.1.1.1"),
                    new DerSequence(new DerObjectIdentifier("1.2.643.2.2.35.1"),
                                    new DerObjectIdentifier("1.2.643.7.1.1.2.2"))),
                new DerSequence(
                    new DerObjectIdentifier("1.2.643.7.1.1.6.1"),
                    new DerSequence(new DerObjectIdentifier("1.2.643.2.2.36.0"),
                                    new DerObjectIdentifier("1.2.643.7.1.1.2.2"))),
                new DerSequence(
                    new DerObjectIdentifier("1.2.643.2.2.37.3.10"),
                    new DerOctetString(expiration)))
                .GetEncoded();

            var header = ContainerKeyExtractor.ParseHeader(headerDer);

            Assert.Equal("1.2.643.2.2.35.1", header.SignatureCurveOid);
            Assert.Equal("1.2.643.2.2.36.0", header.AgreementCurveOid);
            Assert.Equal("20300102030405Z", header.KeyExpirationUtc);
        }

        private static EncryptedPrivateKeyInfo Shroud(ContainerKeyExtractor.Result result)
            => CryptoProPbe.Shroud(
                result,
                Password,
                Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
                Convert.FromHexString("1011121314151617"));

        private static string InnerAlgorithm(EncryptedPrivateKeyInfo encrypted)
        {
            var parameters = Asn1Sequence.GetInstance(encrypted.EncryptionAlgorithm.Parameters);
            byte[] salt = Asn1OctetString.GetInstance(parameters[0]).GetOctets();
            int iterations = DerInteger.GetInstance(parameters[1]).IntValueExact;
            byte[] key = CryptoProPbe.DerivePbeKey(Password, salt, iterations);
            byte[] plain = CryptoProPbe.CfbDecrypt(key, salt[..8], encrypted.GetEncryptedData());
            var blob = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(plain));
            byte[] payload = Asn1OctetString.GetInstance(blob[2]).GetOctets();
            var export = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(payload[16..]));
            var value = Asn1Sequence.GetInstance(export[0]);
            var taggedPrivateKey = Asn1TaggedObject.GetInstance(value[2]);
            var privateKey = Asn1Sequence.GetInstance(taggedPrivateKey, false);
            var taggedAlgorithm = Asn1TaggedObject.GetInstance(privateKey[1]);
            var algorithm = Asn1Sequence.GetInstance(taggedAlgorithm, false);
            return DerObjectIdentifier.GetInstance(algorithm[0]).Id;
        }

        private static void WithContainer(bool signature, Action<ContainerKeyExtractor.Result> test)
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-pbe-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 41, password: "");
                if (signature)
                {
                    File.Move(Path.Combine(dir, "primary.key"), Path.Combine(dir, "primary2.key"));
                    File.Move(Path.Combine(dir, "masks.key"), Path.Combine(dir, "masks2.key"));
                }

                test(ContainerKeyExtractor.Extract(dir));
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }
}
