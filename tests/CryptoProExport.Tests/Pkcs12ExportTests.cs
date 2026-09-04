using System;
using System.IO;
using System.Linq;
using CryptoProExport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Сборка PKCS#12 своими силами. Проверка круговая и на синтетике: контейнер собирается тем
    /// же кодом, что и разбирается (см. <see cref="ContainerKeyExtractorTests"/>), из него
    /// строится .pfx, затем независимо проверяются структура мешков, CryptoPro PBE, ключ
    /// и зашифрованный мешок сертификата.
    /// </summary>
    public class Pkcs12ExportTests
    {
        private const string PfxPassword = "pfx-пароль";

        [Fact]
        public void Pfx_HasCryptoProCompatibleStructure()
        {
            string dir = NewTempDir();
            try
            {
                var built = ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 3, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");

                byte[] pfx = Pkcs12Export.Build(result, PfxPassword, friendlyName: "тест");

                var parsed = Pfx.GetInstance(Asn1Object.FromByteArray(pfx));
                byte[] authSafe = Asn1OctetString.GetInstance(parsed.AuthSafe.Content).GetOctets();
                var contents = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(authSafe));
                Assert.Equal(2, contents.Count);

                var keyContent = ContentInfo.GetInstance(contents[0]);
                Assert.Equal(PkcsObjectIdentifiers.Data, keyContent.ContentType);
                var keySafe = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(
                    Asn1OctetString.GetInstance(keyContent.Content).GetOctets()));
                var keyBag = SafeBag.GetInstance(keySafe[0]);
                Assert.Equal(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag, keyBag.BagID);
                var encryptedKey = EncryptedPrivateKeyInfo.GetInstance(keyBag.BagValue);
                Assert.Equal(CryptoProPbe.Oid, encryptedKey.EncryptionAlgorithm.Algorithm.Id);
                Assert.Equal(ContainerKeyExtractor.Reverse(built.PrivateKey),
                             CryptoProPbe.Unshroud(encryptedKey, PfxPassword));

                var certContent = ContentInfo.GetInstance(contents[1]);
                Assert.Equal(PkcsObjectIdentifiers.EncryptedData, certContent.ContentType);
                byte[] certSafeDer = DecryptCertificateSafe(certContent, PfxPassword);
                var certSafe = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(certSafeDer));
                var certBag = CertBag.GetInstance(SafeBag.GetInstance(certSafe[0]).BagValue);
                Assert.Equal(built.Certificate, Asn1OctetString.GetInstance(certBag.CertValue).GetOctets());
            }
            finally { TryDelete(dir); }
        }

        private static byte[] DecryptCertificateSafe(ContentInfo contentInfo, string password)
        {
            var encryptedData = Asn1Sequence.GetInstance(contentInfo.Content);
            var encryptedContentInfo = Asn1Sequence.GetInstance(encryptedData[1]);
            var algorithm = AlgorithmIdentifier.GetInstance(encryptedContentInfo[1]);
            Assert.Equal(PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc, algorithm.Algorithm);
            var pbe = Pkcs12PbeParams.GetInstance(algorithm.Parameters);
            var tagged = Asn1TaggedObject.GetInstance(encryptedContentInfo[2]);
            byte[] ciphertext = Asn1OctetString.GetInstance(tagged, false).GetOctets();
            var generator = new Pkcs12ParametersGenerator(new Sha1Digest());
            generator.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(password.ToCharArray()),
                           pbe.GetIV(), pbe.Iterations.IntValueExact);
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(false, generator.GenerateDerivedParameters("DESEDE", 192, 64));
            return cipher.DoFinal(ciphertext);
        }

        [Fact]
        public void Pfx_WrongPassword_IsRejected()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 4, password: "");
                byte[] pfx = Pkcs12Export.Build(ContainerKeyExtractor.Extract(dir, ""), PfxPassword);

                var parsed = Pfx.GetInstance(Asn1Object.FromByteArray(pfx));
                byte[] authSafe = Asn1OctetString.GetInstance(parsed.AuthSafe.Content).GetOctets();
                var contents = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(authSafe));
                var keyContent = ContentInfo.GetInstance(contents[0]);
                var keySafe = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(
                    Asn1OctetString.GetInstance(keyContent.Content).GetOctets()));
                var encrypted = EncryptedPrivateKeyInfo.GetInstance(
                    SafeBag.GetInstance(keySafe[0]).BagValue);
                Assert.ThrowsAny<Exception>(() => CryptoProPbe.Unshroud(encrypted, "не тот"));
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Pfx_KeyIsShroudedNotPlain()
        {
            string dir = NewTempDir();
            try
            {
                var built = ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 6, password: "");
                byte[] pfx = Pkcs12Export.Build(ContainerKeyExtractor.Extract(dir, ""), PfxPassword);

                // Закрытый ключ не должен встречаться в файле открытым текстом — иначе пароль
                // .pfx не защищал бы ничего, а тест выше этого бы не заметил.
                string hex = Convert.ToHexString(pfx);
                Assert.DoesNotContain(Convert.ToHexString(built.PrivateKey), hex, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToHexString(built.PrivateKey.Reverse().ToArray()), hex,
                                      StringComparison.Ordinal);
                var outer = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(pfx));
                Assert.Equal(3, DerInteger.GetInstance(outer[0]).IntValueExact);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Build_ForeignCertificate_IsRejected()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 8, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");

                // Сертификат чужого ключа: собранный с ним .pfx выглядел бы рабочим и не работал
                byte[] alien = ContainerKeyExtractorTests.FakeCertificate(
                    new byte[32], new byte[32], "CN=alien");

                var ex = Assert.Throws<ContainerKeyException>(
                    () => Pkcs12Export.Build(result, PfxPassword, alien));
                Assert.Equal(Strings.Get("err.pfx.certmismatch"), ex.Message);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Build_WithoutAnyCertificate_ExplainsWhatIsMissing()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 9, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");
                result.Certificate = null;      // контейнер без сертификата — так тоже бывает

                var ex = Assert.Throws<ContainerKeyException>(() => Pkcs12Export.Build(result, PfxPassword));
                Assert.Equal(Strings.Get("err.pfx.nocert"), ex.Message);
            }
            finally { TryDelete(dir); }
        }

        private static string NewTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-pfx-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
