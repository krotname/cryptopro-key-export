using System;
using System.IO;
using CryptoProExport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Проверка CSP-free разбора файлового контейнера. Реальных ключей и персданных здесь нет:
    /// контейнер собирается тем же кодом, что и разбирается (круговая проверка). Из известного
    /// закрытого ключа d и случайной маски строятся primary.key/masks.key/header.key, затем
    /// экстрактор должен вернуть исходный d — так проверяется вся цепочка (CPKDF, ГОСТ 28147 ECB,
    /// арифметика, оракул отпечатка), не завися от живого токена.
    /// </summary>
    public class ContainerKeyExtractorTests
    {
        // Кривая контейнеров владельца — CryptoPro XchA (256 бит). Тот же набор параметров у всех трёх.
        private const string CurveOid = "1.2.643.2.2.36.0";

        [Theory]
        [InlineData(1, "")]
        [InlineData(2, "")]
        [InlineData(7, "")]
        [InlineData(42, "secret")]
        [InlineData(100, "П@ssw0rd-ГОСТ")]
        public void Extract_RecoversOriginalPrivateKey(int seed, string password)
        {
            string dir = NewTempDir();
            try
            {
                var built = BuildSyntheticContainer(dir, seed, password);

                var result = ContainerKeyExtractor.Extract(dir, password);

                Assert.True(result.FingerprintVerified);
                Assert.Equal(built.PrivateKey, result.PrivateKey);
                Assert.Equal(built.PublicX, result.PublicX);
                Assert.Equal(built.PublicY, result.PublicY);
                Assert.Equal(CurveOid, result.CurveOid);
                // Из двух сертификатов в header.key должен выбраться свой, а не чужой
                Assert.Equal(built.Certificate, result.Certificate);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Extract_WrongPassword_ThrowsOnFingerprintMismatch()
        {
            string dir = NewTempDir();
            try
            {
                BuildSyntheticContainer(dir, seed: 5, password: "правильный");
                // Неверный пароль даёт другой ключ хранения → отпечаток не сойдётся.
                Assert.Throws<ContainerKeyException>(() => ContainerKeyExtractor.Extract(dir, "неверный"));
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Extract_MissingFile_Throws()
        {
            string dir = NewTempDir();
            try
            {
                var ex = Assert.Throws<ContainerKeyException>(() => ContainerKeyExtractor.Extract(dir, ""));
                Assert.Contains("primary.key", ex.Message);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Pkcs8_RoundTripsThroughBouncyCastle()
        {
            string dir = NewTempDir();
            try
            {
                var built = BuildSyntheticContainer(dir, seed: 11, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");

                byte[] der = GostKeyExport.ToPkcs8Der(result);
                // Разбираем свой же PKCS#8 обратно и сверяем закрытый и открытый ключ.
                var priv = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(der);
                Assert.Equal(new BigInteger(1, built.PrivateKey), priv.D);

                ECPoint q = priv.Parameters.G.Multiply(priv.D).Normalize();
                Assert.Equal(built.PublicX, Pad32(q.AffineXCoord.ToBigInteger()));
                Assert.Equal(built.PublicY, Pad32(q.AffineYCoord.ToBigInteger()));

                string pem = GostKeyExport.ToPkcs8Pem(result);
                Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
                Assert.Contains("-----END PRIVATE KEY-----", pem);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void DeriveStorageKey_IsDeterministicAndSaltDependent()
        {
            byte[] salt1 = new byte[12];
            byte[] salt2 = new byte[12];
            for (int i = 0; i < 12; i++) { salt1[i] = (byte)i; salt2[i] = (byte)(i + 1); }

            byte[] a = GostContainerCrypto.DeriveStorageKey("", salt1);
            byte[] b = GostContainerCrypto.DeriveStorageKey("", salt1);
            byte[] c = GostContainerCrypto.DeriveStorageKey("", salt2);

            Assert.Equal(32, a.Length);
            Assert.Equal(a, b);                 // детерминизм
            Assert.NotEqual(a, c);              // зависимость от соли
            Assert.NotEqual(new byte[32], a);   // ключ нетривиален даже на пустом пароле
        }

        [Fact]
        public void Gost28147Ecb_EncryptDecrypt_RoundTrips()
        {
            byte[] key = GostContainerCrypto.DeriveStorageKey("k", new byte[12]);
            byte[] data = new byte[32];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)(i * 7 + 3);

            byte[] enc = GostContainerCrypto.EcbEncrypt(key, data);
            byte[] dec = GostContainerCrypto.EcbDecrypt(key, enc);

            Assert.NotEqual(data, enc);
            Assert.Equal(data, dec);
        }

        // ---------- сборка синтетического контейнера (обратная к разбору) ----------

        internal sealed class Built
        {
            public byte[] PrivateKey, PublicX, PublicY, Certificate;
        }

        /// <summary>
        /// Собрать контейнер из известного d: p = d·m mod q, primary = ГОСТ28147-ECB(p little-endian),
        /// mask = m little-endian, header с OID кривой и отпечатком (первые 8 байт X little-endian).
        /// Всё детерминировано по seed, поэтому тест воспроизводим без живого ключа.
        /// </summary>
        internal static Built BuildSyntheticContainer(string dir, int seed, string password)
        {
            var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(CurveOid));
            BigInteger q = domain.N;
            var rng = new Random(seed);

            BigInteger d = RandomMod(rng, q);
            BigInteger m = RandomMod(rng, q);
            BigInteger p = d.Multiply(m).Mod(q);

            byte[] salt = RandomBytes(rng, 12);
            byte[] storageKey = GostContainerCrypto.DeriveStorageKey(password, salt);

            byte[] primDec = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(p)); // little-endian
            byte[] primEnc = GostContainerCrypto.EcbEncrypt(storageKey, primDec);
            byte[] maskBytes = ContainerKeyExtractor.Reverse(ContainerKeyExtractor.Pad32(m)); // little-endian

            ECPoint pub = domain.G.Multiply(d).Normalize();
            byte[] x = Pad32(pub.AffineXCoord.ToBigInteger());
            byte[] y = Pad32(pub.AffineYCoord.ToBigInteger());
            byte[] fingerprint = new byte[8];
            Array.Copy(ContainerKeyExtractor.Reverse(x), fingerprint, 8); // первые 8 байт X little-endian

            // primary.key = SEQUENCE { OCTET STRING (32) }
            WriteDer(dir, "primary.key", new DerSequence(new DerOctetString(primEnc)));
            // masks.key = SEQUENCE { OCTET STRING маска, OCTET STRING соль, OCTET STRING crc }
            WriteDer(dir, "masks.key", new DerSequence(
                new DerOctetString(maskBytes),
                new DerOctetString(salt),
                new DerOctetString(new byte[4])));
            // header.key: OID кривой, восьмибайтовый отпечаток и два сертификата — свой и чужой.
            // Сертификаты лежат так же, как в настоящем контейнере: открытым DER в элементе с
            // неявным контекстным тегом ([5] — ключ подписи, [6] — ключ обмена). Чужой добавлен
            // намеренно: экстрактор обязан выбрать тот, чей открытый ключ сошёлся с d·G.
            byte[] own = FakeCertificate(x, y, "CN=own");
            ECPoint other = domain.G.Multiply(RandomMod(rng, q)).Normalize();
            byte[] alien = FakeCertificate(Pad32(other.AffineXCoord.ToBigInteger()),
                                           Pad32(other.AffineYCoord.ToBigInteger()), "CN=alien");
            WriteDer(dir, "header.key", new DerSequence(
                new DerObjectIdentifier(CurveOid),
                new DerOctetString(fingerprint),
                new DerTaggedObject(false, 6, new DerOctetString(alien)),
                new DerTaggedObject(false, 5, new DerOctetString(own))));

            return new Built { PrivateKey = Pad32(d), PublicX = x, PublicY = y, Certificate = own };
        }

        /// <summary>
        /// Сертификат X.509 нужной формы: подпись фиктивная, потому что проверяется не она,
        /// а разбор и выбор по открытому ключу. Открытый ключ лежит как у КриптоПро —
        /// OCTET STRING из 64 байт (X‖Y little-endian) внутри BIT STRING.
        /// </summary>
        internal static byte[] FakeCertificate(byte[] x, byte[] y, string name)
        {
            byte[] pub = new byte[64];
            Array.Copy(ContainerKeyExtractor.Reverse(x), 0, pub, 0, 32);
            Array.Copy(ContainerKeyExtractor.Reverse(y), 0, pub, 32, 32);

            var algId = new AlgorithmIdentifier(
                new DerObjectIdentifier("1.2.643.7.1.1.1.1"),
                new DerSequence(new DerObjectIdentifier(CurveOid),
                                new DerObjectIdentifier("1.2.643.7.1.1.2.2")));
            var sigAlg = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.643.7.1.1.3.2"));

            var tbs = new V3TbsCertificateGenerator();
            tbs.SetSerialNumber(new DerInteger(BigInteger.One));
            tbs.SetIssuer(new X509Name(name));
            tbs.SetSubject(new X509Name(name));
            tbs.SetSignature(sigAlg);
            tbs.SetStartDate(new Time(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbs.SetEndDate(new Time(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbs.SetSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, new DerOctetString(pub)));

            return new DerSequence(tbs.GenerateTbsCertificate(), sigAlg,
                                   new DerBitString(new byte[64])).GetEncoded();
        }

        private static BigInteger RandomMod(Random rng, BigInteger q)
        {
            while (true)
            {
                var v = new BigInteger(1, RandomBytes(rng, 32)).Mod(q);
                if (v.SignValue != 0) return v;
            }
        }

        private static byte[] RandomBytes(Random rng, int n)
        {
            var b = new byte[n];
            rng.NextBytes(b);
            return b;
        }

        private static byte[] Pad32(BigInteger v) => ContainerKeyExtractor.Pad32(v);

        private static void WriteDer(string dir, string name, Asn1Encodable obj) =>
            File.WriteAllBytes(Path.Combine(dir, name), obj.GetEncoded());

        private static string NewTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-extract-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
