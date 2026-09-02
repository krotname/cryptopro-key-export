using System;
using System.Collections.Generic;
using CryptoProExport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Сборка синтетического файлового контейнера КриптоПро — операция, обратная разбору.
    /// Из известного d и случайной маски строит primary/masks/header (ГОСТ 28147 ECB + CPKDF +
    /// имитовставка заголовка), чтобы разными тестами (экстрактор, сборщик экспортируемой копии)
    /// прогонять одну и ту же проверенную цепочку без живого токена и персональных данных.
    ///
    /// Это тот же генератор, что в Android-ядре (<c>core/src/test/.../SyntheticContainer.kt</c>),
    /// вплоть до <see cref="JavaRandom"/> — генератора <c>java.util.Random</c>, воспроизведённого
    /// байт в байт. Одинаковый seed на обеих платформах даёт один и тот же контейнер, поэтому
    /// векторы Windows- и Android-порта общие, а не «похожие».
    /// </summary>
    internal static class SyntheticContainer
    {
        /// <summary>CryptoPro XchA (256 бит) — кривая контейнеров владельца.</summary>
        internal const string CurveOid = "1.2.643.2.2.36.0";

        /// <summary>Один синтетический ключ и файлы контейнера вокруг него.</summary>
        internal sealed class Built
        {
            internal byte[] PrivateKey, PublicX, PublicY, Certificate;

            /// <summary>Четыре <c>*.key</c> в «чистом» DER, как на диске.</summary>
            internal Dictionary<string, byte[]> FileBytes;

            internal ContainerFiles Files() => ContainerFiles.Of(FileBytes);
        }

        /// <summary>Двухключевой контейнер: обмен и подпись — независимые пары в одном header.</summary>
        internal sealed class DualBuilt
        {
            internal Built Exchange, Signature;
            internal Dictionary<string, byte[]> FileBytes;

            internal ContainerFiles Files() => ContainerFiles.Of(FileBytes);
        }

        internal static Built Build(int seed, string password)
        {
            var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(CurveOid));
            BigInteger q = domain.N;
            var rng = new JavaRandom(seed);

            BigInteger d = RandomMod(rng, q);
            BigInteger m = RandomMod(rng, q);
            BigInteger p = d.Multiply(m).Mod(q);

            byte[] salt = RandomBytes(rng, 12);
            byte[] storageKey = GostContainerCrypto.DeriveStorageKey(password, salt);

            byte[] primDec = Reverse(Pad32(p));       // little-endian
            byte[] primEnc = GostContainerCrypto.EcbEncrypt(storageKey, primDec);
            byte[] maskBytes = Reverse(Pad32(m));     // little-endian

            ECPoint pub = domain.G.Multiply(d).Normalize();
            byte[] x = Pad32(pub.AffineXCoord.ToBigInteger());
            byte[] y = Pad32(pub.AffineYCoord.ToBigInteger());
            byte[] fingerprint = Slice(Reverse(x), 8); // первые 8 байт X little-endian

            byte[] own = FakeCertificate(x, y, "CN=own");
            ECPoint otherPoint = domain.G.Multiply(RandomMod(rng, q)).Normalize();
            byte[] alien = FakeCertificate(Pad32(otherPoint.AffineXCoord.ToBigInteger()),
                                           Pad32(otherPoint.AffineYCoord.ToBigInteger()), "CN=alien");

            byte[] primaryKey = new DerSequence(new DerOctetString(primEnc)).GetEncoded(Asn1Encodable.Der);
            byte[] masksKey = new DerSequence(
                new DerOctetString(maskBytes),
                new DerOctetString(salt),
                new DerOctetString(GostContainerCrypto.MaskMac(maskBytes, salt))).GetEncoded(Asn1Encodable.Der);
            var content = new DerSequence(
                new DerBitString(new byte[] { 0x00 }),
                PrivateParameters(),
                new DerTaggedObject(false, 6, new DerOctetString(alien)),
                new DerTaggedObject(false, 5, new DerOctetString(own)),
                new DerTaggedObject(false, 10, new DerOctetString(fingerprint)));
            byte[] headerKey = Header(content);
            byte[] nameKey = new DerSequence(
                new DerOctetString(System.Text.Encoding.ASCII.GetBytes("cpxtest"))).GetEncoded(Asn1Encodable.Der);

            return new Built
            {
                PrivateKey = Pad32(d),
                PublicX = x,
                PublicY = y,
                Certificate = own,
                FileBytes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["primary.key"] = primaryKey,
                    ["masks.key"] = masksKey,
                    ["header.key"] = headerKey,
                    ["name.key"] = nameKey,
                },
            };
        }

        /// <summary>Две независимые пары в одном header: обмен в primary, подпись в неявном теге [4].</summary>
        internal static DualBuilt BuildDual(int seed, string password)
        {
            Built exchange = Build(seed, password);
            Built signature = Build(seed + 1, password);
            byte[] primaryFingerprint = Slice(Reverse(exchange.PublicX), 8);
            byte[] secondaryFingerprint = Slice(Reverse(signature.PublicX), 8);
            var content = new DerSequence(
                new DerBitString(new byte[] { 0x00 }),
                PrivateParameters(),
                new DerTaggedObject(false, 4, PrivateParameters()),
                new DerTaggedObject(false, 5, new DerOctetString(exchange.Certificate)),
                new DerTaggedObject(false, 6, new DerOctetString(signature.Certificate)),
                new DerTaggedObject(false, 10, new DerOctetString(primaryFingerprint)),
                new DerTaggedObject(false, 11, new DerOctetString(secondaryFingerprint)));

            return new DualBuilt
            {
                Exchange = exchange,
                Signature = signature,
                FileBytes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
                {
                    ["primary.key"] = exchange.FileBytes["primary.key"],
                    ["masks.key"] = exchange.FileBytes["masks.key"],
                    ["primary2.key"] = signature.FileBytes["primary.key"],
                    ["masks2.key"] = signature.FileBytes["masks.key"],
                    ["header.key"] = Header(content),
                    ["name.key"] = exchange.FileBytes["name.key"],
                },
            };
        }

        /// <summary>header.key = SEQUENCE { содержимое, OCTET STRING имитовставка(4) }.</summary>
        private static byte[] Header(Asn1Sequence content) =>
            new DerSequence(content,
                new DerOctetString(GostContainerCrypto.ContainerMac(content.GetEncoded(Asn1Encodable.Der))))
                .GetEncoded(Asn1Encodable.Der);

        private static DerSequence Algorithm() => new DerSequence(
            new DerObjectIdentifier("1.2.643.7.1.1.1.1"),
            new DerSequence(new DerObjectIdentifier(CurveOid), new DerObjectIdentifier("1.2.643.7.1.1.2.2")));

        /// <summary>Параметры ключа: BIT STRING атрибутов (бит экспорта снят) и алгоритм в теге [0].</summary>
        private static DerSequence PrivateParameters() => new DerSequence(
            new DerBitString(new byte[] { 0x00 }),
            new DerTaggedObject(false, 0, Algorithm()));

        /// <summary>
        /// Сертификат X.509 нужной формы: подпись фиктивная, потому что проверяется не она,
        /// а разбор и выбор по открытому ключу. Открытый ключ лежит как у КриптоПро —
        /// OCTET STRING из 64 байт (X‖Y little-endian) внутри BIT STRING.
        /// </summary>
        internal static byte[] FakeCertificate(byte[] x, byte[] y, string name)
        {
            byte[] pub = new byte[64];
            Array.Copy(Reverse(x), 0, pub, 0, 32);
            Array.Copy(Reverse(y), 0, pub, 32, 32);

            var algId = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.643.7.1.1.1.1"),
                new DerSequence(new DerObjectIdentifier(CurveOid), new DerObjectIdentifier("1.2.643.7.1.1.2.2")));
            var sigAlg = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.643.7.1.1.3.2"));

            var tbs = new V3TbsCertificateGenerator();
            tbs.SetSerialNumber(new DerInteger(BigInteger.One));
            tbs.SetIssuer(new X509Name(name));
            tbs.SetSubject(new X509Name(name));
            tbs.SetSignature(sigAlg);
            tbs.SetStartDate(new Time(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbs.SetEndDate(new Time(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbs.SetSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, new DerOctetString(pub)));

            return new DerSequence(tbs.GenerateTbsCertificate(), sigAlg, new DerBitString(new byte[64]))
                .GetEncoded(Asn1Encodable.Der);
        }

        private static BigInteger RandomMod(JavaRandom rng, BigInteger q)
        {
            while (true)
            {
                var v = new BigInteger(1, RandomBytes(rng, 32)).Mod(q);
                if (v.SignValue != 0) return v;
            }
        }

        private static byte[] RandomBytes(JavaRandom rng, int n)
        {
            var b = new byte[n];
            rng.NextBytes(b);
            return b;
        }

        internal static byte[] Reverse(byte[] a) => ContainerKeyExtractor.Reverse(a);

        internal static byte[] Pad32(BigInteger v) => ContainerKeyExtractor.Pad32(v);

        internal static byte[] Slice(byte[] a, int len)
        {
            var r = new byte[len];
            Array.Copy(a, r, len);
            return r;
        }
    }

    /// <summary>
    /// <c>java.util.Random</c> — линейный конгруэнтный генератор с 48-битным состоянием,
    /// воспроизведённый по спецификации Java. Нужен ровно для одного: чтобы синтетический
    /// контейнер с тем же seed совпадал байт в байт с Android-портом, где тесты написаны на
    /// Kotlin. Криптографического назначения не имеет и в продуктовом коде не используется.
    /// </summary>
    internal sealed class JavaRandom
    {
        private const long Multiplier = 0x5DEECE66DL;
        private const long Addend = 0xBL;
        private const long Mask = (1L << 48) - 1;

        private long _seed;

        internal JavaRandom(long seed) => _seed = (seed ^ Multiplier) & Mask;

        private int Next(int bits)
        {
            _seed = (_seed * Multiplier + Addend) & Mask;
            return (int)((ulong)_seed >> (48 - bits));
        }

        internal int NextInt() => Next(32);

        internal void NextBytes(byte[] bytes)
        {
            for (int i = 0; i < bytes.Length;)
            {
                int rnd = NextInt();
                for (int n = Math.Min(bytes.Length - i, 4); n-- > 0; rnd >>= 8)
                    bytes[i++] = (byte)rnd;
            }
        }
    }
}
