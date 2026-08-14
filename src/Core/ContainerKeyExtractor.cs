using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace CryptoProExport
{
    /// <summary>Разбор не удался (нет файла, битый ASN.1, отпечаток не сошёлся).</summary>
    public sealed class ContainerKeyException : Exception
    {
        public ContainerKeyException(string message) : base(message) { }
    }

    /// <summary>
    /// Восстановление закрытого ключа ГОСТ Р 34.10-2012 (256 бит) из файлов контейнера КриптоПро
    /// без единого обращения к CSP. Алгоритм разобран и проверен на реальных контейнерах
    /// (ROADMAP раздел 3.1); здесь — самостоятельная реализация по описанию алгоритма.
    ///
    /// Порядок действий:
    ///   1. ключ хранения = CPKDF(пароль, соль из masks.key), хеш — Стрибог-256;
    ///   2. расшифровать primary.key алгоритмом ГОСТ 28147-89 (Магма) в режиме ECB, узел Param-Z;
    ///   3. развернуть расшифрованные 32 байта (little-endian) в число; так же развернуть маску;
    ///   4. закрытый ключ d = (primary · mask⁻¹) mod q, где q — порядок группы кривой из header.key.
    ///
    /// Оракул проверки лежит в самом контейнере: единственный восьмибайтовый OCTET STRING в
    /// header.key — это первые 8 байт координаты X открытого ключа в little-endian. При несовпадении
    /// результат считается неверным (неверный пароль / битый контейнер) и метод бросает исключение.
    /// </summary>
    public static class ContainerKeyExtractor
    {
        /// <summary>Результат разбора: закрытый ключ и всё, что нужно для вывода в PKCS#8/PEM.</summary>
        public sealed class Result
        {
            /// <summary>Закрытый ключ d, 32 байта, big-endian.</summary>
            public byte[] PrivateKey { get; internal set; }

            /// <summary>OID набора параметров кривой (publicKeyParamSet), например 1.2.643.2.2.36.0.</summary>
            public string CurveOid { get; internal set; }

            /// <summary>Открытый ключ d·G: координата X, 32 байта big-endian.</summary>
            public byte[] PublicX { get; internal set; }

            /// <summary>Открытый ключ d·G: координата Y, 32 байта big-endian.</summary>
            public byte[] PublicY { get; internal set; }

            /// <summary>Отпечаток из header.key сошёлся с посчитанным открытым ключом (всегда true при успехе).</summary>
            public bool FingerprintVerified { get; internal set; }

            /// <summary>
            /// Сертификат этого ключа из header.key в DER, или <c>null</c>, если его там нет.
            /// Берётся только сертификат, чей открытый ключ совпал с посчитанным d·G: в контейнере
            /// с двумя ключами (подпись + обмен) сертификатов два, и чужой не подойдёт.
            /// </summary>
            public byte[] Certificate { get; internal set; }

            internal BigInteger D { get; set; }
        }

        /// <summary>
        /// Разобрать контейнер в папке <paramref name="containerDir"/> (шесть *.key). Пароль контейнера —
        /// <paramref name="password"/> (для контейнеров без пароля — пустая строка). Бросает
        /// <see cref="ContainerKeyException"/>, если файлов нет, ASN.1 битый или отпечаток не сошёлся.
        /// </summary>
        public static Result Extract(string containerDir, string password = "")
        {
            if (containerDir == null) throw new ArgumentNullException(nameof(containerDir));

            bool hasPrimary = File.Exists(Path.Combine(containerDir, "primary.key"));
            bool hasMasks = File.Exists(Path.Combine(containerDir, "masks.key"));
            bool hasPrimary2 = File.Exists(Path.Combine(containerDir, "primary2.key"));
            bool hasMasks2 = File.Exists(Path.Combine(containerDir, "masks2.key"));
            if (hasPrimary != hasMasks)
                _ = ReadKeyFile(containerDir, hasPrimary ? "masks.key" : "primary.key");
            if (hasPrimary2 != hasMasks2)
                _ = ReadKeyFile(containerDir, hasPrimary2 ? "masks2.key" : "primary2.key");

            bool useExchange = hasPrimary || !hasPrimary2;
            string primaryFile = useExchange ? "primary.key" : "primary2.key";
            string masksFile = useExchange ? "masks.key" : "masks2.key";
            byte[] primaryRaw = ReadKeyFile(containerDir, primaryFile);
            byte[] masksRaw = ReadKeyFile(containerDir, masksFile);
            byte[] headerRaw = ReadKeyFile(containerDir, "header.key");

            byte[] primEnc = ParsePrimary(primaryRaw);
            var (mask, salt) = ParseMasks(masksRaw);
            var header = ParseHeader(headerRaw);
            string curveOid = header.CurveOid;
            byte[] fingerprint = header.Fingerprint;

            var domain = ECGost3410NamedCurves.GetByOid(new DerObjectIdentifier(curveOid));
            if (domain == null)
                throw new ContainerKeyException(Strings.Format("err.extract.curve", curveOid));
            BigInteger q = domain.N;

            // Ключ хранения из пароля и соли; на пустом пароле функция даёт нетривиальный ключ.
            byte[] storageKey = GostContainerCrypto.DeriveStorageKey(password ?? "", salt);

            // Шифруется сам primary.key, маска в masks.key лежит открытым текстом.
            byte[] primDec = GostContainerCrypto.EcbDecrypt(storageKey, primEnc);

            // primary и маска — little-endian: байты разворачиваются перед переводом в число.
            var p = new BigInteger(1, Reverse(primDec)).Mod(q);
            var m = new BigInteger(1, Reverse(mask)).Mod(q);
            if (p.SignValue == 0 || m.SignValue == 0)
                throw new ContainerKeyException(Strings.Get("err.extract.degenerate"));

            BigInteger d = p.Multiply(m.ModInverse(q)).Mod(q);
            if (d.SignValue == 0)
                throw new ContainerKeyException(Strings.Get("err.extract.degenerate"));

            ECPoint pub = domain.G.Multiply(d).Normalize();
            byte[] x = Pad32(pub.AffineXCoord.ToBigInteger());
            byte[] y = Pad32(pub.AffineYCoord.ToBigInteger());

            // Оракул: первые 8 байт X в little-endian = отпечаток из header.key. Отпечаток —
            // единственная проверка целостности разбора, поэтому контейнер без него принимать
            // нельзя: на неверном пароле получился бы математически валидный, но чужой ключ.
            if (fingerprint == null)
                throw new ContainerKeyException(Strings.Get("err.extract.nofingerprint"));
            byte[] fpComputed = Reverse(x);
            if (!Slice(fpComputed, 8).AsSpan().SequenceEqual(fingerprint))
                throw new ContainerKeyException(Strings.Get("err.extract.fingerprint"));

            return new Result
            {
                PrivateKey = Pad32(d),
                CurveOid = curveOid,
                PublicX = x,
                PublicY = y,
                FingerprintVerified = true,
                Certificate = PickCertificate(header.Certificates, x, y),
                D = d,
            };
        }

        // ---------- разбор ASN.1 ----------

        /// <summary>primary.key = SEQUENCE { OCTET STRING (32) } — зашифрованный primary.</summary>
        internal static byte[] ParsePrimary(byte[] der)
        {
            var seq = AsSequence(der, "primary.key");
            byte[] enc = OctetsAt(seq, 0, "primary.key");
            if (enc.Length != 32)
                throw Corrupt($"primary.key: {enc.Length} bytes, expected 32");
            return enc;
        }

        /// <summary>masks.key = SEQUENCE { OCTET STRING маска(32), OCTET STRING соль(12), OCTET STRING crc(4) }.</summary>
        internal static (byte[] mask, byte[] salt) ParseMasks(byte[] der)
        {
            var seq = AsSequence(der, "masks.key");
            if (seq.Count < 2)
                throw Corrupt($"masks.key: {seq.Count} elements");
            byte[] mask = OctetsAt(seq, 0, "masks.key");
            byte[] salt = OctetsAt(seq, 1, "masks.key");
            if (mask.Length != 32)
                throw Corrupt($"masks.key mask: {mask.Length} bytes");
            return (mask, salt);
        }

        /// <summary>Что удалось вычитать из header.key.</summary>
        internal sealed class Header
        {
            /// <summary>OID набора параметров кривой.</summary>
            public string CurveOid;

            /// <summary>Отпечаток открытого ключа: первые 8 байт X little-endian (или null).</summary>
            public byte[] Fingerprint;

            /// <summary>Сертификаты, найденные в header.key, в порядке появления (обычно 1–2).</summary>
            public List<byte[]> Certificates = new List<byte[]>();
        }

        /// <summary>
        /// header.key: обычный ASN.1. Оттуда берём OID кривой, первый восьмибайтовый OCTET STRING
        /// (отпечаток открытого ключа первого ключа контейнера) и сертификаты. Сертификат лежит
        /// открытым DER в элементе с неявным контекстным тегом ([5] для первого ключа, [6] для
        /// второго) — сжатия и нестандартной обёртки нет. Внутрь сертификата обход не заходит:
        /// иначе его OID-ы и восьмибайтовые строки смешались бы с полями самого контейнера.
        /// </summary>
        internal static Header ParseHeader(byte[] der)
        {
            Asn1Object root;
            try { root = Asn1Object.FromByteArray(der); }
            catch (Exception e) { throw Corrupt("header.key ASN.1: " + e.Message); }

            var oids = new List<string>();
            var octets8 = new List<byte[]>();
            var header = new Header();
            Walk(root, oids, octets8, header.Certificates);

            foreach (string id in oids)
                if (IsCurveOid(id)) { header.CurveOid = id; break; }
            if (header.CurveOid == null)
                throw Corrupt("header.key: no GOST curve OID");

            header.Fingerprint = octets8.Count > 0 ? octets8[0] : null;
            return header;
        }

        /// <summary>
        /// Выбрать из найденных сертификатов тот, чей открытый ключ равен посчитанному d·G.
        /// В контейнере с двумя ключами (подпись и обмен) сертификатов два, и взять «первый»
        /// нельзя — к разобранному primary.key относится только один из них. Совпадение
        /// открытого ключа заодно работает вторым, независимым от отпечатка оракулом.
        /// </summary>
        private static byte[] PickCertificate(List<byte[]> candidates, byte[] x, byte[] y)
        {
            byte[] expected = new byte[64];
            Array.Copy(Reverse(x), 0, expected, 0, 32);      // X little-endian
            Array.Copy(Reverse(y), 0, expected, 32, 32);     // затем Y little-endian
            foreach (byte[] der in candidates)
            {
                byte[] pub = CertificatePublicKey(der);
                if (pub != null && pub.AsSpan().SequenceEqual(expected)) return der;
            }
            return null;
        }

        /// <summary>
        /// Открытый ключ ГОСТ из сертификата: 64 байта (X‖Y little-endian), завёрнутые в OCTET
        /// STRING внутри BIT STRING поля subjectPublicKey. Возвращает null, если разобрать не вышло
        /// или ключ не той длины (например, 512-битный).
        /// </summary>
        internal static byte[] CertificatePublicKey(byte[] certDer)
        {
            try
            {
                var cert = X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(certDer));
                byte[] inner = cert.SubjectPublicKeyInfo.PublicKey.GetBytes();
                byte[] pub = Asn1OctetString.GetInstance(Asn1Object.FromByteArray(inner)).GetOctets();
                return pub.Length == 64 ? pub : null;
            }
            catch (Exception) { return null; }
        }

        /// <summary>Похож ли блоб на сертификат X.509 (строгий разбор DER, без «хвоста»).</summary>
        private static byte[] AsCertificate(byte[] der)
        {
            if (der.Length < 64 || der[0] != 0x30) return null;
            try
            {
                var cert = X509CertificateStructure.GetInstance(Asn1Object.FromByteArray(der));
                return cert.SubjectPublicKeyInfo != null && cert.Subject != null ? der : null;
            }
            catch (Exception) { return null; }
        }

        /// <summary>Наборы параметров кривых ГОСТ Р 34.10 (256 бит): CryptoPro A/B/C/XchA/XchB и tc26.</summary>
        private static bool IsCurveOid(string id) =>
            id.StartsWith("1.2.643.2.2.35", StringComparison.Ordinal)
            || id.StartsWith("1.2.643.2.2.36", StringComparison.Ordinal)
            || id.StartsWith("1.2.643.7.1.2.1.1", StringComparison.Ordinal);

        private static void Walk(Asn1Object o, List<string> oids, List<byte[]> octets8, List<byte[]> certs)
        {
            switch (o)
            {
                case DerObjectIdentifier oid:
                    oids.Add(oid.Id);
                    break;
                case Asn1OctetString os:
                    byte[] v = os.GetOctets();
                    if (v.Length == 8) octets8.Add(v);
                    // Элементы с неявным контекстным тегом BouncyCastle отдаёт как OCTET STRING;
                    // именно так выглядит сертификат в header.key. Внутрь него не заходим.
                    byte[] cert = AsCertificate(v);
                    if (cert != null) { certs.Add(cert); break; }
                    // Вложенный DER внутри OCTET STRING (в header.key так упакованы структуры).
                    try { Walk(Asn1Object.FromByteArray(v), oids, octets8, certs); }
                    catch (Exception) { /* не ASN.1 — это просто байты */ }
                    break;
                case Asn1Sequence seq:
                    foreach (Asn1Encodable e in seq) Walk(e.ToAsn1Object(), oids, octets8, certs);
                    break;
                case Asn1Set set:
                    foreach (Asn1Encodable e in set) Walk(e.ToAsn1Object(), oids, octets8, certs);
                    break;
                case Asn1TaggedObject t:
                    Walk(t.GetBaseObject().ToAsn1Object(), oids, octets8, certs);
                    break;
            }
        }

        private static Asn1Sequence AsSequence(byte[] der, string file)
        {
            try { return (Asn1Sequence)Asn1Object.FromByteArray(der); }
            catch (Exception e) { throw Corrupt($"{file} SEQUENCE: {e.Message}"); }
        }

        private static byte[] OctetsAt(Asn1Sequence seq, int index, string file)
        {
            if (index >= seq.Count)
                throw Corrupt($"{file}: element #{index} missing");
            if (seq[index] is not Asn1OctetString os)
                throw Corrupt($"{file}: element #{index} not OCTET STRING");
            return os.GetOctets();
        }

        private static byte[] ReadKeyFile(string dir, string name)
        {
            string path = Path.Combine(dir, name);
            if (!File.Exists(path))
                throw new ContainerKeyException(Strings.Format("err.extract.nofile", name, dir));
            return File.ReadAllBytes(path);
        }

        /// <summary>
        /// Локализованное «контейнер повреждён». Технический хвост {0} — диагностический токен
        /// (имя файла, длина, смещение) на латинице, как коды в CryptoErrors: он не переводится,
        /// человекочитаемая часть сообщения — переводится.
        /// </summary>
        private static ContainerKeyException Corrupt(string detail) =>
            new ContainerKeyException(Strings.Format("err.extract.corrupt", detail));

        // ---------- утилиты байтов ----------

        internal static byte[] Reverse(byte[] a)
        {
            var r = (byte[])a.Clone();
            Array.Reverse(r);
            return r;
        }

        private static byte[] Slice(byte[] a, int len)
        {
            var r = new byte[len];
            Array.Copy(a, r, len);
            return r;
        }

        /// <summary>Число → 32 байта big-endian с ведущими нулями (усечение старших нулей BigInteger компенсируется).</summary>
        internal static byte[] Pad32(BigInteger v)
        {
            byte[] b = v.ToByteArrayUnsigned();
            if (b.Length == 32) return b;
            if (b.Length > 32) throw Corrupt($"value {b.Length} bytes > 32");
            var r = new byte[32];
            Array.Copy(b, 0, r, 32 - b.Length, b.Length);
            return r;
        }
    }

    /// <summary>
    /// ГОСТ-примитивы для файлового контейнера: узел замены Param-Z, Стрибог-256, ГОСТ 28147 ECB
    /// и вывод ключа хранения из пароля (CPKDF). Вынесено отдельно, чтобы тем же кодом можно было
    /// собирать синтетический контейнер в тестах (круговая проверка).
    /// </summary>
    internal static class GostContainerCrypto
    {
        // Узел замены id-tc26-gost-28147-param-Z (1.2.643.7.1.2.5.1.1). В BouncyCastle его нет,
        // задаём константой. В gost-engine таблица записана начиная с k8, а Gost28147Engine ждёт
        // первой строку младшего полубайта (k1) — поэтому строки перевёрнуты (порядок строк обратный).
        private static readonly byte[][] ParamZRows =
        {
            new byte[] { 0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2 },
            new byte[] { 0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7 },
            new byte[] { 0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0 },
            new byte[] { 0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc },
            new byte[] { 0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb },
            new byte[] { 0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0 },
            new byte[] { 0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf },
            new byte[] { 0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1 },
        };

        // Константа рабочего буфера CPKDF — 32 ASCII-символа.
        private const string CpkdfSeed = "DENEFH028.760246785.IUEFHWUIO.EF";

        /// <summary>Плоский узел замены 128 байт (8×16) в порядке строк, который ждёт Gost28147Engine.</summary>
        internal static byte[] ParamZSBox { get; } = FlattenReversed(ParamZRows);

        private static byte[] FlattenReversed(byte[][] rows)
        {
            var r = new byte[128];
            for (int i = 0; i < 8; i++)
                Array.Copy(rows[7 - i], 0, r, i * 16, 16);
            return r;
        }

        /// <summary>Стрибог-256 от конкатенации частей. Порядок байт дайджеста не разворачивается.</summary>
        internal static byte[] Streebog256(params byte[][] parts)
        {
            var d = new Gost3411_2012_256Digest();
            foreach (var p in parts) d.BlockUpdate(p, 0, p.Length);
            var outp = new byte[d.GetDigestSize()];
            d.DoFinal(outp, 0);
            return outp;
        }

        internal static byte[] EcbDecrypt(byte[] key, byte[] data) => Ecb(key, data, encrypt: false);
        internal static byte[] EcbEncrypt(byte[] key, byte[] data) => Ecb(key, data, encrypt: true);

        private static byte[] Ecb(byte[] key, byte[] data, bool encrypt)
        {
            if (data.Length % 8 != 0)
                throw new ContainerKeyException(Strings.Format("err.extract.corrupt", $"GOST 28147 length {data.Length} not /8"));
            var engine = new Gost28147Engine();
            engine.Init(encrypt, new ParametersWithSBox(new KeyParameter(key), ParamZSBox));
            var outp = new byte[data.Length];
            for (int i = 0; i < data.Length; i += 8)
                engine.ProcessBlock(data, i, outp, i);
            return outp;
        }

        /// <summary>
        /// CPKDF: ключ хранения из пароля и соли (Стрибог-256, bs = 64).
        /// Пароль «разрежается» — буфер вчетверо длиннее, байты в позиции 0,4,8,…; пустой пароль
        /// даёт пустой буфер. hash = Стрибог(соль ‖ разрежённый пароль) считается один раз. Итераций
        /// 2 для пустого пароля, 2000 для заданного (на пустом обе трактовки неразличимы).
        /// </summary>
        internal static byte[] DeriveStorageKey(string password, byte[] salt)
        {
            const int bs = 64;
            byte[] pwdSparse = Sparse(Encoding.UTF8.GetBytes(password ?? ""));
            int iterations = pwdSparse.Length == 0 ? 2 : 2000;

            byte[] hash = Streebog256(salt, pwdSparse);
            byte[] c = Pad(Encoding.ASCII.GetBytes(CpkdfSeed), bs);

            for (int i = 0; i < iterations; i++)
                c = Pad(Streebog256(Xor(c, 0x36), hash, Xor(c, 0x5C), hash), bs);

            c = Streebog256(Slice(Xor(c, 0x36), 32), salt, Slice(Xor(c, 0x5C), 32), pwdSparse);
            return Streebog256(Slice(Pad(c, bs), 32));
        }

        private static byte[] Sparse(byte[] pwd)
        {
            var buf = new byte[pwd.Length * 4];
            for (int i = 0; i < pwd.Length; i++) buf[i * 4] = pwd[i];
            return buf;
        }

        private static byte[] Pad(byte[] a, int len)
        {
            if (a.Length >= len) return a;
            var r = new byte[len];
            Array.Copy(a, r, a.Length);
            return r;
        }

        private static byte[] Xor(byte[] a, byte v)
        {
            var r = new byte[a.Length];
            for (int i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ v);
            return r;
        }

        private static byte[] Slice(byte[] a, int len)
        {
            var r = new byte[len];
            Array.Copy(a, r, Math.Min(len, a.Length));
            return r;
        }
    }
}
