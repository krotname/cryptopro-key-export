using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoProExport
{
    /// <summary>
    /// Сборка PKCS#12 (.pfx) своими силами — из восстановленного закрытого ключа ГОСТ Р 34.10-2012
    /// и сертификата. Ни CSP, ни <c>certmgr</c>, ни <c>p12utility</c> не нужны: это последнее звено
    /// конвейера, которое ещё требовало установленного КриптоПро.
    ///
    /// Что внутри получившегося файла:
    ///   PFX { version 3, authSafe = ContentInfo(data), macData }
    ///   authSafe → AuthenticatedSafe = SEQUENCE OF ContentInfo:
    ///     • ContentInfo(data) → SafeContents { certBag }        — сертификат открытым текстом;
    ///     • ContentInfo(data) → SafeContents { pkcs8ShroudedKeyBag } — закрытый ключ под паролем.
    ///
    /// Защита ключа — <c>pbeWithSHAAnd3-KeyTripleDES-CBC</c> (PKCS#12 KDF на SHA-1 + 3DES-CBC),
    /// имитовставка файла — HMAC-SHA-1. Это самый широко читаемый набор: ГОСТ-овые PBE понимает
    /// только КриптоПро, а 3DES/SHA-1 читают и КриптоПро, и Windows, и OpenSSL. Сертификат не
    /// шифруется намеренно: он публичен, а незашифрованный certBag принимают все реализации.
    ///
    /// Закрытый ключ кладётся в том же виде, что и в <see cref="GostKeyExport"/> — PKCS#8 с
    /// algorithm id-tc26-gost3410-12-256. Собирать его через <c>PrivateKeyInfoFactory</c> нельзя:
    /// BouncyCastle подставляет туда OID gost2001 (1.2.643.2.2.19) и получается ключ, который
    /// объявляет себя алгоритмом 2001 года при параметрах 2012-го.
    /// </summary>
    public static class Pkcs12Export
    {
        /// <summary>Итераций в PBE и в имитовставке. 2048 — то же, что кладут OpenSSL и Windows.</summary>
        private const int Iterations = 2048;

        private const int SaltLength = 8;

        /// <summary>
        /// Собрать .pfx из результата разбора контейнера. Сертификат берётся из
        /// <paramref name="certificate"/>, а если он не задан — из самого контейнера
        /// (<see cref="ContainerKeyExtractor.Result.Certificate"/>). Имя <paramref name="friendlyName"/>
        /// попадает в атрибут friendlyName обоих мешков; пустое — атрибут не добавляется.
        /// </summary>
        public static byte[] Build(ContainerKeyExtractor.Result result, string password,
                                   byte[] certificate = null, string friendlyName = null)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

            byte[] certDer = certificate ?? result.Certificate;
            if (certDer == null)
                throw new ContainerKeyException(Strings.Get("err.pfx.nocert"));
            CheckCertificateMatchesKey(certDer, result);

            byte[] pkcs8 = GostKeyExport.ToPkcs8Der(result);
            var random = new SecureRandom();

            // localKeyId связывает сертификат с ключом: без него Windows ставит их в хранилище
            // как несвязанную пару, и «сертификат с закрытым ключом» не собирается.
            byte[] localKeyId = Sha1(result.PublicX);

            var certBag = new SafeBag(
                PkcsObjectIdentifiers.CertBag,
                new CertBag(PkcsObjectIdentifiers.X509Certificate, new DerOctetString(certDer)).ToAsn1Object(),
                Attributes(localKeyId, friendlyName));

            var keyBag = new SafeBag(
                PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag,
                Shroud(pkcs8, password, random).ToAsn1Object(),
                Attributes(localKeyId, friendlyName));

            byte[] authSafe = new DerSequence(
                DataContentInfo(new DerSequence(certBag)),
                DataContentInfo(new DerSequence(keyBag))).GetEncoded();

            return new Pfx(
                new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(authSafe)),
                Mac(authSafe, password, random)).GetEncoded();
        }

        /// <summary>
        /// Сертификат должен принадлежать этому ключу. Из контейнера он и так выбирается по
        /// совпадению открытого ключа, но переданный пользователем файл никто не проверял:
        /// молча собранный .pfx с чужим сертификатом выглядел бы рабочим и не работал.
        /// </summary>
        private static void CheckCertificateMatchesKey(byte[] certDer, ContainerKeyExtractor.Result result)
        {
            byte[] pub = ContainerKeyExtractor.CertificatePublicKey(certDer);
            if (pub == null)
                throw new ContainerKeyException(Strings.Get("err.pfx.badcert"));

            byte[] expected = new byte[64];
            Array.Copy(ContainerKeyExtractor.Reverse(result.PublicX), 0, expected, 0, 32);
            Array.Copy(ContainerKeyExtractor.Reverse(result.PublicY), 0, expected, 32, 32);
            if (!pub.AsSpan().SequenceEqual(expected))
                throw new ContainerKeyException(Strings.Get("err.pfx.certmismatch"));
        }

        /// <summary>Зашифровать PKCS#8 паролем: pbeWithSHAAnd3-KeyTripleDES-CBC.</summary>
        private static EncryptedPrivateKeyInfo Shroud(byte[] pkcs8, string password, SecureRandom random)
        {
            byte[] salt = new byte[SaltLength];
            random.NextBytes(salt);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, DeriveCipherParameters(password, salt));
            byte[] encrypted = cipher.DoFinal(pkcs8);

            var algId = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc,
                new Pkcs12PbeParams(salt, Iterations));
            return new EncryptedPrivateKeyInfo(algId, encrypted);
        }

        /// <summary>Имитовставка всего файла: HMAC-SHA-1 на ключе, выведенном из пароля (PKCS#12 KDF, ID 3).</summary>
        private static MacData Mac(byte[] authSafe, string password, SecureRandom random)
        {
            byte[] salt = new byte[SaltLength];
            random.NextBytes(salt);

            var gen = new Pkcs12ParametersGenerator(new Sha1Digest());
            gen.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(Chars(password)), salt, Iterations);
            var mac = new HMac(new Sha1Digest());
            mac.Init(gen.GenerateDerivedMacParameters(mac.GetMacSize() * 8));
            mac.BlockUpdate(authSafe, 0, authSafe.Length);
            byte[] digest = new byte[mac.GetMacSize()];
            mac.DoFinal(digest, 0);

            var algId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            return new MacData(new DigestInfo(algId, digest), salt, Iterations);
        }

        /// <summary>Ключ и вектор инициализации 3DES по PKCS#12 KDF (SHA-1, ID 1 и 2).</summary>
        private static ICipherParameters DeriveCipherParameters(string password, byte[] salt)
        {
            var gen = new Pkcs12ParametersGenerator(new Sha1Digest());
            gen.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(Chars(password)), salt, Iterations);
            return gen.GenerateDerivedParameters("DESEDE", 192, 64);
        }

        /// <summary>Пустой пароль — пустой массив символов: BouncyCastle сам даёт для него пустую строку байт.</summary>
        private static char[] Chars(string password) => (password ?? "").ToCharArray();

        /// <summary>ContentInfo типа data, внутри которого лежит DER переданной структуры.</summary>
        private static ContentInfo DataContentInfo(Asn1Encodable content) =>
            new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(content.GetEncoded()));

        private static Asn1Set Attributes(byte[] localKeyId, string friendlyName)
        {
            var attrs = new List<Asn1Encodable>
            {
                Attribute(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID, new DerOctetString(localKeyId)),
            };
            if (!string.IsNullOrEmpty(friendlyName))
                attrs.Add(Attribute(PkcsObjectIdentifiers.Pkcs9AtFriendlyName, new DerBmpString(friendlyName)));
            return new DerSet(attrs.ToArray());
        }

        private static Asn1Sequence Attribute(DerObjectIdentifier oid, Asn1Encodable value) =>
            new DerSequence(oid, new DerSet(value));

        private static byte[] Sha1(byte[] data)
        {
            var d = new Sha1Digest();
            d.BlockUpdate(data, 0, data.Length);
            byte[] outp = new byte[d.GetDigestSize()];
            d.DoFinal(outp, 0);
            return outp;
        }
    }
}
