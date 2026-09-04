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
    ///     • ContentInfo(data) → SafeContents { pkcs8ShroudedKeyBag } — ключ под PBE КриптоПро;
    ///     • ContentInfo(encryptedData) → SafeContents { certBag } — сертификат под стандартным PBE.
    ///
    /// Защита ключа — проприетарный PBE КриптоПро <c>1.2.840.113549.1.12.1.80</c>,
    /// имитовставка файла — HMAC-SHA-1. Именно такой key bag КриптоПро принимает при обратном
    /// импорте. Сертификат шифруется 3DES-PBE, как в файлах, созданных certmgr.
    ///
    /// Внутренний ключевой blob повторяет формат PFX КриптоПро и содержит закрытый ключ
    /// ГОСТ Р 34.10-2012 длиной 256 бит. Собирать его через <c>PrivateKeyInfoFactory</c> нельзя:
    /// BouncyCastle подставляет OID gost2001 (1.2.643.2.2.19) и получается ключ, который
    /// объявляет себя алгоритмом 2001 года при параметрах 2012-го.
    /// </summary>
    public static class Pkcs12Export
    {
        /// <summary>Итераций в PBE и в имитовставке — как в файлах КриптоПро.</summary>
        private const int Iterations = 2000;

        private const int MacSaltLength = 20;

        private const string CryptoProProviderName =
            "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider";

        /// <summary>
        /// Собрать .pfx из результата разбора контейнера. Сертификат берётся из
        /// <paramref name="certificate"/>, а если он не задан — из самого контейнера
        /// (<see cref="ContainerKeyExtractor.Result.Certificate"/>). Имя <paramref name="friendlyName"/>
        /// попадает в атрибут friendlyName ключевого мешка; пустое — атрибут не добавляется.
        /// </summary>
        public static byte[] Build(ContainerKeyExtractor.Result result, string password,
                                   byte[] certificate = null, string friendlyName = null)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));

            byte[] certDer = certificate ?? result.Certificate;
            if (certDer == null)
                throw new ContainerKeyException(Strings.Get("err.pfx.nocert"));
            CheckCertificateMatchesKey(certDer, result);

            var random = new SecureRandom();

            // В PFX КриптоПро localKeyId — little-endian KeySpec: 1 для обмена, 2 для подписи.
            byte[] localKeyId = { result.SignatureKey ? (byte)2 : (byte)1, 0, 0, 0 };

            var certBag = new SafeBag(
                PkcsObjectIdentifiers.CertBag,
                new CertBag(PkcsObjectIdentifiers.X509Certificate, new DerOctetString(certDer)).ToAsn1Object(),
                Attributes(localKeyId, friendlyName: null, includeProvider: false));

            var keyBag = new SafeBag(
                PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag,
                CryptoProPbe.Shroud(result, password, random).ToAsn1Object(),
                Attributes(localKeyId, friendlyName, includeProvider: true));

            byte[] authSafe = new DerSequence(
                DataContentInfo(new DerSequence(keyBag)),
                EncryptedContentInfo(new DerSequence(certBag).GetEncoded(), password, random)).GetEncoded();

            return new Pfx(
                new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(authSafe)),
                Mac(authSafe, password, random)).GetEncoded(Asn1Encodable.Der);
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

        /// <summary>Имитовставка всего файла: HMAC-SHA-1 на ключе, выведенном из пароля (PKCS#12 KDF, ID 3).</summary>
        private static MacData Mac(byte[] authSafe, string password, SecureRandom random)
        {
            byte[] salt = new byte[MacSaltLength];
            random.NextBytes(salt);

            var gen = new Pkcs12ParametersGenerator(new Sha1Digest());
            gen.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(Chars(password)), salt, Iterations);
            var mac = new HMac(new Sha1Digest());
            mac.Init(gen.GenerateDerivedMacParameters(mac.GetMacSize() * 8));
            mac.BlockUpdate(authSafe, 0, authSafe.Length);
            byte[] digest = new byte[mac.GetMacSize()];
            mac.DoFinal(digest, 0);

            var algId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);
            return new MacData(new DigestInfo(algId, digest), salt, Iterations);
        }

        /// <summary>Пустой пароль — пустой массив символов: BouncyCastle сам даёт для него пустую строку байт.</summary>
        private static char[] Chars(string password) => (password ?? "").ToCharArray();

        /// <summary>ContentInfo типа data, внутри которого лежит DER переданной структуры.</summary>
        private static ContentInfo DataContentInfo(Asn1Encodable content) =>
            new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(content.GetEncoded()));

        private static ContentInfo EncryptedContentInfo(byte[] content, string password,
                                                        SecureRandom random)
        {
            byte[] salt = new byte[8];
            random.NextBytes(salt);
            var generator = new Pkcs12ParametersGenerator(new Sha1Digest());
            generator.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(Chars(password)),
                           salt, Iterations);
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
            cipher.Init(true, generator.GenerateDerivedParameters("DESEDE", 192, 64));
            byte[] encrypted = cipher.DoFinal(content);

            var algorithm = new AlgorithmIdentifier(
                PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc,
                new Pkcs12PbeParams(salt, Iterations));
            var encryptedContent = new DerSequence(
                PkcsObjectIdentifiers.Data,
                algorithm,
                new DerTaggedObject(false, 0, new DerOctetString(encrypted)));
            var encryptedData = new DerSequence(DerInteger.ValueOf(0), encryptedContent);
            return new ContentInfo(PkcsObjectIdentifiers.EncryptedData, encryptedData);
        }

        private static Asn1Set Attributes(byte[] localKeyId, string friendlyName, bool includeProvider)
        {
            var attrs = new List<Asn1Encodable>
            {
                Attribute(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID, new DerOctetString(localKeyId)),
            };
            if (!string.IsNullOrEmpty(friendlyName))
                attrs.Add(Attribute(PkcsObjectIdentifiers.Pkcs9AtFriendlyName, new DerBmpString(friendlyName)));
            if (includeProvider)
                attrs.Add(Attribute(new DerObjectIdentifier("1.3.6.1.4.1.311.17.1"),
                                    new DerBmpString(CryptoProProviderName)));
            return new DerSet(attrs.ToArray());
        }

        private static Asn1Sequence Attribute(DerObjectIdentifier oid, Asn1Encodable value) =>
            new DerSequence(oid, new DerSet(value));

    }
}
