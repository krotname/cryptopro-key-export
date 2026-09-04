using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CryptoProExport
{
    /// <summary>
    /// Примитивы проприетарного PBE КриптоПро из PKCS#12
    /// (<c>1.2.840.113549.1.12.1.80</c>).
    /// </summary>
    internal static class CryptoProPbe
    {
        internal const string Oid = "1.2.840.113549.1.12.1.80";

        internal const int Iterations = 2000;

        private const int SaltLength = 16;
        private const int UkmLength = 8;
        private const string Gost3410_2012_256 = "1.2.643.7.1.1.1.1";
        private const string GostAgreement_2012_256 = "1.2.643.7.1.1.6.1";
        private const string GostDigest_2012_256 = "1.2.643.7.1.1.2.2";

        private static readonly byte[] KeyBlobHeader =
        {
            0x07, 0x20, 0x00, 0x00, 0x46, 0xAA, 0x00, 0x00,
            0x4D, 0x41, 0x47, 0x31, 0x20, 0x00, 0x00, 0x00,
        };

        private static readonly byte[] CryptoProASBox = Gost28147Engine.GetSBox("E-A");

        internal static EncryptedPrivateKeyInfo Shroud(ContainerKeyExtractor.Result result,
                                                        string password, SecureRandom random)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (result.PrivateKey == null || result.PrivateKey.Length != 32)
                throw new ArgumentException("private key", nameof(result));
            if (string.IsNullOrWhiteSpace(result.CurveOid))
                throw new ArgumentException("curve", nameof(result));
            if (random == null) throw new ArgumentNullException(nameof(random));

            byte[] salt = new byte[SaltLength];
            byte[] ukm = new byte[UkmLength];
            random.NextBytes(salt);
            random.NextBytes(ukm);
            return Shroud(result, password, salt, ukm);
        }

        internal static EncryptedPrivateKeyInfo Shroud(ContainerKeyExtractor.Result result,
                                                        string password, byte[] salt, byte[] ukm)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (result.PrivateKey == null || result.PrivateKey.Length != 32)
                throw new ArgumentException("private key", nameof(result));
            if (string.IsNullOrWhiteSpace(result.CurveOid))
                throw new ArgumentException("curve", nameof(result));
            if (salt == null || salt.Length != SaltLength) throw new ArgumentException("salt", nameof(salt));
            if (ukm == null || ukm.Length != UkmLength) throw new ArgumentException("ukm", nameof(ukm));

            byte[] pbeKey = null;
            byte[] kek = null;
            byte[] rawKey = null;
            try
            {
                pbeKey = DerivePbeKey(password, salt, Iterations);
                kek = DeriveKek(pbeKey, ukm);
                rawKey = ContainerKeyExtractor.Reverse(result.PrivateKey);
                byte[] encryptedKey = EcbEncrypt(kek, rawKey);
                byte[] keyMac = ComputeMac(kek, ukm, rawKey);

                string innerAlgorithm = result.SignatureKey
                    ? Gost3410_2012_256
                    : GostAgreement_2012_256;
                string keyCurveOid = result.KeyAlgorithmCurveOid ?? result.CurveOid;
                var keyAlgorithm = new DerSequence(
                    new DerObjectIdentifier(innerAlgorithm),
                    new DerSequence(
                        new DerObjectIdentifier(keyCurveOid),
                        new DerObjectIdentifier(GostDigest_2012_256)));
                var privateKeyInfo = new DerSequence(
                    new DerBitString(new byte[] { 0xA0 }, 5),
                    new DerTaggedObject(false, 0, keyAlgorithm));
                var value = new DerSequence(
                    new DerOctetString(ukm),
                    new DerSequence(new DerOctetString(encryptedKey), new DerOctetString(keyMac)),
                    new DerTaggedObject(false, 0, privateKeyInfo));
                byte[] trailer = ComputeMacWithoutIv(kek, value.GetEncoded());
                var exportBlob = new DerSequence(value, new DerOctetString(trailer));

                byte[] exportDer = exportBlob.GetEncoded();
                byte[] payload = new byte[KeyBlobHeader.Length + exportDer.Length];
                Array.Copy(KeyBlobHeader, payload, KeyBlobHeader.Length);
                Array.Copy(exportDer, 0, payload, KeyBlobHeader.Length, exportDer.Length);
                var blobItems = new List<Asn1Encodable>
                {
                    DerInteger.ValueOf(0),
                    new DerSequence(new DerObjectIdentifier(Gost3410_2012_256)),
                    new DerOctetString(payload),
                };
                if (!string.IsNullOrEmpty(result.KeyExpirationUtc))
                {
                    var expiration = new DerSequence(
                        new DerObjectIdentifier("1.2.643.2.2.37.3.10"),
                        new DerSet(new DerSequence(
                            new DerTaggedObject(false, 1,
                                new DerGeneralizedTime(result.KeyExpirationUtc)))));
                    blobItems.Add(new DerTaggedObject(true, 0, expiration));
                }
                var blob = new DerSequence(blobItems.ToArray());
                byte[] iv = new byte[8];
                Array.Copy(salt, iv, iv.Length);
                byte[] encryptedBlob = CfbEncrypt(pbeKey, iv, blob.GetEncoded());

                var algorithm = new AlgorithmIdentifier(
                    new DerObjectIdentifier(Oid),
                    new DerSequence(new DerOctetString(salt), DerInteger.ValueOf(Iterations)));
                return new EncryptedPrivateKeyInfo(algorithm, encryptedBlob);
            }
            finally
            {
                if (pbeKey != null) Array.Clear(pbeKey, 0, pbeKey.Length);
                if (kek != null) Array.Clear(kek, 0, kek.Length);
                if (rawKey != null) Array.Clear(rawKey, 0, rawKey.Length);
            }
        }

        internal static byte[] Unshroud(EncryptedPrivateKeyInfo encrypted, string password)
        {
            if (encrypted == null) throw new ArgumentNullException(nameof(encrypted));
            if (encrypted.EncryptionAlgorithm.Algorithm.Id != Oid)
                throw new ArgumentException("algorithm", nameof(encrypted));

            var parameters = Asn1Sequence.GetInstance(encrypted.EncryptionAlgorithm.Parameters);
            if (parameters.Count != 2) throw new ArgumentException("parameters", nameof(encrypted));
            byte[] salt = Asn1OctetString.GetInstance(parameters[0]).GetOctets();
            int iterations = DerInteger.GetInstance(parameters[1]).IntValueExact;
            if (salt.Length < 8) throw new ArgumentException("salt", nameof(encrypted));

            byte[] pbeKey = null;
            byte[] kek = null;
            byte[] raw = null;
            try
            {
                pbeKey = DerivePbeKey(password, salt, iterations);
                byte[] iv = new byte[8];
                Array.Copy(salt, iv, iv.Length);
                byte[] plain = CfbDecrypt(pbeKey, iv, encrypted.GetEncryptedData());
                var blob = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(plain));
                byte[] payload = Asn1OctetString.GetInstance(blob[2]).GetOctets();
                if (payload.Length <= KeyBlobHeader.Length
                    || !payload.AsSpan(0, KeyBlobHeader.Length).SequenceEqual(KeyBlobHeader))
                    throw new ArgumentException("key blob", nameof(encrypted));

                var export = Asn1Sequence.GetInstance(
                    Asn1Object.FromByteArray(payload.AsSpan(KeyBlobHeader.Length).ToArray()));
                var value = Asn1Sequence.GetInstance(export[0]);
                byte[] expectedTrailer = Asn1OctetString.GetInstance(export[1]).GetOctets();
                byte[] ukm = Asn1OctetString.GetInstance(value[0]).GetOctets();
                var cek = Asn1Sequence.GetInstance(value[1]);
                byte[] encryptedKey = Asn1OctetString.GetInstance(cek[0]).GetOctets();
                byte[] expectedMac = Asn1OctetString.GetInstance(cek[1]).GetOctets();
                kek = DeriveKek(pbeKey, ukm);
                raw = EcbDecrypt(kek, encryptedKey);
                byte[] actualMac = ComputeMac(kek, ukm, raw);
                if (!CryptographicOperations.FixedTimeEquals(expectedMac, actualMac))
                    throw new ArgumentException("key MAC", nameof(encrypted));
                byte[] actualTrailer = ComputeMacWithoutIv(kek, value.GetEncoded());
                if (!CryptographicOperations.FixedTimeEquals(expectedTrailer, actualTrailer))
                    throw new ArgumentException("blob MAC", nameof(encrypted));
                return (byte[])raw.Clone();
            }
            finally
            {
                if (pbeKey != null) Array.Clear(pbeKey, 0, pbeKey.Length);
                if (kek != null) Array.Clear(kek, 0, kek.Length);
                if (raw != null) Array.Clear(raw, 0, raw.Length);
            }
        }

        /// <summary>
        /// KDF КриптоПро: K_0 = UTF-16LE(password), затем
        /// K_i = ГОСТ Р 34.11-94(K_(i-1) || salt || i_be16).
        /// </summary>
        internal static byte[] DerivePbeKey(string password, byte[] salt, int iterations)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iterations < 1 || iterations > 1_000_000)
                throw new ArgumentOutOfRangeException(nameof(iterations));

            byte[] current = Encoding.Unicode.GetBytes(password ?? string.Empty);
            try
            {
                for (int i = 1; i <= iterations; i++)
                {
                    var digest = new Gost3411Digest();
                    digest.BlockUpdate(current, 0, current.Length);
                    digest.BlockUpdate(salt, 0, salt.Length);
                    digest.Update((byte)(i >> 8));
                    digest.Update((byte)i);
                    byte[] next = new byte[digest.GetDigestSize()];
                    digest.DoFinal(next, 0);
                    Array.Clear(current, 0, current.Length);
                    current = next;
                }
                byte[] result = (byte[])current.Clone();
                return result;
            }
            finally
            {
                Array.Clear(current, 0, current.Length);
            }
        }

        internal static byte[] CfbDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
            => Cfb(key, iv, ciphertext, encrypt: false);

        internal static byte[] CfbEncrypt(byte[] key, byte[] iv, byte[] plaintext)
            => Cfb(key, iv, plaintext, encrypt: true);

        /// <summary>
        /// KDF_GOSTR3411_2012_256(K, 0x26BDB878, UKM) по Р 50.1.113-2016.
        /// </summary>
        internal static byte[] DeriveKek(byte[] key, byte[] ukm)
        {
            if (key == null || key.Length != 32) throw new ArgumentException("key", nameof(key));
            if (ukm == null) throw new ArgumentNullException(nameof(ukm));

            byte[] input = new byte[1 + 4 + 1 + ukm.Length + 2];
            input[0] = 1;
            input[1] = 0x26;
            input[2] = 0xBD;
            input[3] = 0xB8;
            input[4] = 0x78;
            input[5] = 0;
            Array.Copy(ukm, 0, input, 6, ukm.Length);
            input[^2] = 1;
            input[^1] = 0;

            var hmac = new HMac(new Gost3411_2012_256Digest());
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(input, 0, input.Length);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            return result;
        }

        internal static byte[] EcbDecrypt(byte[] key, byte[] ciphertext)
            => Ecb(key, ciphertext, encrypt: false);

        internal static byte[] EcbEncrypt(byte[] key, byte[] plaintext)
            => Ecb(key, plaintext, encrypt: true);

        internal static byte[] ComputeMac(byte[] key, byte[] ukm, byte[] data)
        {
            if (key == null || key.Length != 32) throw new ArgumentException("key", nameof(key));
            if (ukm == null || ukm.Length != 8) throw new ArgumentException("ukm", nameof(ukm));
            if (data == null) throw new ArgumentNullException(nameof(data));

            var mac = new Gost28147Mac();
            // Gost28147Mac в BouncyCastle использует E-A (CryptoPro-A) по умолчанию,
            // но не принимает одновременно ParametersWithSBox и ParametersWithIV.
            mac.Init(new ParametersWithIV(new KeyParameter(key), ukm));
            mac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return result;
        }

        private static byte[] ComputeMacWithoutIv(byte[] key, byte[] data)
        {
            var mac = new Gost28147Mac();
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return result;
        }

        private static byte[] Cfb(byte[] key, byte[] iv, byte[] input, bool encrypt)
        {
            if (key == null || key.Length != 32) throw new ArgumentException("key", nameof(key));
            if (iv == null || iv.Length != 8) throw new ArgumentException("iv", nameof(iv));
            if (input == null) throw new ArgumentNullException(nameof(input));

            var cipher = new BufferedBlockCipher(new CfbBlockCipher(new Gost28147Engine(), 64));
            cipher.Init(encrypt, new ParametersWithIV(
                new ParametersWithSBox(new KeyParameter(key), CryptoProASBox), iv));
            return cipher.DoFinal(input);
        }

        private static byte[] Ecb(byte[] key, byte[] input, bool encrypt)
        {
            if (key == null || key.Length != 32) throw new ArgumentException("key", nameof(key));
            if (input == null || input.Length == 0 || input.Length % 8 != 0)
                throw new ArgumentException("input", nameof(input));

            var engine = new Gost28147Engine();
            engine.Init(encrypt, new ParametersWithSBox(new KeyParameter(key), CryptoProASBox));
            byte[] result = new byte[input.Length];
            for (int offset = 0; offset < input.Length; offset += engine.GetBlockSize())
                engine.ProcessBlock(input, offset, result, offset);
            return result;
        }
    }
}
