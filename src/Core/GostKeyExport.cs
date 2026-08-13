using System;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace CryptoProExport
{
    /// <summary>
    /// Вывод восстановленного закрытого ключа ГОСТ Р 34.10-2012 (256 бит) в PKCS#8 (DER/PEM),
    /// совместимо с OpenSSL gost-engine. Структура собирается вручную, чтобы точно задать
    /// algorithm identifier: id-tc26-gost3410-12-256 (1.2.643.7.1.1.1.1) с набором параметров
    /// кривой и дайджеста — тот же, что в сертификатах 2012-256. Тело ключа — 32 байта в
    /// little-endian, вложенные в OCTET STRING (форма, которую читает gost-engine).
    /// </summary>
    public static class GostKeyExport
    {
        // id-tc26-gost3410-12-256 — алгоритм закрытого ключа.
        private static readonly DerObjectIdentifier Gost3410_2012_256 =
            new DerObjectIdentifier("1.2.643.7.1.1.1.1");

        // id-tc26-gost3411-12-256 — набор параметров дайджеста для ключей 256 бит.
        private static readonly DerObjectIdentifier DigestParamSet256 =
            new DerObjectIdentifier("1.2.643.7.1.1.2.2");

        /// <summary>PKCS#8 (PrivateKeyInfo) в DER.</summary>
        public static byte[] ToPkcs8Der(ContainerKeyExtractor.Result result)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            return BuildPrivateKeyInfo(result).GetEncoded();
        }

        /// <summary>PKCS#8 в PEM (`-----BEGIN PRIVATE KEY-----`), с завершающим переводом строки.</summary>
        public static string ToPkcs8Pem(ContainerKeyExtractor.Result result)
        {
            return ToPem("PRIVATE KEY", ToPkcs8Der(result));
        }

        private static PrivateKeyInfo BuildPrivateKeyInfo(ContainerKeyExtractor.Result result)
        {
            var curveOid = new DerObjectIdentifier(result.CurveOid);
            if (ECGost3410NamedCurves.GetByOid(curveOid) == null)
                throw new ContainerKeyException(Strings.Format("err.extract.curve", result.CurveOid));

            var algId = new AlgorithmIdentifier(
                Gost3410_2012_256,
                new DerSequence(curveOid, DigestParamSet256));

            // gost-engine ждёт закрытый ключ в little-endian.
            byte[] le = ContainerKeyExtractor.Reverse(result.PrivateKey);
            return new PrivateKeyInfo(algId, new DerOctetString(le));
        }

        private static string ToPem(string label, byte[] der)
        {
            var sb = new StringBuilder();
            sb.Append("-----BEGIN ").Append(label).Append("-----\n");
            string b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64)
                sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
            sb.Append("-----END ").Append(label).Append("-----\n");
            return sb.ToString();
        }
    }
}
