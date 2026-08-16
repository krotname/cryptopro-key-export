using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using KrotName.Licensing;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Гейт лицензии продукта cryptoexport: отпечаток машины, вшитый публичный ключ и
    /// офлайн-проверка подписи вендоренным референс-клиентом. Приватного ключа в тестах нет,
    /// поэтому «правильно подписанная вшитым ключом лицензия» здесь не строится — вместо этого
    /// проверяется, что подделки отвергаются, а сам верификатор принимает лицензию, подписанную
    /// известной тестовой парой.
    /// </summary>
    public class LicenseGateTests
    {
        private const string Fp = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

        [Fact]
        public void Fingerprint_HasProtocolFormat()
        {
            string fp = LicenseGate.Fingerprint();
            Assert.Matches("^sha256:[0-9a-f]{64}$", fp);
        }

        [Fact]
        public void Fingerprint_IsStableWithinRun()
        {
            Assert.Equal(LicenseGate.Fingerprint(), LicenseGate.Fingerprint());
        }

        [Fact]
        public void EmbeddedPublicKey_IsValidP256()
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(LicenseGate.PublicKeyB64), out _);
            Assert.Equal(256, ecdsa.KeySize);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("не.лицензия")]
        [InlineData("a.b.c")]
        public void Verify_RejectsGarbage(string bad)
        {
            Assert.Equal(LicenseState.Invalid, LicenseGate.Verify(bad).State);
        }

        [Fact]
        public void Verify_RejectsForgedLicenseWithTheRealKid()
        {
            // Заголовок объявляет вшитый kid, но подпись поставлена ЧУЖИМ ключом: гейт обязан
            // отвергнуть такую лицензию по несовпадению подписи с вшитым публичным ключом.
            using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string jws = BuildLicense(attacker, LicenseGate.Kid, LicenseGate.ProductId, "windows", Fp, expNull: true);

            var info = LicenseGate.Verify(jws);
            Assert.Equal(LicenseState.Invalid, info.State);
        }

        [Fact]
        public void VendoredVerifier_AcceptsValidLicense()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            const string kid = "cryptoexport-test";
            string spki = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            string jws = BuildLicense(signer, kid, "cryptoexport", "windows", Fp, expNull: true);

            var verifier = new LicenseVerifier("cryptoexport", Platform.Windows,
                new Dictionary<string, string> { [kid] = spki });
            LicensePayload payload = verifier.Verify(jws, Fp, null, 1765000000, 0);

            Assert.Equal("cryptoexport", payload.Pid);
            Assert.Equal(LicenseType.Perpetual, payload.Typ);
            Assert.Null(payload.Exp);
            Assert.Equal(Fp, payload.Fp);
        }

        [Fact]
        public void VendoredVerifier_RejectsWrongMachineAndTamper()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            const string kid = "cryptoexport-test";
            string spki = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
            string jws = BuildLicense(signer, kid, "cryptoexport", "windows", Fp, expNull: true);

            var verifier = new LicenseVerifier("cryptoexport", Platform.Windows,
                new Dictionary<string, string> { [kid] = spki });

            // Другой отпечаток машины — шаг 7 §2.5.
            Assert.Throws<LicenseException>(() => verifier.Verify(jws,
                "sha256:" + new string('0', 64), null, 1765000000, 0));

            // Испорченная подпись — шаг 4.
            string tampered = jws.Substring(0, jws.Length - 2) + (jws.EndsWith("AA") ? "BB" : "AA");
            Assert.Throws<LicenseException>(() => verifier.Verify(tampered, Fp, null, 1765000000, 0));
        }

        /// <summary>Собирает compact JWS ES256 (PROTOCOL §2) тестовым ключом.</summary>
        private static string BuildLicense(ECDsa signer, string kid, string pid, string plat, string fp, bool expNull)
        {
            string header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
            string exp = expNull ? "null" : "1900000000";
            string typ = expNull ? "perpetual" : "term";
            string payload =
                "{\"v\":1,\"lid\":\"L\",\"aid\":\"A\",\"pid\":\"" + pid + "\",\"typ\":\"" + typ +
                "\",\"plat\":\"" + plat + "\",\"iat\":1765000000,\"exp\":" + exp + ",\"fp\":\"" + fp +
                "\",\"seats\":1,\"feat\":[],\"kid\":\"" + kid + "\"}";

            string signingInput = B64Url(Encoding.UTF8.GetBytes(header)) + "." + B64Url(Encoding.UTF8.GetBytes(payload));
            // .NET по умолчанию отдаёт подпись P-256 в формате IEEE P1363 (r||s) — ровно как в JWS (§2.4).
            byte[] sig = signer.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return signingInput + "." + B64Url(sig);
        }

        private static string B64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
