using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
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
            Assert.Equal(LicenseFailureCode.InvalidSignature, info.Failure.Code);
            Assert.Null(info.Failure.Detail);
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

        // ---------- причина отказа: код вместо русской диагностики верификатора ----------

        [Theory]
        // Тот самый случай владельца: файл выдан Android-сборке, а открывают его в Windows.
        [InlineData("cryptoexport", "android", null, LicenseFailureCode.OtherPlatform, "android")]
        [InlineData("androidexport", "windows", null, LicenseFailureCode.OtherProduct, "androidexport")]
        [InlineData("cryptoexport", "windows", Expired, LicenseFailureCode.Expired, "2023-11-14")]
        public void Classify_NamesWhatIsWrongWithTheFile(string pid, string plat, long? until,
            LicenseFailureCode expected, string detail)
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string jws = BuildLicense(signer, LicenseGate.Kid, pid, plat, LicenseGate.Fingerprint(), until);

            LicenseFailureInfo failure = LicenseGate.Classify(jws, Now, Keys(signer));

            Assert.Equal(expected, failure.Code);
            Assert.Equal(detail, failure.Detail);
        }

        [Fact]
        public void Classify_NamesOtherMachine()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string jws = BuildLicense(signer, LicenseGate.Kid, "cryptoexport", "windows", Fp, null);

            LicenseFailureInfo failure = LicenseGate.Classify(jws, Now, Keys(signer));

            Assert.Equal(LicenseFailureCode.OtherMachine, failure.Code);
            Assert.Null(failure.Detail);
        }

        [Fact]
        public void Classify_ReportsInvalidSignatureWithoutTrustingPayloadClaims()
        {
            // Нагрузка заявляет чужую платформу, но подписана ключом, которого нет среди доверенных:
            // её поля не классифицируются, а безопасный код говорит только о провале подписи.
            using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string jws = BuildLicense(stranger, LicenseGate.Kid, "cryptoexport", "android", LicenseGate.Fingerprint(), null);

            LicenseFailureInfo failure = LicenseGate.Classify(jws, Now,
                new Dictionary<string, string> { [LicenseGate.Kid] = LicenseGate.PublicKeyB64 });

            Assert.Equal(LicenseFailureCode.InvalidSignature, failure.Code);
            Assert.Null(failure.Detail);
        }

        [Fact]
        public void Classify_ReportsUnknownSigningKeyWithoutExposingKid()
        {
            using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            string jws = BuildLicense(signer, "retired-key", "cryptoexport", "windows", Fp, null);

            LicenseFailureInfo failure = LicenseGate.Classify(jws, Now, Keys(signer));

            Assert.Equal(LicenseFailureCode.InvalidSignature, failure.Code);
            Assert.Null(failure.Detail);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("не.лицензия")]
        [InlineData("a.b.c")]
        public void Verify_ReportsGarbageAsUnreadable(string bad)
        {
            Assert.Equal(LicenseFailureCode.Unreadable, LicenseGate.Verify(bad).Failure.Code);
        }

        [Fact]
        public void ReasonText_IsLocalizedAndNotTheVerifierMessage()
        {
            using var scope = Strings.Scope("ja");
            foreach (LicenseFailureCode code in Enum.GetValues<LicenseFailureCode>())
            {
                var info = new LicenseInfo(LicenseState.Invalid,
                    verifierDiagnostic: "подпись лицензии неверна",
                    failure: new LicenseFailureInfo(code, "x"));
                string text = LicenseGate.ReasonText(info);

                Assert.False(string.IsNullOrWhiteSpace(text));
                Assert.DoesNotContain("[!", text);
                Assert.NotEqual(info.VerifierDiagnostic, text);
            }
        }

        [Fact]
        public void SignatureReason_IsTranslatedInAllTwentyLanguages()
        {
            string russian = Strings.Table("ru")["license.reason.signature"];
            foreach (string language in Strings.Available)
            {
                string value = Strings.Table(language)["license.reason.signature"];
                Assert.False(string.IsNullOrWhiteSpace(value));
                if (language != "ru") Assert.NotEqual(russian, value);
            }
        }

        [Fact]
        public void GuiAndCli_KeepVerifierDiagnosticOutOfVisibleOutput()
        {
            string gui = File.ReadAllText(RepoFile("src", "App", "MainForm.cs"));
            Assert.Contains("LogWarning(\"  \" + LicenseGate.ReasonText(info));", gui, StringComparison.Ordinal);
            Assert.Contains("SessionLog.Write(\"  \" + info.VerifierDiagnostic, LogLevel.Debug);", gui, StringComparison.Ordinal);
            Assert.DoesNotContain("Log(\"  \" + info.VerifierDiagnostic", gui, StringComparison.Ordinal);

            string cli = File.ReadAllText(RepoFile("src", "App", "Cli.cs"));
            Assert.Contains("Err(LicenseGate.ReasonText(info));", cli, StringComparison.Ordinal);
            Assert.Contains("SessionLog.Write(info.VerifierDiagnostic, LogLevel.Debug);", cli, StringComparison.Ordinal);
            Assert.DoesNotContain("Err(info.VerifierDiagnostic", cli, StringComparison.Ordinal);
        }

        /// <summary>Момент проверки в тестах и просроченный срок из прошлого (2023-11-14).</summary>
        private const long Now = 1765000000;

        private const long Expired = 1700000000;

        private static Dictionary<string, string> Keys(ECDsa signer) =>
            new() { [LicenseGate.Kid] = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo()) };

        private static string RepoFile(params string[] parts)
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CryptoProExport.slnx")))
                dir = dir.Parent;
            Assert.NotNull(dir);

            string path = dir!.FullName;
            foreach (string part in parts) path = Path.Combine(path, part);
            Assert.True(File.Exists(path), "Не найден файл " + path);
            return path;
        }

        /// <summary>Собирает compact JWS ES256 (PROTOCOL §2) тестовым ключом.</summary>
        private static string BuildLicense(ECDsa signer, string kid, string pid, string plat, string fp, bool expNull) =>
            BuildLicense(signer, kid, pid, plat, fp, expNull ? null : 1900000000L);

        /// <summary>То же, но со своим сроком: <c>null</c> — бессрочная, иначе term до этой отметки.</summary>
        private static string BuildLicense(ECDsa signer, string kid, string pid, string plat, string fp, long? until)
        {
            string header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
            string exp = until is long stamp ? stamp.ToString(CultureInfo.InvariantCulture) : "null";
            string typ = until is null ? "perpetual" : "term";
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
