using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace CryptoProExport.Tests
{
    public class Pkcs8ContainerRestoreTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RestoreToDirectory_RoundTripsGostKeyExportAndCertificate(bool pem)
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built source = SyntheticContainer.Build(404, "source-pass");
                ContainerKeyExtractor.Result extracted = ContainerKeyExtractor.Extract(
                    source.Files(), "source-pass");
                byte[] key = pem
                    ? Encoding.UTF8.GetBytes(GostKeyExport.ToPkcs8Pem(extracted))
                    : GostKeyExport.ToPkcs8Der(extracted);
                string keyPath = Path.Combine(root, pem ? "private.pem" : "private.der");
                string certPath = Path.Combine(root, pem ? "certificate.pem" : "certificate.cer");
                string target = Path.Combine(root, "restored-container");
                File.WriteAllBytes(keyPath, key);
                File.WriteAllBytes(certPath, pem ? CertificatePem(source.Certificate) : source.Certificate);

                Pkcs8ContainerRestoreResult result = Pkcs8ContainerRestore.RestoreToDirectory(
                    keyPath, certPath, target, "new-pass");

                Assert.Equal(Path.GetFullPath(target), result.Directory);
                Assert.Equal("restored-container", result.ContainerName);
                Assert.Equal(SyntheticContainer.CurveOid, result.CurveOid);
                Assert.Equal(source.PublicX, result.PublicX);
                Assert.Equal("restored-container", NameKey.Parse(File.ReadAllBytes(
                    Path.Combine(target, "name.key"))));
                Assert.Equal(4, Directory.GetFiles(target, "*.key").Length);
                CryptoProHeaderExportability.RequireExportable(
                    File.ReadAllBytes(Path.Combine(target, "header.key")), true, false);

                ContainerKeyExtractor.Result restored = ContainerKeyExtractor.Extract(target, "new-pass");
                try
                {
                    Assert.Equal(source.PrivateKey, restored.PrivateKey);
                    Assert.Equal(source.PublicX, restored.PublicX);
                    Assert.Equal(source.PublicY, restored.PublicY);
                    Assert.Equal(source.Certificate, restored.Certificate);
                }
                finally { CryptographicOperations.ZeroMemory(restored.PrivateKey); }
                AssertNoTemporaryDirectories(root);

                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(extracted.PrivateKey);
            }
            finally { TryDelete(root); }
        }

        [Fact]
        public void RestoreToDirectory_RejectsDifferentCertificateWithoutPartialOutput()
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built keyOwner = SyntheticContainer.Build(405, "");
                SyntheticContainer.Built other = SyntheticContainer.Build(406, "");
                ContainerKeyExtractor.Result extracted = ContainerKeyExtractor.Extract(keyOwner.Files());
                string keyPath = Path.Combine(root, "private.pem");
                string certPath = Path.Combine(root, "other.cer");
                string target = Path.Combine(root, "target");
                File.WriteAllText(keyPath, GostKeyExport.ToPkcs8Pem(extracted));
                File.WriteAllBytes(certPath, other.Certificate);

                var error = Assert.Throws<ContainerKeyException>(() =>
                    Pkcs8ContainerRestore.RestoreToDirectory(keyPath, certPath, target));

                Assert.Contains("не соответствует", error.Message, StringComparison.Ordinal);
                Assert.False(Directory.Exists(target));
                AssertNoTemporaryDirectories(root);
                CryptographicOperations.ZeroMemory(extracted.PrivateKey);
            }
            finally { TryDelete(root); }
        }

        [Theory]
        [InlineData("broken")]
        [InlineData("encrypted")]
        public void RestoreToDirectory_RejectsBrokenOrEncryptedPkcs8WithoutPartialOutput(string kind)
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built source = SyntheticContainer.Build(407, "");
                string keyPath = Path.Combine(root, "private.pem");
                string certPath = Path.Combine(root, "certificate.cer");
                string target = Path.Combine(root, "target");
                string body = kind == "encrypted"
                    ? "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAQID\n-----END ENCRYPTED PRIVATE KEY-----\n"
                    : "-----BEGIN PRIVATE KEY-----\nnot-base64\n-----END PRIVATE KEY-----\n";
                File.WriteAllText(keyPath, body);
                File.WriteAllBytes(certPath, source.Certificate);

                Assert.Throws<ContainerKeyException>(() =>
                    Pkcs8ContainerRestore.RestoreToDirectory(keyPath, certPath, target));

                Assert.False(Directory.Exists(target));
                AssertNoTemporaryDirectories(root);
            }
            finally { TryDelete(root); }
        }

        [Fact]
        public void Build_RejectsUnsupportedPrivateKeyAlgorithm()
        {
            SyntheticContainer.Built source = SyntheticContainer.Build(408, "");
            byte[] unsupported = new PrivateKeyInfo(
                new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption),
                new DerOctetString(new byte[32])).GetEncoded(Asn1Encodable.Der);

            var error = Assert.Throws<ContainerKeyException>(() =>
                Pkcs8ContainerRestore.Build(unsupported, source.Certificate, "restored"));

            Assert.Contains(PkcsObjectIdentifiers.RsaEncryption.Id, error.Message,
                StringComparison.Ordinal);
        }

        [Fact]
        public void RestoreToDirectory_RejectsCurveMismatchWithoutPartialOutput()
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built source = SyntheticContainer.Build(410, "");
                const string otherCurve = "1.2.643.7.1.2.1.1.1";
                var algorithm = new AlgorithmIdentifier(
                    new DerObjectIdentifier("1.2.643.7.1.1.1.1"),
                    new DerSequence(new DerObjectIdentifier(otherCurve),
                        new DerObjectIdentifier("1.2.643.7.1.1.2.2")));
                byte[] key = new PrivateKeyInfo(algorithm,
                    new DerOctetString(SyntheticContainer.Reverse(source.PrivateKey)))
                    .GetEncoded(Asn1Encodable.Der);
                string keyPath = Path.Combine(root, "private.der");
                string certPath = Path.Combine(root, "certificate.cer");
                string target = Path.Combine(root, "target");
                File.WriteAllBytes(keyPath, key);
                File.WriteAllBytes(certPath, source.Certificate);

                var error = Assert.Throws<ContainerKeyException>(() =>
                    Pkcs8ContainerRestore.RestoreToDirectory(keyPath, certPath, target));

                Assert.Contains("Кривая", error.Message, StringComparison.Ordinal);
                Assert.False(Directory.Exists(target));
                AssertNoTemporaryDirectories(root);
                CryptographicOperations.ZeroMemory(key);
            }
            finally { TryDelete(root); }
        }

        [Fact]
        public void RestoreToDirectory_RejectsCorruptedCertificateWithoutPartialOutput()
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built source = SyntheticContainer.Build(411, "");
                ContainerKeyExtractor.Result extracted = ContainerKeyExtractor.Extract(source.Files());
                string keyPath = Path.Combine(root, "private.pem");
                string certPath = Path.Combine(root, "certificate.cer");
                string target = Path.Combine(root, "target");
                File.WriteAllText(keyPath, GostKeyExport.ToPkcs8Pem(extracted));
                File.WriteAllBytes(certPath, new byte[] { 0x30, 0x01, 0x00 });

                Assert.Throws<ContainerKeyException>(() =>
                    Pkcs8ContainerRestore.RestoreToDirectory(keyPath, certPath, target));

                Assert.False(Directory.Exists(target));
                AssertNoTemporaryDirectories(root);
                CryptographicOperations.ZeroMemory(extracted.PrivateKey);
            }
            finally { TryDelete(root); }
        }

        [Fact]
        public void RestoreToDirectory_DoesNotOverwriteExistingTarget()
        {
            string root = NewTempDir();
            try
            {
                SyntheticContainer.Built source = SyntheticContainer.Build(409, "");
                ContainerKeyExtractor.Result extracted = ContainerKeyExtractor.Extract(source.Files());
                string keyPath = Path.Combine(root, "private.pem");
                string certPath = Path.Combine(root, "certificate.cer");
                string target = Path.Combine(root, "target");
                Directory.CreateDirectory(target);
                string marker = Path.Combine(target, "keep.txt");
                File.WriteAllText(marker, "keep");
                File.WriteAllText(keyPath, GostKeyExport.ToPkcs8Pem(extracted));
                File.WriteAllBytes(certPath, source.Certificate);

                Assert.Throws<ContainerKeyException>(() =>
                    Pkcs8ContainerRestore.RestoreToDirectory(keyPath, certPath, target));

                Assert.Equal("keep", File.ReadAllText(marker));
                Assert.Single(Directory.GetFiles(target));
                AssertNoTemporaryDirectories(root);
                CryptographicOperations.ZeroMemory(extracted.PrivateKey);
            }
            finally { TryDelete(root); }
        }

        private static byte[] CertificatePem(byte[] der) => Encoding.ASCII.GetBytes(
            "-----BEGIN CERTIFICATE-----\n" + Convert.ToBase64String(der,
                Base64FormattingOptions.InsertLineBreaks) + "\n-----END CERTIFICATE-----\n");

        private static void AssertNoTemporaryDirectories(string root) =>
            Assert.Empty(Directory.GetDirectories(root, ".*.restore-*.tmp"));

        private static string NewTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-restore-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDelete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
