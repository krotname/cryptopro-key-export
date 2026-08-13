using System;
using System.IO;
using System.Linq;
using CryptoProExport;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Сборка PKCS#12 своими силами. Проверка круговая и на синтетике: контейнер собирается тем
    /// же кодом, что и разбирается (см. <see cref="ContainerKeyExtractorTests"/>), из него
    /// строится .pfx, затем .pfx читается обратно независимым разбором BouncyCastle — так
    /// проверяются сразу имитовставка, PBE, структура мешков, ключ и сертификат.
    /// </summary>
    public class Pkcs12ExportTests
    {
        private const string PfxPassword = "pfx-пароль";

        [Fact]
        public void Pfx_RoundTripsThroughBouncyCastle()
        {
            string dir = NewTempDir();
            try
            {
                var built = ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 3, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");

                byte[] pfx = Pkcs12Export.Build(result, PfxPassword, friendlyName: "тест");

                var store = new Pkcs12StoreBuilder().Build();   // сам проверит имитовставку файла
                store.Load(new MemoryStream(pfx), PfxPassword.ToCharArray());

                string alias = store.Aliases.Single();
                Assert.True(store.IsKeyEntry(alias));

                var priv = (ECPrivateKeyParameters)store.GetKey(alias).Key;
                Assert.Equal(new BigInteger(1, built.PrivateKey), priv.D);

                byte[] cert = store.GetCertificate(alias).Certificate.GetEncoded();
                Assert.Equal(built.Certificate, cert);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Pfx_WrongPassword_IsRejected()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 4, password: "");
                byte[] pfx = Pkcs12Export.Build(ContainerKeyExtractor.Extract(dir, ""), PfxPassword);

                var store = new Pkcs12StoreBuilder().Build();
                Assert.ThrowsAny<Exception>(() => store.Load(new MemoryStream(pfx), "не тот".ToCharArray()));
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Pfx_KeyIsShroudedNotPlain()
        {
            string dir = NewTempDir();
            try
            {
                var built = ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 6, password: "");
                byte[] pfx = Pkcs12Export.Build(ContainerKeyExtractor.Extract(dir, ""), PfxPassword);

                // Закрытый ключ не должен встречаться в файле открытым текстом — иначе пароль
                // .pfx не защищал бы ничего, а тест выше этого бы не заметил.
                string hex = Convert.ToHexString(pfx);
                Assert.DoesNotContain(Convert.ToHexString(built.PrivateKey), hex, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToHexString(built.PrivateKey.Reverse().ToArray()), hex,
                                      StringComparison.Ordinal);
                var outer = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(pfx));
                Assert.Equal(3, DerInteger.GetInstance(outer[0]).IntValueExact);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Build_ForeignCertificate_IsRejected()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 8, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");

                // Сертификат чужого ключа: собранный с ним .pfx выглядел бы рабочим и не работал
                byte[] alien = ContainerKeyExtractorTests.FakeCertificate(
                    new byte[32], new byte[32], "CN=alien");

                var ex = Assert.Throws<ContainerKeyException>(
                    () => Pkcs12Export.Build(result, PfxPassword, alien));
                Assert.Equal(Strings.Get("err.pfx.certmismatch"), ex.Message);
            }
            finally { TryDelete(dir); }
        }

        [Fact]
        public void Build_WithoutAnyCertificate_ExplainsWhatIsMissing()
        {
            string dir = NewTempDir();
            try
            {
                ContainerKeyExtractorTests.BuildSyntheticContainer(dir, seed: 9, password: "");
                var result = ContainerKeyExtractor.Extract(dir, "");
                result.Certificate = null;      // контейнер без сертификата — так тоже бывает

                var ex = Assert.Throws<ContainerKeyException>(() => Pkcs12Export.Build(result, PfxPassword));
                Assert.Equal(Strings.Get("err.pfx.nocert"), ex.Message);
            }
            finally { TryDelete(dir); }
        }

        private static string NewTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-pfx-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
