using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using CryptoProExport;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// CSP-free «сделать экспортируемым»: из контейнера собирается новая папка, где в header.key
    /// взведён бит экспорта и пересчитана имитовставка. Круговая проверка: тем же экстрактором
    /// из копии обязан восстановиться исходный d, иначе ключ потерян. Проверяются оба режима
    /// ключевых файлов — перенос как есть (по умолчанию, его принимает КриптоПро) и пересборка
    /// со свежей маской (паритет с Android-ядром). Ни живого токена, ни персональных данных
    /// здесь нет: контейнер синтетический (<see cref="SyntheticContainer"/>), seed-ы те же,
    /// что в тестах Android-порта.
    /// </summary>
    public class ExportableContainerBuilderTests
    {
        [Fact]
        public void Build_Remask_RebuildsWithFreshMaskAndSetsVerifiedExportFlag()
        {
            var source = SyntheticContainer.Build(seed: 31, password: "secret");
            var rebuilt = ExportableContainerBuilder.Build(
                source.Files(), "secret", ExportableKeyFiles.Remask, Counter(1));

            // Маска и шифротекст обязаны смениться, имя контейнера — остаться прежним:
            // КриптоПро сверяет name.key с содержимым папки (AGENTS, п. 11).
            Assert.NotEqual(source.FileBytes["primary.key"], rebuilt.Require("primary.key"));
            Assert.NotEqual(source.FileBytes["masks.key"], rebuilt.Require("masks.key"));
            Assert.Equal(source.FileBytes["name.key"], rebuilt.Require("name.key"));
            CryptoProHeaderExportability.RequireExportable(
                rebuilt.Require("header.key"), exchange: true, signature: false);

            var key = ContainerKeyExtractor.Extract(rebuilt, "secret");
            Assert.Equal(source.PrivateKey, key.PrivateKey);
            Assert.Equal(source.PublicX, key.PublicX);
            Assert.Equal(source.PublicY, key.PublicY);
            Assert.True(key.FingerprintVerified);
        }

        [Fact]
        public void Build_Remask_RebuildsAndVerifiesBothIndependentKeys()
        {
            var source = SyntheticContainer.BuildDual(seed: 70, password: "");
            var rebuilt = ExportableContainerBuilder.Build(
                source.Files(), "", ExportableKeyFiles.Remask, Counter(17, step: 13));

            CryptoProHeaderExportability.RequireExportable(
                rebuilt.Require("header.key"), exchange: true, signature: true);

            var keys = ContainerKeyExtractor.ExtractAll(rebuilt, "");
            var exchange = keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Exchange).Result;
            var signature = keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Signature).Result;
            Assert.Equal(source.Exchange.PrivateKey, exchange.PrivateKey);
            Assert.Equal(source.Signature.PrivateKey, signature.PrivateKey);
            Assert.Equal(source.Exchange.PublicX, exchange.PublicX);
            Assert.Equal(source.Signature.PublicX, signature.PublicX);
            // Ключи независимые: перепутанная пара дала бы совпадение с чужим d.
            Assert.NotEqual(source.Exchange.PrivateKey, source.Signature.PrivateKey);
        }

        [Fact]
        public void Build_Remask_SignatureOnlyContainerWithoutSecondaryHeaderUsesPrimaryExportFlag()
        {
            var source = SyntheticContainer.Build(seed: 91, password: "");
            var signatureOnly = ContainerFiles.Of(new Dictionary<string, byte[]>
            {
                ["primary2.key"] = source.FileBytes["primary.key"],
                ["masks2.key"] = source.FileBytes["masks.key"],
                ["header.key"] = source.FileBytes["header.key"],
                ["name.key"] = source.FileBytes["name.key"],
            });

            var rebuilt = ExportableContainerBuilder.Build(signatureOnly, "", ExportableKeyFiles.Remask);

            CryptoProHeaderExportability.RequireExportable(
                rebuilt.Require("header.key"), exchange: false, signature: true);
            Assert.False(rebuilt.Has("primary.key"));
            var key = ContainerKeyExtractor.ExtractAll(rebuilt).Single();
            Assert.Equal(ContainerKeyExtractor.KeyUsage.Signature, key.Usage);
            Assert.Equal(source.PrivateKey, key.Result.PrivateKey);
        }

        [Fact]
        public void Build_RejectsHeaderWithInvalidMacBeforeRewrappingKey()
        {
            var source = SyntheticContainer.Build(seed: 101, password: "");
            var corrupted = new Dictionary<string, byte[]>(source.FileBytes);
            byte[] header = (byte[])corrupted["header.key"].Clone();
            header[header.Length - 1] ^= 0x01;                 // испорчен последний байт имитовставки
            corrupted["header.key"] = header;

            var ex = Assert.Throws<ContainerKeyException>(
                () => ExportableContainerBuilder.Build(ContainerFiles.Of(corrupted), ""));
            Assert.Contains("MAC mismatch", ex.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void Build_ByDefaultKeepsKeyFilesByteForByte()
        {
            var source = SyntheticContainer.BuildDual(seed: 44, password: "");

            var rebuilt = ExportableContainerBuilder.Build(source.Files(), "");

            // Режим по умолчанию меняет ровно один файл — заголовок. Ключевые файлы обязаны
            // остаться прежними: в неэкспортируемой форме primary.key рабочее для CSP поле —
            // первое, и пересборка ключей лишает КриптоПро возможности выгрузить PFX.
            foreach (string name in new[] { "primary.key", "masks.key", "primary2.key", "masks2.key", "name.key" })
                Assert.Equal(source.FileBytes[name], rebuilt.Require(name));
            Assert.NotEqual(source.FileBytes["header.key"], rebuilt.Require("header.key"));
            CryptoProHeaderExportability.RequireExportable(
                rebuilt.Require("header.key"), exchange: true, signature: true);

            var keys = ContainerKeyExtractor.ExtractAll(rebuilt, "");
            Assert.Equal(source.Exchange.PrivateKey,
                keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Exchange).Result.PrivateKey);
            Assert.Equal(source.Signature.PrivateKey,
                keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Signature).Result.PrivateKey);
        }

        [Fact]
        public void Build_WrongPassword_Throws()
        {
            var source = SyntheticContainer.Build(seed: 55, password: "правильный");

            // Неверный пароль даёт другой ключ хранения → d·G не сойдётся с отпечатком,
            // и до правки заголовка дело не доходит.
            Assert.Throws<ContainerKeyException>(
                () => ExportableContainerBuilder.Build(source.Files(), "неверный"));
        }

        [Fact]
        public void Build_Remask_TwiceGivesDifferentMasksForTheSameKey()
        {
            var source = SyntheticContainer.Build(seed: 12, password: "");

            var first = ExportableContainerBuilder.Build(source.Files(), "", ExportableKeyFiles.Remask);
            var second = ExportableContainerBuilder.Build(source.Files(), "", ExportableKeyFiles.Remask);

            // Маска каждый раз свежая, а восстановленный ключ — один и тот же.
            Assert.NotEqual(first.Require("masks.key"), second.Require("masks.key"));
            Assert.NotEqual(first.Require("primary.key"), second.Require("primary.key"));
            Assert.Equal(ContainerKeyExtractor.Extract(first, "").PrivateKey,
                         ContainerKeyExtractor.Extract(second, "").PrivateKey);
        }

        [Fact]
        public void Build_KeepsTheSourceFolderUntouchedAndWritesANewOne()
        {
            string sourceDir = NewTempDir();
            string outDir = sourceDir + "-exportable";
            try
            {
                var built = SyntheticContainer.BuildDual(seed: 5, password: "секрет");
                foreach (var pair in built.FileBytes)
                    File.WriteAllBytes(Path.Combine(sourceDir, pair.Key), pair.Value);
                var before = Snapshot(sourceDir);

                var rebuilt = ExportableContainerBuilder.Build(
                    ContainerFiles.FromDirectory(sourceDir), "секрет");
                rebuilt.WriteTo(outDir);

                // Исходная папка не тронута — это главное обещание команды.
                Assert.Equal(before, Snapshot(sourceDir));

                var keys = ContainerKeyExtractor.ExtractAll(outDir, "секрет");
                Assert.Equal(2, keys.Count);
                Assert.Equal(built.Exchange.PrivateKey,
                    keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Exchange).Result.PrivateKey);
                Assert.Equal(built.Signature.PrivateKey,
                    keys.Single(k => k.Usage == ContainerKeyExtractor.KeyUsage.Signature).Result.PrivateKey);
                CryptoProHeaderExportability.RequireExportable(
                    File.ReadAllBytes(Path.Combine(outDir, "header.key")), exchange: true, signature: true);

                // Повторный запуск в ту же папку — отказ, а не молчаливая перезапись чужого ключа.
                Assert.Throws<ContainerKeyException>(() => rebuilt.WriteTo(outDir));
            }
            finally
            {
                TryDelete(sourceDir);
                TryDelete(outDir);
            }
        }

        [Fact]
        public void SetExportable_KeepsEverythingExceptTheExportBitAndMac()
        {
            var source = SyntheticContainer.Build(seed: 64, password: "");
            byte[] header = source.FileBytes["header.key"];

            byte[] changed = CryptoProHeaderExportability.SetExportable(header, exchange: true, signature: false);

            Assert.Equal(header.Length, changed.Length);
            // Ровно два байта: атрибуты ключа и один из четырёх байт имитовставки могут совпасть,
            // поэтому проверяется не число различий, а сам факт взведённого бита и целостность.
            Assert.NotEqual(header, changed);
            CryptoProHeaderExportability.RequireExportable(changed, exchange: true, signature: false);
            Assert.Throws<ContainerKeyException>(
                () => CryptoProHeaderExportability.RequireExportable(header, exchange: true, signature: false));
        }

        [Fact]
        public void SetExportable_IsIdempotent()
        {
            var source = SyntheticContainer.Build(seed: 77, password: "");
            byte[] once = CryptoProHeaderExportability.SetExportable(
                source.FileBytes["header.key"], exchange: true, signature: false);

            byte[] twice = CryptoProHeaderExportability.SetExportable(once, exchange: true, signature: false);

            Assert.Equal(once, twice);
        }

        [Fact]
        public void MaskMac_TakesTheSecondHalfOfALongMask()
        {
            byte[] salt = new byte[12];
            byte[] shortMask = new byte[32];
            byte[] longMask = new byte[64];
            for (int i = 0; i < 32; i++) { shortMask[i] = (byte)(i + 1); longMask[32 + i] = (byte)(i + 1); }

            Assert.Equal(GostContainerCrypto.MaskMac(shortMask, salt), GostContainerCrypto.MaskMac(longMask, salt));
            Assert.Equal(4, GostContainerCrypto.MaskMac(shortMask, salt).Length);
            Assert.Throws<ContainerKeyException>(() => GostContainerCrypto.MaskMac(new byte[16], salt));
        }

        /// <summary>
        /// Детерминированный «ГПСЧ» тестов: те же значения, что подставляет Kotlin-тест
        /// Android-порта, чтобы сравнивать не только результат, но и промежуточные байты.
        /// </summary>
        private static Action<byte[]> Counter(int start, int step = 1)
        {
            int next = start;
            return bytes =>
            {
                for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(next++ * step);
            };
        }

        private static List<string> Snapshot(string dir) =>
            Directory.GetFiles(dir).OrderBy(p => p, StringComparer.Ordinal)
                     .Select(p => Path.GetFileName(p) + ":" + Convert.ToHexString(File.ReadAllBytes(p)))
                     .ToList();

        private static string NewTempDir()
        {
            string dir = Path.Combine(Path.GetTempPath(), "cpx-exportable-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void TryDelete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); } catch (IOException) { }
        }
    }
}
