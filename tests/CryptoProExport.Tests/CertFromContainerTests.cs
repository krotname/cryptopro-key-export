using System;
using System.IO;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Извлечение сертификата из контейнера. Реального контейнера тут нет — проверяется
    /// поведение на промахе, то есть ровно то, что видит пользователь без токена и без CSP.
    /// </summary>
    public class CertFromContainerTests
    {
        [Fact]
        public void SaveCerts_DoesNotCreateFolderWhenNothingExtracted()
        {
            // Пустая папка после неудачи читается как «что-то сохранилось»,
            // хотя не сохранилось ничего: до правки каталог создавался всегда.
            string dir = Path.Combine(Path.GetTempPath(), "cpx-nocert-" + Guid.NewGuid().ToString("N"));
            try
            {
                var (exchange, signature) = CertFromContainer.SaveCerts(
                    "контейнер, которого нет " + Guid.NewGuid().ToString("N"), dir);

                Assert.Null(exchange);
                Assert.Null(signature);
                Assert.False(Directory.Exists(dir));
            }
            finally
            {
                // DirectoryNotFoundException — тоже IOException, отдельная ветка не нужна
                try { Directory.Delete(dir, recursive: true); } catch (IOException) { }
            }
        }

        [Fact]
        public void AllFoundKeysExportable_RejectsMixedContainer()
        {
            var exchange = new CertFromContainer.ExportCheck { KeyFound = true, Exportable = true };
            var signature = new CertFromContainer.ExportCheck { KeyFound = true, Exportable = false };

            Assert.False(CertFromContainer.AllFoundKeysExportable(exchange, signature));
            Assert.True(CertFromContainer.AllFoundKeysExportable(exchange,
                new CertFromContainer.ExportCheck { KeyFound = false }));
            Assert.False(CertFromContainer.AllFoundKeysExportable(
                new CertFromContainer.ExportCheck { KeyFound = false }));
        }
    }
}
