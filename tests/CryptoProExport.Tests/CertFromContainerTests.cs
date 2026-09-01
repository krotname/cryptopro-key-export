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

        [Fact]
        public void ProbeContainer_DoesNotOpenAnInventedName()
        {
            // Промах по имени — единственный случай, воспроизводимый без CSP и токена.
            // Он же и был перепутан: «нет такого контейнера» выглядело как «ключа нет».
            var probe = CertFromContainer.ProbeContainer(
                "контейнер, которого нет " + Guid.NewGuid().ToString("N"));

            Assert.False(probe.ContainerOpened);
        }

        [Fact]
        public void IsMissingContainer_AcceptsOnlyTheAbsentKeysetCodes()
        {
            // Право сказать «контейнера нет» дают только эти два кода. NTE_SILENT_CONTEXT —
            // это «носителю нужен диалог PIN», то есть контейнер, возможно, на месте
            // (замечание Codex на PR #84).
            Assert.True(CertFromContainer.IsMissingContainer(unchecked((int)0x80090016)));   // NTE_BAD_KEYSET
            Assert.True(CertFromContainer.IsMissingContainer(unchecked((int)0x80090019)));   // NTE_KEYSET_NOT_DEF
            Assert.False(CertFromContainer.IsMissingContainer(unchecked((int)0x80090022)));  // NTE_SILENT_CONTEXT
            Assert.False(CertFromContainer.IsMissingContainer(unchecked((int)0x8010000C)));  // SCARD_E_NOT_TRANSACTED
            Assert.False(CertFromContainer.IsMissingContainer(0));
        }

        [Fact]
        public void CheckExportable_ReportsThatTheContainerNeverOpened()
        {
            var check = CertFromContainer.CheckExportable(
                "контейнер, которого нет " + Guid.NewGuid().ToString("N"));

            Assert.False(check.ContainerOpened);
            Assert.False(check.KeyFound);
        }

        [Fact]
        public void Cli_AsksAboutTheContainerBeforeReportingMissingKeys()
        {
            // Порядок важен: сообщение «ключ не найден» имеет смысл только для контейнера,
            // который открылся. Проверяем проводку, потому что сам вызов требует CSP.
            string cli = File.ReadAllText(RepoFile("src", "App", "Cli.cs"));

            Assert.Contains("CertFromContainer.ProbeContainer(args[1])", cli, StringComparison.Ordinal);
            Assert.Contains("!ex.ContainerOpened && !sg.ContainerOpened", cli, StringComparison.Ordinal);
            // «Не найден» печатается только на кодах «нет такого контейнера»; остальные отказы
            // идут своим текстом с расшифровкой кода.
            Assert.Contains("err.container.missing", cli, StringComparison.Ordinal);
            Assert.Contains("err.container.openfail", cli, StringComparison.Ordinal);
            Assert.Contains("CertFromContainer.IsMissingContainer(error)", cli, StringComparison.Ordinal);
        }

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

        [Fact]
        public void AllFoundKeysExportable_AcceptsTwoExportableKeysButRejectsReadError()
        {
            var exchange = new CertFromContainer.ExportCheck { KeyFound = true, Exportable = true };
            var signature = new CertFromContainer.ExportCheck { KeyFound = true, Exportable = true };

            Assert.True(CertFromContainer.AllFoundKeysExportable(exchange, signature));

            signature.Error = unchecked((int)0x8009000B);
            Assert.False(CertFromContainer.AllFoundKeysExportable(exchange, signature));
        }
    }
}
