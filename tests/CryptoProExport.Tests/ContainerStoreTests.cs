using System;
using System.IO;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Установка контейнера в хранилище CSP. Тесты работают во временной папке,
    /// системное хранилище КриптоПро не трогается (и проверка видимости в CSP не запускается).
    /// </summary>
    public class ContainerStoreTests : IDisposable
    {
        private readonly string _root;
        private readonly string _source;
        private readonly string _store;

        public ContainerStoreTests()
        {
            _root = Path.Combine(Path.GetTempPath(), "cpx-tests-" + Guid.NewGuid().ToString("N"));
            _source = Path.Combine(_root, "source");
            _store = Path.Combine(_root, "store");
            Directory.CreateDirectory(_source);

            foreach (string f in ContainerStore.ContainerFiles)
                File.WriteAllBytes(Path.Combine(_source, f), new byte[] { 1, 2, 3 });
            File.WriteAllBytes(Path.Combine(_source, "name.key"), NameKey.Build("исходное имя"));
            // мусор, который не должен попасть в хранилище
            File.WriteAllBytes(Path.Combine(_source, "header.key.backup"), new byte[] { 9 });
            File.WriteAllBytes(Path.Combine(_source, "cert_exchange.cer"), new byte[] { 9 });
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
        }

        [Fact]
        public void LooksLikeContainer_RequiresKeyFiles()
        {
            Assert.True(ContainerStore.LooksLikeContainer(_source));

            string empty = Path.Combine(_root, "empty");
            Directory.CreateDirectory(empty);
            Assert.False(ContainerStore.LooksLikeContainer(empty));
            Assert.False(ContainerStore.LooksLikeContainer(Path.Combine(_root, "нет такой папки")));
        }

        [Fact]
        public void ReadName_TakesNameFromNameKey()
        {
            Assert.Equal("исходное имя", ContainerStore.ReadName(_source));
            Assert.Null(ContainerStore.ReadName(Path.Combine(_root, "нет такой папки")));
        }

        [Fact]
        public void Install_CopiesOnlyKeyFiles()
        {
            var result = ContainerStore.Install(_source, storeDir: _store);

            Assert.True(Directory.Exists(result.Folder));
            Assert.EndsWith(".000", result.Folder);

            var names = Directory.GetFiles(result.Folder).Select(Path.GetFileName).OrderBy(n => n).ToArray();
            Assert.Equal(ContainerStore.ContainerFiles.OrderBy(n => n).ToArray(), names);
        }

        [Fact]
        public void Install_KeepsOriginalNameByDefault()
        {
            // По умолчанию имя не трогаем: CSP сверяет name.key с содержимым контейнера
            var result = ContainerStore.Install(_source, storeDir: _store);

            Assert.False(result.Renamed);
            Assert.Equal("исходное имя", result.Name);
            Assert.Equal("исходное имя", NameKey.Parse(File.ReadAllBytes(Path.Combine(result.Folder, "name.key"))));
        }

        [Fact]
        public void Install_RenamesWhenAsked()
        {
            var result = ContainerStore.Install(_source, "Новое имя", _store);

            Assert.True(result.Renamed);
            Assert.Equal("Новое имя", result.Name);
            Assert.Equal("Новое имя", NameKey.Parse(File.ReadAllBytes(Path.Combine(result.Folder, "name.key"))));
        }

        [Fact]
        public void Install_DoesNotVerifyForCustomStore()
        {
            // Проверка видимости имеет смысл только для системного хранилища
            Assert.False(ContainerStore.Install(_source, storeDir: _store).Verified);
        }

        [Fact]
        public void Install_TwiceGivesDifferentFolders()
        {
            var first = ContainerStore.Install(_source, "дубль", _store);
            var second = ContainerStore.Install(_source, "дубль", _store);
            Assert.NotEqual(first.Folder, second.Folder);
            Assert.EndsWith(".000", first.Folder);
            Assert.EndsWith(".001", second.Folder);
        }

        [Fact]
        public void Installed_ListsContainersByNameFromNameKey()
        {
            ContainerStore.Install(_source, "контейнер один", _store);
            ContainerStore.Install(_source, "контейнер два", _store);

            var installed = ContainerStore.Installed(_store);
            Assert.Equal(2, installed.Count);
            Assert.Contains(installed, c => c.Name == "контейнер один");
            Assert.Contains(installed, c => c.Name == "контейнер два");
        }

        [Fact]
        public void Installed_EmptyWhenStoreMissing()
        {
            Assert.Empty(ContainerStore.Installed(Path.Combine(_root, "ещё не создано")));
        }

        [Fact]
        public void Uninstall_RemovesInstalledContainer()
        {
            var installed = ContainerStore.Install(_source, "на удаление", _store);
            Assert.True(ContainerStore.Uninstall(installed.Folder, _store));
            Assert.False(Directory.Exists(installed.Folder));
        }

        [Fact]
        public void Uninstall_RefusesFolderOutsideStore()
        {
            Assert.Throws<ArgumentException>(() => ContainerStore.Uninstall(_source, _store));
        }

        [Fact]
        public void Uninstall_RefusesFolderWithForeignFiles()
        {
            var installed = ContainerStore.Install(_source, "с посторонним файлом", _store);
            File.WriteAllText(Path.Combine(installed.Folder, "важный.txt"), "не удалять");
            Assert.Throws<InvalidOperationException>(() => ContainerStore.Uninstall(installed.Folder, _store));
            Assert.True(Directory.Exists(installed.Folder));
        }

        [Fact]
        public void Install_RejectsFolderWithoutContainer()
        {
            string empty = Path.Combine(_root, "пусто");
            Directory.CreateDirectory(empty);
            Assert.Throws<DirectoryNotFoundException>(() => ContainerStore.Install(empty, "имя", _store));
        }

        [Theory]
        [InlineData("обычное", "обычное")]
        [InlineData("с/косой\\чертой", "с_косой_чертой")]
        [InlineData("точка.в.имени", "точка_в_имени")]
        public void Sanitize_MakesSafeFolderName(string input, string expected)
        {
            Assert.Equal(expected, ContainerStore.Sanitize(input));
        }
    }
}
