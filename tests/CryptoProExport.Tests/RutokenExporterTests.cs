using System;
using System.IO;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Запись снятого с токена контейнера на диск. Токена здесь нет: проверяется только
    /// чистая логика имени папки — её задаёт <c>name.key</c> с токена, то есть данные,
    /// а не пользователь.
    /// </summary>
    public class RutokenExporterTests : IDisposable
    {
        private readonly string _root;

        public RutokenExporterTests()
        {
            _root = Path.Combine(Path.GetTempPath(), "cpx-rt-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_root);
        }

        public void Dispose()
        {
            try { Directory.Delete(_root, recursive: true); } catch (IOException) { }
        }

        [Theory]
        // Смарт-карточные Рутокены обходить нельзя: на ЭЦП 3.0 ReadBinary рушит кучу процесса
        // (0xC0000374), а контейнеров в файловой памяти у них всё равно нет.
        [InlineData("Aktiv Rutoken ECP 0", false)]
        [InlineData("Aktiv Rutoken lite 0", false)]
        [InlineData("Aktiv ruToken 0", true)]      // Рутокен S — ровно тот случай, ради которого обход и нужен
        [InlineData("Generic Smart Card Reader 0", true)]
        [InlineData("", false)]
        [InlineData(null, false)]
        public void ShouldWalk_SkipsSmartCardRutokensByReaderName(string reader, bool expected)
        {
            Assert.Equal(expected, RutokenExporter.ShouldWalk(reader, null));
        }

        [Fact]
        public void ShouldWalk_HonoursExplicitSkipList()
        {
            // Имя считывателя ни о чём не говорит, а PKCS#11 уже определил модель — верим ему.
            var skip = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ACS ACR38U 0",
            };
            Assert.False(RutokenExporter.ShouldWalk("acs acr38u 0", skip));
            Assert.True(RutokenExporter.ShouldWalk("ACS ACR38U 1", skip));
        }

        [Theory]
        [InlineData("Иванов", "Иванов")]
        [InlineData(@"a/b\c:d", "a_b_c_d")]
        [InlineData("", "container")]
        [InlineData(null, "container")]
        [InlineData("   ", "container")]
        [InlineData("..", "container")]     // GetInvalidFileNameChars не считает точку недопустимой
        [InlineData(".", "container")]
        [InlineData("имя.", "имя")]         // хвостовую точку Windows молча отбрасывает
        public void SafeFolderName_NeverLeavesTheParentFolder(string name, string expected)
        {
            Assert.Equal(expected, RutokenContainer.SafeFolderName(name));
        }

        [Fact]
        public void SaveTo_WritesInsideParentEvenWithHostileContainerName()
        {
            // Имя «..» прошло бы фильтр недопустимых символов, и Path.Combine увёл бы запись
            // в родительский каталог, затерев там чужие *.key.
            string parent = Path.Combine(_root, "export");
            var container = new RutokenContainer { ContainerName = ".." };
            container.Files["primary.key"] = new byte[] { 1, 2, 3 };

            string folder = container.SaveTo(parent);

            Assert.StartsWith(Path.GetFullPath(parent) + Path.DirectorySeparatorChar,
                              Path.GetFullPath(folder), StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(Path.Combine(folder, "primary.key")));
            Assert.False(File.Exists(Path.Combine(_root, "primary.key")));
        }

        [Fact]
        public void SaveTo_KeepsExplicitFolderName()
        {
            var container = new RutokenContainer { ContainerName = "с токена" };
            container.Files["name.key"] = new byte[] { 7 };

            string folder = container.SaveTo(_root, "явное имя");

            Assert.Equal("явное имя", Path.GetFileName(folder));
            Assert.True(File.Exists(Path.Combine(folder, "name.key")));
        }
    }
}
