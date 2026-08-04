using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Хранилище файловых контейнеров КриптоПро (считыватель HDIMAGE) —
    /// каталог <c>%LOCALAPPDATA%\Crypto Pro</c>, где каждая подпапка вида <c>&lt;имя&gt;.000</c>
    /// содержит те же 6 файлов *.key, что снимаются с Рутокена.
    ///
    /// Это даёт последний недостающий шаг: снятый с токена контейнер можно «установить» в CSP —
    /// после этого он виден в списке, из него извлекается сертификат и делается экспорт в PFX,
    /// даже когда токен уже вынут.
    ///
    /// Имя, под которым контейнер увидит CSP, лежит внутри <c>name.key</c> (см. <see cref="NameKey"/>),
    /// поэтому при установке оно переписывается — иначе копия сольётся с оригиналом.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class ContainerStore
    {
        /// <summary>Файлы, из которых состоит контейнер. Первые четыре обязательны.</summary>
        public static readonly string[] ContainerFiles =
            { "name.key", "header.key", "primary.key", "masks.key", "primary2.key", "masks2.key" };

        /// <summary>Каталог HDIMAGE-хранилища текущего пользователя.</summary>
        public static string HdImageDir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Crypto Pro");

        public sealed class InstalledContainer
        {
            public string Name;    // имя из name.key — его показывает CSP
            public string Folder;  // папка в хранилище
            public override string ToString() => $"{Name} ({Folder})";
        }

        /// <summary>Контейнеры, лежащие в хранилище HDIMAGE (storeDir — для тестов, по умолчанию системное).</summary>
        public static List<InstalledContainer> Installed(string storeDir = null)
        {
            storeDir ??= HdImageDir;
            var list = new List<InstalledContainer>();
            if (!Directory.Exists(storeDir)) return list;
            foreach (string dir in Directory.GetDirectories(storeDir))
            {
                string nameKey = Path.Combine(dir, "name.key");
                if (!File.Exists(nameKey) || !File.Exists(Path.Combine(dir, "header.key"))) continue;
                string name = null;
                try { name = NameKey.Parse(File.ReadAllBytes(nameKey)); } catch (IOException) { }
                list.Add(new InstalledContainer { Name = name ?? Path.GetFileName(dir), Folder = dir });
            }
            return list;
        }

        /// <summary>Похожа ли папка на контейнер КриптоПро (есть обязательные файлы).</summary>
        public static bool LooksLikeContainer(string folder) =>
            Directory.Exists(folder)
            && File.Exists(Path.Combine(folder, "header.key"))
            && File.Exists(Path.Combine(folder, "primary.key"))
            && File.Exists(Path.Combine(folder, "masks.key"));

        /// <summary>
        /// Установить контейнер из папки в хранилище CSP под именем containerName.
        /// Копируются только файлы *.key (бэкапы и сертификаты остаются в исходной папке).
        /// Возвращает путь созданной папки хранилища.
        /// </summary>
        public static string Install(string containerFolder, string containerName, string storeDir = null)
        {
            storeDir ??= HdImageDir;
            if (!LooksLikeContainer(containerFolder))
                throw new DirectoryNotFoundException(
                    $"В папке нет контейнера (нужны header.key, primary.key, masks.key): {containerFolder}");
            if (string.IsNullOrWhiteSpace(containerName))
                throw new ArgumentException("Не задано имя контейнера", nameof(containerName));

            Directory.CreateDirectory(storeDir);
            string target = FreeFolderFor(storeDir, containerName);
            Directory.CreateDirectory(target);

            foreach (string file in ContainerFiles)
            {
                string src = Path.Combine(containerFolder, file);
                if (File.Exists(src)) File.Copy(src, Path.Combine(target, file), overwrite: true);
            }

            // Имя, под которым контейнер увидит CSP
            File.WriteAllBytes(Path.Combine(target, "name.key"), NameKey.Build(containerName));
            return target;
        }

        /// <summary>Удалить установленный контейнер. Удаляет только папку, похожую на контейнер внутри хранилища.</summary>
        public static bool Uninstall(string folder, string storeDir = null)
        {
            string full = Path.GetFullPath(folder);
            string store = Path.GetFullPath(storeDir ?? HdImageDir);
            if (!full.StartsWith(store + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Папка вне хранилища КриптоПро: " + folder, nameof(folder));
            if (!LooksLikeContainer(full))
                throw new ArgumentException("Папка не похожа на контейнер: " + folder, nameof(folder));

            foreach (string f in Directory.GetFiles(full))
            {
                if (!f.EndsWith(".key", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("В папке контейнера есть посторонние файлы, удаление отменено: " + f);
            }
            Directory.Delete(full, recursive: true);
            return true;
        }

        /// <summary>Свободное имя папки в хранилище: &lt;имя&gt;.000, .001, …</summary>
        private static string FreeFolderFor(string storeDir, string containerName)
        {
            string baseName = Sanitize(containerName);
            for (int i = 0; i < 1000; i++)
            {
                string candidate = Path.Combine(storeDir, $"{baseName}.{i:000}");
                if (!Directory.Exists(candidate)) return candidate;
            }
            throw new IOException("Не удалось подобрать свободную папку в " + storeDir);
        }

        internal static string Sanitize(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
            name = name.Replace('.', '_').Trim();
            if (name.Length == 0) name = "container";
            return name.Length > 40 ? name.Substring(0, 40) : name;
        }
    }
}
