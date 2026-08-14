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
        /// <summary>Файлы контейнера: name/header и хотя бы одна полная пара primary/masks.</summary>
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

        /// <summary>Похожа ли папка на контейнер КриптоПро (общие файлы и целая пара ключа).</summary>
        public static bool LooksLikeContainer(string folder)
        {
            if (!Directory.Exists(folder)
                || !File.Exists(Path.Combine(folder, "name.key"))
                || !File.Exists(Path.Combine(folder, "header.key"))) return false;

            bool primary = File.Exists(Path.Combine(folder, "primary.key"));
            bool masks = File.Exists(Path.Combine(folder, "masks.key"));
            bool primary2 = File.Exists(Path.Combine(folder, "primary2.key"));
            bool masks2 = File.Exists(Path.Combine(folder, "masks2.key"));
            return primary == masks && primary2 == masks2 && (primary || primary2);
        }

        /// <summary>Результат установки контейнера в хранилище.</summary>
        public sealed class InstallResult
        {
            /// <summary>Созданная папка в хранилище.</summary>
            public string Folder;
            /// <summary>Имя, под которым контейнер в итоге лежит в name.key.</summary>
            public string Name;
            /// <summary>Переименование запрашивалось и применилось.</summary>
            public bool Renamed;
            /// <summary>Проверка видимости выполнялась (только для системного хранилища).</summary>
            public bool Verified;
            /// <summary>Контейнер действительно виден КриптоПро после установки.</summary>
            public bool VisibleToCsp;

            public override string ToString() => Strings.Format(
                !Verified ? "install.result"
                : VisibleToCsp ? "install.result.visible"
                : "install.result.invisible", Name, Folder);
        }

        /// <summary>
        /// Установить контейнер из папки в хранилище CSP. Копируются только файлы *.key
        /// (бэкапы и сертификаты остаются в исходной папке).
        ///
        /// По умолчанию имя контейнера не трогается: CSP сверяет содержимое name.key с самим
        /// контейнером и копию с переписанным именем может не принять. Если newName задано,
        /// имя переписывается, но результат проверяется перечислением — и при неудаче
        /// откатывается к исходному имени.
        ///
        /// Итог всегда проверяется: <see cref="InstallResult.VisibleToCsp"/> говорит, увидел ли
        /// контейнер КриптоПро на самом деле, а не «команда отработала без ошибки».
        /// </summary>
        public static InstallResult Install(string containerFolder, string newName = null, string storeDir = null)
        {
            bool systemStore = storeDir == null;
            storeDir ??= HdImageDir;
            if (!LooksLikeContainer(containerFolder))
                throw new DirectoryNotFoundException(
                    Strings.Format("err.folder.notcontainer", containerFolder));

            string sourceName = ReadName(containerFolder)
                                ?? Path.GetFileName(Path.GetFullPath(containerFolder));
            bool wantRename = !string.IsNullOrWhiteSpace(newName) && newName != sourceName;

            string target = CopyInto(storeDir, wantRename ? newName : sourceName, containerFolder,
                                     wantRename ? newName : null);
            var result = new InstallResult { Folder = target, Name = sourceName };

            if (wantRename)
            {
                if (!systemStore || IsVisibleToCsp(newName))
                {
                    result.Name = newName;
                    result.Renamed = true;
                }
                else
                {
                    // CSP копию с новым именем не принял — полностью откатываемся к исходному
                    // имени и раскладке папки, чтобы у пользователя остался рабочий контейнер.
                    Directory.Delete(target, recursive: true);
                    result.Folder = CopyInto(storeDir, sourceName, containerFolder);
                }
            }

            if (systemStore)
            {
                result.Verified = true;
                result.VisibleToCsp = IsVisibleToCsp(result.Name);
            }
            return result;
        }

        /// <summary>Скопировать файлы контейнера в свободную папку хранилища. Возвращает путь папки.</summary>
        private static string CopyInto(string storeDir, string folderBase, string containerFolder,
                                       string nameOverride = null)
        {
            Directory.CreateDirectory(storeDir);
            string target = FreeFolderFor(storeDir, folderBase);
            string staging = Path.Combine(storeDir, ".cpx-install-" + Guid.NewGuid().ToString("N") + ".tmp");
            Directory.CreateDirectory(staging);
            try
            {
                foreach (string file in ContainerFiles)
                {
                    string src = Path.Combine(containerFolder, file);
                    if (File.Exists(src)) File.Copy(src, Path.Combine(staging, file));
                }
                if (nameOverride != null)
                    File.WriteAllBytes(Path.Combine(staging, "name.key"), NameKey.Build(nameOverride));
                Directory.Move(staging, target);
                return target;
            }
            finally
            {
                // Ошибка копирования не должна оставлять в HDIMAGE частичный контейнер,
                // который выглядит установленным по первым трём успешно записанным файлам.
                if (Directory.Exists(staging))
                    try { Directory.Delete(staging, recursive: true); } catch (IOException) { }
            }
        }

        /// <summary>Имя контейнера из name.key в папке (null — файла нет или он не разобран).</summary>
        public static string ReadName(string containerFolder)
        {
            string path = Path.Combine(containerFolder, "name.key");
            if (!File.Exists(path)) return null;
            try { return NameKey.Parse(File.ReadAllBytes(path)); }
            catch (IOException) { return null; }
        }

        private static bool IsVisibleToCsp(string containerName)
        {
            if (string.IsNullOrEmpty(containerName)) return false;
            foreach (var c in CertFromContainer.EnumContainers())
                if (string.Equals(c.Name, containerName, StringComparison.Ordinal)) return true;
            return false;
        }

        /// <summary>Удалить установленный контейнер. Удаляет только папку, похожую на контейнер внутри хранилища.</summary>
        public static bool Uninstall(string folder, string storeDir = null)
        {
            string full = Path.GetFullPath(folder);
            string store = Path.GetFullPath(storeDir ?? HdImageDir);
            string parent = Path.GetDirectoryName(full);
            if (!string.Equals(parent, store, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(Strings.Format("err.folder.outside", folder), nameof(folder));
            if (!LooksLikeContainer(full))
                throw new ArgumentException(Strings.Format("err.folder.notlike", folder), nameof(folder));

            string[] nested = Directory.GetDirectories(full);
            if (nested.Length != 0)
                throw new InvalidOperationException(Strings.Format("err.folder.extra", nested[0]));

            var allowed = new HashSet<string>(ContainerFiles, StringComparer.OrdinalIgnoreCase);
            foreach (string f in Directory.GetFiles(full))
            {
                if (!allowed.Contains(Path.GetFileName(f)))
                    throw new InvalidOperationException(Strings.Format("err.folder.extra", f));
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
                if (!Directory.Exists(candidate) && !File.Exists(candidate)) return candidate;
            }
            throw new IOException(Strings.Format("err.store.full", storeDir));
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
