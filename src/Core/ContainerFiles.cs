using System;
using System.Collections.Generic;
using System.IO;

namespace CryptoProExport
{
    /// <summary>
    /// Файлы файлового контейнера КриптоПро (<c>*.key</c>) в памяти, по каноническим именам.
    /// Источник неважен: папка на диске (HDIMAGE), снятая с носителя по APDU копия или
    /// собранный синтетический контейнер из тестов. На одноключевом контейнере есть
    /// <c>masks/primary/header/name</c>, на двухключевом добавляются <c>masks2/primary2</c>.
    ///
    /// Нужен, чтобы разбор (<see cref="ContainerKeyExtractor"/>) и сборка экспортируемой копии
    /// (<see cref="ExportableContainerBuilder"/>) работали с одним набором байт и проверка новой
    /// копии шла до записи на диск, а не после. Порт того же класса из Android-ядра.
    /// </summary>
    public sealed class ContainerFiles
    {
        /// <summary>Канонические имена файлов контейнера.</summary>
        public static readonly string[] Names =
            { "masks.key", "primary.key", "header.key", "name.key", "masks2.key", "primary2.key" };

        private readonly Dictionary<string, byte[]> _files;

        /// <summary>Откуда прочитано — только для сообщения «в папке контейнера нет …».</summary>
        private readonly string _origin;

        private ContainerFiles(Dictionary<string, byte[]> files, string origin)
        {
            _files = files;
            _origin = origin;
        }

        /// <summary>Собрать из карты «имя → байты»; null-значения и неизвестные имена отбрасываются.</summary>
        public static ContainerFiles Of(IDictionary<string, byte[]> files, string origin = null)
        {
            if (files == null) throw new ArgumentNullException(nameof(files));
            var clean = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in Names)
                if (files.TryGetValue(name, out byte[] value) && value != null)
                    clean[name] = value;
            return new ContainerFiles(clean, origin);
        }

        /// <summary>Прочитать папку-контейнер: берутся только присутствующие канонические файлы.</summary>
        public static ContainerFiles FromDirectory(string containerDir)
        {
            if (containerDir == null) throw new ArgumentNullException(nameof(containerDir));
            var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in Names)
            {
                string path = Path.Combine(containerDir, name);
                if (File.Exists(path)) files[name] = File.ReadAllBytes(path);
            }
            return new ContainerFiles(files, containerDir);
        }

        /// <summary>Файл присутствует в контейнере.</summary>
        public bool Has(string name) => _files.ContainsKey(name);

        /// <summary>Байты файла или <c>null</c>, если его в контейнере нет.</summary>
        public byte[] Get(string name) => _files.TryGetValue(name, out byte[] value) ? value : null;

        /// <summary>Байты файла или <see cref="ContainerKeyException"/>, если файла нет.</summary>
        public byte[] Require(string name)
        {
            if (_files.TryGetValue(name, out byte[] value)) return value;
            throw new ContainerKeyException(Strings.Format("err.extract.nofile", name, _origin ?? "-"));
        }

        /// <summary>Независимая копия всех файлов: вызывающий может заменять и затирать массивы.</summary>
        public Dictionary<string, byte[]> CopyMap()
        {
            var copy = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in Names)
                if (_files.TryGetValue(name, out byte[] value)) copy[name] = (byte[])value.Clone();
            return copy;
        }

        /// <summary>
        /// Затереть ключевой материал. Из <c>primary*.key</c> и <c>masks*.key</c> закрытый ключ
        /// восстанавливается полностью, поэтому набор файлов, который больше не нужен, нельзя
        /// просто «забыть»: массивы остались бы в памяти процесса до сборки мусора.
        /// </summary>
        public void WipeKeyMaterial()
        {
            foreach (var pair in _files)
                if (pair.Key.StartsWith("primary", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.StartsWith("masks", StringComparison.OrdinalIgnoreCase))
                    Array.Clear(pair.Value, 0, pair.Value.Length);
        }

        /// <summary>
        /// Записать контейнер в папку. Папка должна быть новой или пустой: перезапись чужого
        /// контейнера — необратимая потеря ключа, а копия и делается как раз для того, чтобы
        /// исходная папка осталась нетронутой.
        /// </summary>
        public void WriteTo(string outDir)
        {
            if (outDir == null) throw new ArgumentNullException(nameof(outDir));
            if (Directory.Exists(outDir) && Directory.GetFileSystemEntries(outDir).Length > 0)
                throw new ContainerKeyException(Strings.Format("err.exportable.exists", outDir));
            Directory.CreateDirectory(outDir);
            foreach (string name in Names)
                if (_files.TryGetValue(name, out byte[] value))
                    File.WriteAllBytes(Path.Combine(outDir, name), value);
        }
    }
}
