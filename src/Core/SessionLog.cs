using System;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Журнал сеанса в файл: %LOCALAPPDATA%\CryptoProExport\logs\ГГГГММДД-ЧЧММСС.log.
    /// Нужен, чтобы после неудачной операции было что показать — окно с логом
    /// пользователь обычно уже закрыл.
    ///
    /// Пароли в журнал не пишутся: команды маскируются на стороне вызывающих
    /// (<see cref="P12Utility"/>, <see cref="CertMgr"/>).
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class SessionLog
    {
        private static readonly object Gate = new object();
        private static string _path;
        private static bool _failed;

        /// <summary>Каталог с журналами.</summary>
        public static string Dir => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoProExport", "logs");

        /// <summary>Файл журнала текущего запуска (создаётся при первой записи).</summary>
        public static string FilePath
        {
            get
            {
                lock (Gate)
                {
                    return _path ??= Path.Combine(
                        Dir, DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".log");
                }
            }
        }

        /// <summary>Записать строку. Ошибки записи не мешают работе программы.</summary>
        public static void Write(string message)
        {
            if (_failed) return;
            try
            {
                string path = FilePath;
                lock (Gate)
                {
                    Directory.CreateDirectory(Dir);
                    File.AppendAllText(path,
                        DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture) + "  " + message + Environment.NewLine);
                }
            }
            catch (Exception)
            {
                _failed = true; // нет прав на запись — просто работаем без журнала
            }
        }

        /// <summary>Обернуть приёмник лога так, чтобы всё дублировалось в файл.</summary>
        public static Action<string> Tee(Action<string> inner) => message =>
        {
            Write(message);
            inner?.Invoke(message);
        };

        /// <summary>Удалить журналы старше указанного числа дней.</summary>
        public static void Prune(int keepDays = 30)
        {
            try
            {
                if (!Directory.Exists(Dir)) return;
                DateTime limit = DateTime.Now.AddDays(-keepDays);
                foreach (string f in Directory.GetFiles(Dir, "*.log"))
                {
                    if (File.GetLastWriteTime(f) < limit)
                        try { File.Delete(f); } catch (IOException) { }
                }
            }
            catch (Exception) { /* уборка журналов не должна ломать запуск */ }
        }
    }
}
