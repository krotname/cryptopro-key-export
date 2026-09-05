using System;

namespace CryptoProExport
{
    /// <summary>Важность записи журнала; больший уровень означает более важное сообщение.</summary>
    public enum LogLevel
    {
        Debug = 0,
        Information = 1,
        Warning = 2,
        Error = 3,
    }

    /// <summary>Чистая логика фильтра и подписей уровней, отдельно от WinForms и файловой системы.</summary>
    internal static class LogLevels
    {
        public static bool IsVisible(LogLevel entry, LogLevel minimum) => entry >= minimum;

        /// <summary>
        /// Порядок кнопки рассчитан на работу, а не на числовой enum: обычный поток →
        /// подробный → только предупреждения → только ошибки → обычный.
        /// </summary>
        public static LogLevel Next(LogLevel current) => current switch
        {
            LogLevel.Information => LogLevel.Debug,
            LogLevel.Debug => LogLevel.Warning,
            LogLevel.Warning => LogLevel.Error,
            _ => LogLevel.Information,
        };

        public static string Tag(LogLevel level) => level switch
        {
            LogLevel.Debug => "DEBUG",
            LogLevel.Warning => "WARN",
            LogLevel.Error => "ERROR",
            _ => "INFO",
        };

        public static string NameKey(LogLevel level) => level switch
        {
            LogLevel.Debug => "log.level.debug",
            LogLevel.Warning => "log.level.warning",
            LogLevel.Error => "log.level.error",
            _ => "log.level.information",
        };
    }
}
