using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;

namespace CryptoProExport
{
    /// <summary>Результат запуска консольной утилиты КриптоПро.</summary>
    public sealed class ToolResult
    {
        public bool Success;
        public int ExitCode;
        public string Output;

        /// <summary>Человекочитаемая расшифровка кода возврата, если он ненулевой.</summary>
        public string Explain() => Success ? "OK" : CryptoErrors.Describe(ExitCode);
    }

    /// <summary>
    /// Запуск консольных утилит КриптоПро. Вывод читается как cp866 (в ней пишут
    /// p12utility/certmgr), stdout и stderr — параллельно, чтобы не словить дедлок на буфере.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class ProcessRunner
    {
        public static ToolResult Run(string exe, string arguments, string workingDirectory, int timeoutMs)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = arguments,
                WorkingDirectory = workingDirectory ?? Path.GetDirectoryName(exe) ?? ".",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var p = Process.Start(psi);
            if (p == null)
                return new ToolResult
                {
                    Success = false,
                    ExitCode = -2,
                    Output = "Не удалось запустить " + Path.GetFileName(exe),
                };

            var outTask = Task.Run(() => ReadAll(p.StandardOutput.BaseStream));
            var errTask = Task.Run(() => ReadAll(p.StandardError.BaseStream));

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return new ToolResult
                {
                    Success = false,
                    ExitCode = -1,
                    Output = $"Таймаут {timeoutMs} мс: {Path.GetFileName(exe)}",
                };
            }

            Task.WaitAll(new Task[] { outTask, errTask }, 3000);
            string text = (Text(outTask) + Text(errTask)).Trim();
            return new ToolResult { Success = p.ExitCode == 0, ExitCode = p.ExitCode, Output = text };
        }

        private static string Text(Task<byte[]> t) =>
            t.IsCompletedSuccessfully ? Cp866.GetString(t.Result) : string.Empty;

        private static byte[] ReadAll(Stream s)
        {
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            return ms.ToArray();
        }
    }
}
