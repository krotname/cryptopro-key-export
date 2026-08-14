using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading;
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
        /// <summary>
        /// Запустить утилиту и дождаться результата. Отмена прерывает ожидание и убивает процесс:
        /// сама утилита КриптоПро сигналов не понимает, аккуратнее её остановить нечем.
        /// </summary>
        public static ToolResult Run(string exe, string arguments, string workingDirectory, int timeoutMs,
                                     CancellationToken cancel = default)
        {
            // Проверяем до запуска: иначе утилиту вроде `p12utility --cprepair --keyexport`
            // мы бы стартовали и тут же убили — уже посреди перезаписи контейнера.
            cancel.ThrowIfCancellationRequested();

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
                    Output = Strings.Format("tool.startfail", Path.GetFileName(exe)),
                };

            var outTask = Task.Run(() => ReadAll(p.StandardOutput.BaseStream));
            var errTask = Task.Run(() => ReadAll(p.StandardError.BaseStream));

            // Снимаем процесс только если он ещё работает: иначе уже готовый результат
            // выглядел бы как отменённый, хотя работа сделана.
            // Флаг пишет поток отмены, а читает этот — отсюда Volatile, иначе запись не видна.
            var killedByCancel = new StrongBox<bool>(false);
            using var registration = cancel.Register(() =>
            {
                try
                {
                    if (p.HasExited) return;
                    // Флаг ставим до Kill: снять дерево процессов не всегда удаётся без ошибки,
                    // но раз отмена застала утилиту работающей — её результат уже недействителен.
                    Volatile.Write(ref killedByCancel.Value, true);
                    p.Kill(entireProcessTree: true);
                }
                catch (Exception) { }
            });

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                // Kill только посылает завершение. Дожидаемся фактического выхода и закрытия
                // stdout/stderr, чтобы вызывающий не продолжил работу с контейнером, пока
                // просроченная утилита всё ещё дописывает его в фоне.
                try { p.WaitForExit(5000); } catch (InvalidOperationException) { }
                Task.WaitAll(new Task[] { outTask, errTask }, 3000);
                if (Volatile.Read(ref killedByCancel.Value))
                    throw new OperationCanceledException(Strings.Format("tool.cancelled", Path.GetFileName(exe)), cancel);
                return new ToolResult
                {
                    Success = false,
                    ExitCode = -1,
                    Output = Strings.Format("tool.timeout", timeoutMs, Path.GetFileName(exe)),
                };
            }

            Task.WaitAll(new Task[] { outTask, errTask }, 3000);
            if (Volatile.Read(ref killedByCancel.Value))
                throw new OperationCanceledException(Strings.Format("tool.cancelled", Path.GetFileName(exe)), cancel);
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
