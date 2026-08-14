using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Отмена длинных операций. Прервать вызов внутри COM или уже запущенную утилиту нельзя,
    /// поэтому проверяем то, что действительно гарантируется: отменённая работа не начинается,
    /// а запущенный процесс снимается.
    /// </summary>
    public class CancellationTests
    {
        [Fact]
        public void Exporter_DoesNotStartWhenAlreadyCancelled()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            var exporter = new RutokenExporter { Cancel = cancellation.Token };
            // Токена в сборочной машине нет; важно, что до обращения к COM дело не доходит
            Assert.ThrowsAny<OperationCanceledException>(() => exporter.ReadAllContainers());
        }

        [Fact]
        public void Pipeline_SharesTokenWithWorkers()
        {
            string p12 = BundledTools.P12Utility();
            Assert.NotNull(p12);

            using var cancellation = new CancellationTokenSource();
            var pipeline = new ExportPipeline(p12) { Cancel = cancellation.Token };

            Assert.Equal(cancellation.Token, pipeline.Exporter.Cancel);
            Assert.Equal(cancellation.Token, pipeline.P12.Cancel);
        }

        [Fact]
        public void ProcessRunner_KillsRunningToolOnCancel()
        {
            // Долгий процесс: ping идёт ~30 секунд и не зависит от стандартного ввода
            string ping = Path.Combine(Environment.SystemDirectory, "ping.exe");
            Assert.True(File.Exists(ping), "нет ping.exe — тест рассчитан на Windows");

            using var cancellation = new CancellationTokenSource();
            cancellation.CancelAfter(TimeSpan.FromMilliseconds(500));

            var sw = Stopwatch.StartNew();
            ToolResult finished = null;
            var error = Record.Exception(() =>
                finished = ProcessRunner.Run(ping, "-n 30 127.0.0.1", Environment.SystemDirectory, 60000, cancellation.Token));
            sw.Stop();
            Assert.True(error is OperationCanceledException,
                $"ожидали отмену, получили {error?.GetType().Name ?? "результат"}: " +
                $"код={finished?.ExitCode}, вывод={finished?.Output}");

            // Без отмены ждали бы таймаут в 60 секунд
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"отмена не сработала, ждали {sw.Elapsed}");
        }

        [Fact]
        public void ProcessRunner_DoesNotStartToolWhenAlreadyCancelled()
        {
            // Отменили между шагами — утилита не должна стартовать вовсе: иначе
            // p12utility успел бы начать перезапись контейнера и был бы убит на середине.
            string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            string marker = Path.Combine(Path.GetTempPath(), "cpx-marker-" + Guid.NewGuid().ToString("N") + ".txt");

            using var cancellation = new CancellationTokenSource();
            cancellation.Cancel();

            Assert.ThrowsAny<OperationCanceledException>(
                () => ProcessRunner.Run(cmd, $"/c echo x > \"{marker}\"", Environment.SystemDirectory, 15000, cancellation.Token));

            Assert.False(File.Exists(marker), "утилита всё-таки запустилась при отменённом токене");
        }

        [Fact]
        public void ProcessRunner_WorksNormallyWithoutCancellation()
        {
            string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            var result = ProcessRunner.Run(cmd, "/c exit 7", Environment.SystemDirectory, 15000);
            Assert.False(result.Success);
            Assert.Equal(7, result.ExitCode);
        }

        [Fact]
        public void ProcessRunner_KeepsResultWhenCancelArrivesAfterFinish()
        {
            // Отмена уже готовой работы не должна превращать успешный результат в «отменено»
            string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            using var cancellation = new CancellationTokenSource();

            var result = ProcessRunner.Run(cmd, "/c exit 0", Environment.SystemDirectory, 15000, cancellation.Token);
            cancellation.Cancel();

            Assert.True(result.Success);
            Assert.Equal(0, result.ExitCode);
        }

        [Fact]
        public void ProcessRunner_TimeoutStopsProcessBeforeReturning()
        {
            string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            string marker = Path.Combine(Path.GetTempPath(), "cpx-timeout-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                var result = ProcessRunner.Run(cmd,
                    $"/c ping -n 3 127.0.0.1 >nul & echo late>\"{marker}\"",
                    Environment.SystemDirectory, 100);

                Assert.False(result.Success);
                Assert.Equal(-1, result.ExitCode);
                Thread.Sleep(2500);
                Assert.False(File.Exists(marker), "процесс продолжил работу уже после возврата timeout");
            }
            finally { if (File.Exists(marker)) File.Delete(marker); }
        }
    }
}
