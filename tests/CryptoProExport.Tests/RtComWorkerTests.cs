using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using CryptoProExport.WorkerFixture;
using Xunit;

namespace CryptoProExport.Tests
{
    public class RtComWorkerTests
    {
        [Fact]
        public void Worker_TransfersProgressAndContainerOverDedicatedPipes()
        {
            string log = null;
            var worker = Exporter("success", 5000);
            worker.UserPin = "test-pin";
            worker.Log = text => log = text;

            var result = worker.ReadAllContainers();

            Assert.True(worker.Started);
            Assert.Equal("fixture-progress", log);
            var container = Assert.Single(result);
            Assert.Equal("fixture-reader", container.TokenName);
            Assert.Equal("fixture-container", container.ContainerName);
            Assert.Equal(new byte[] { 1, 2, 3 }, container.Files["primary.key"]);
        }

        [Fact]
        public void Worker_ClassifiesManagedFailure()
        {
            var worker = Exporter("managed-error", 5000);
            var error = Assert.Throws<RtComWorkerException>(() => worker.ReadAllContainers());
            Assert.Equal(RtComWorkerFailure.Failed, error.Failure);
            Assert.True(worker.Started);
            Assert.Contains("synthetic worker failure", error.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("nonzero")]
        [InlineData("crash")]
        public void Worker_ClassifiesAbruptOrNonzeroExit(string mode)
        {
            var worker = Exporter(mode, 5000);
            var error = Assert.Throws<RtComWorkerException>(() => worker.ReadAllContainers());
            Assert.Equal(RtComWorkerFailure.Crashed, error.Failure);
            Assert.True(worker.Started);
            Assert.Contains("0x", error.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Worker_TimesOutAndStopsChild()
        {
            var worker = Exporter("timeout", 250);
            var timer = Stopwatch.StartNew();
            var error = Assert.Throws<RtComWorkerException>(() => worker.ReadAllContainers());
            timer.Stop();
            Assert.Equal(RtComWorkerFailure.Timeout, error.Failure);
            Assert.True(worker.Started);
            Assert.True(timer.Elapsed < TimeSpan.FromSeconds(10), $"timeout took {timer.Elapsed}");
        }

        [Fact]
        public void Worker_CancellationStopsChild()
        {
            using var cancellation = new CancellationTokenSource();
            cancellation.CancelAfter(250);
            var worker = Exporter("timeout", 10000);
            worker.Cancel = cancellation.Token;

            var timer = Stopwatch.StartNew();
            Assert.ThrowsAny<OperationCanceledException>(() => worker.ReadAllContainers());
            timer.Stop();
            Assert.True(worker.Started);
            Assert.True(timer.Elapsed < TimeSpan.FromSeconds(10), $"cancel took {timer.Elapsed}");
        }

        [Theory]
        [InlineData("malformed")]
        [InlineData("incomplete")]
        public void Worker_RejectsMalformedOrIncompleteIpc(string mode)
        {
            var worker = Exporter(mode, 5000);
            var error = Assert.Throws<RtComWorkerException>(() => worker.ReadAllContainers());
            Assert.Equal(RtComWorkerFailure.Malformed, error.Failure);
        }

        [Fact]
        public void Worker_RejectsExcessiveCumulativeLogText()
        {
            var worker = Exporter("log-flood", 5000);
            var error = Assert.Throws<RtComWorkerException>(() => worker.ReadAllContainers());
            Assert.Equal(RtComWorkerFailure.Malformed, error.Failure);
            Assert.True(worker.Started);
        }

        private static RutokenExporter Exporter(string mode, int timeoutMs) => new RutokenExporter
        {
            WorkerLaunch = FixtureLaunch(mode),
            WorkerTimeoutMs = timeoutMs,
        };

        private static RtComWorkerLaunch FixtureLaunch(string mode)
        {
            string fixture = typeof(WorkerFixtureMarker).Assembly.Location;
            string tests = typeof(RtComWorkerTests).Assembly.Location;
            string runtimeConfig = Path.ChangeExtension(tests, ".runtimeconfig.json");
            Assert.True(File.Exists(fixture), "worker fixture assembly is missing");
            Assert.True(File.Exists(runtimeConfig), "test runtimeconfig is missing");
            return new RtComWorkerLaunch("dotnet", "exec", "--runtimeconfig", runtimeConfig,
                                         fixture, mode);
        }
    }
}
