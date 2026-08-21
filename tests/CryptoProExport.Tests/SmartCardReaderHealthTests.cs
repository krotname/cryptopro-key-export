using System;
using System.Collections.Generic;
using Xunit;

namespace CryptoProExport.Tests
{
    public class SmartCardReaderHealthTests
    {
        [Fact]
        public void SafeHardwareId_KeepsOnlyVidAndPid()
        {
            string safe = SmartCardReaderHealth.SafeHardwareId(new[]
            {
                @"USB\VID_2CE4&PID_7479&REV_0102",
                @"USB\VID_2CE4&PID_7479\private-suffix-must-not-leak",
            });

            Assert.Equal(@"USB\VID_2CE4&PID_7479", safe);
            Assert.DoesNotContain("private-suffix", safe, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("REV_", safe, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void SafeHardwareId_ReturnsNullForNonUsbIdentity()
        {
            Assert.Null(SmartCardReaderHealth.SafeHardwareId(new[] { "ROOT\\SMARTCARDREADER" }));
        }

        [Fact]
        public void Describe_ExplainsPresentReaderWhoseDriverFailed()
        {
            using var language = Strings.Scope("ru");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus
                {
                    DisplayName = "Microsoft Usbccid (WUDF)",
                    BusDescription = "ESMART Token",
                    HardwareId = @"USB\VID_2CE4&PID_7479",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains("физически подключён", line, StringComparison.Ordinal);
            Assert.Contains("драйвер не запустился", line, StringComparison.Ordinal);
            Assert.Contains("ESMART Token", line, StringComparison.Ordinal);
            Assert.Contains(@"USB\VID_2CE4&PID_7479", line, StringComparison.Ordinal);
            Assert.Contains("10", line, StringComparison.Ordinal);
            Assert.Contains("0xC0000001", line, StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_SummarizesHealthyReaders()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus(),
                new SmartCardReaderStatus(),
            });

            Assert.Equal("Smart-card readers (PnP): 2 connected, all drivers started", Assert.Single(lines));
        }

        [Fact]
        public void Describe_UsesGenericWordingForNonCode10Problem()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus
                {
                    BusDescription = "Reader awaiting restart",
                    HardwareId = @"USB\VID_1234&PID_5678",
                    ProblemCode = 14,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains("Windows reports a PnP problem", line, StringComparison.Ordinal);
            Assert.DoesNotContain("driver did not start", line, StringComparison.Ordinal);
            Assert.Contains("Code 14", line, StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_ReportsNoPresentReaders()
        {
            using var language = Strings.Scope("en");
            Assert.Contains("no devices", Assert.Single(
                SmartCardReaderHealth.Describe(Array.Empty<SmartCardReaderStatus>())),
                StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_ReportsOnlyFailuresWhenHealthyReadersAlsoExist()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new List<SmartCardReaderStatus>
            {
                new SmartCardReaderStatus(),
                new SmartCardReaderStatus
                {
                    BusDescription = "ESMART Token",
                    HardwareId = @"USB\VID_2CE4&PID_7479",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            Assert.Single(lines);
            Assert.Contains("physically connected", lines[0], StringComparison.Ordinal);
        }
    }
}
