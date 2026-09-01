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
                    HardwareId = @"USB\VID_2CE4&PID_7479",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains("присутствует как PnP-устройство", line, StringComparison.Ordinal);
            Assert.DoesNotContain("физически", line, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("драйвер не запустился", line, StringComparison.Ordinal);
            Assert.Contains(@"USB\VID_2CE4&PID_7479", line, StringComparison.Ordinal);
            Assert.Contains("10", line, StringComparison.Ordinal);
            Assert.Contains("0xC0000001", line, StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_DoesNotExposeReaderNamesOrHardwareSuffix()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus
                {
                    HardwareId = @"USB\VID_2CE4&PID_7479\private-serial-must-not-leak",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains(@"USB\VID_2CE4&PID_7479", line, StringComparison.Ordinal);
            Assert.DoesNotContain("private-serial-must-not-leak", line, StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_SummarizesHealthyReaders()
        {
            // Железо и программные устройства считаются отдельно: драйвер Рутокена держит
            // собственный ROOT-считыватель, за которым нет носителя, и общее число вводило в
            // заблуждение — два вставленных токена выглядели как три устройства.
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus { Enumerator = "USB", HardwareId = @"USB\VID_0A89&PID_0030" },
                new SmartCardReaderStatus { Enumerator = "USB", HardwareId = @"USB\VID_0A89&PID_0030" },
                new SmartCardReaderStatus { Enumerator = "ROOT", HardwareId = @"ROOT\SMARTCARDREADER" },
            });

            Assert.Equal("Smart-card readers (PnP): 2 hardware, 1 software, all drivers started",
                Assert.Single(lines));
        }

        [Fact]
        public void Describe_CountsNonUsbReaderAsHardware()
        {
            // Считыватель на PCI, PCMCIA или ACPI — физический, хотя USB VID/PID у него нет.
            // Раньше он попадал в программные, и отчёт врал про состав железа (замечание
            // Codex на PR #70). Признак — шина, а не наличие USB-идентификатора.
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus { Enumerator = "PCI" },
                new SmartCardReaderStatus { Enumerator = "ROOT" },
            }, detailed: true);

            Assert.Equal("Smart-card readers (PnP): 1 hardware, 1 software, all drivers started", lines[0]);
            Assert.Contains("reader on bus PCI", lines[1], StringComparison.Ordinal);
            Assert.Contains("software reader (bus ROOT", lines[2], StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_CountsReaderWithUnknownBusAsHardware()
        {
            // Свойство шины прочитать не удалось — считаем железом: выдать настоящий
            // считыватель за виртуальный хуже, чем не назвать шину.
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[] { new SmartCardReaderStatus() }, detailed: true);

            Assert.Equal("Smart-card readers (PnP): 1 hardware, 0 software, all drivers started", lines[0]);
            Assert.Contains("reader on bus ?", lines[1], StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_ListsEveryReaderOnlyWhenDetailed()
        {
            using var language = Strings.Scope("en");
            var statuses = new[]
            {
                new SmartCardReaderStatus
                {
                    Enumerator = "USB",
                    HardwareId = @"USB\VID_0A89&PID_0030\serial-must-not-leak",
                },
                new SmartCardReaderStatus { Enumerator = "ROOT", HardwareId = @"ROOT\SMARTCARDREADER" },
            };

            Assert.Single(SmartCardReaderHealth.Describe(statuses));

            var detailed = SmartCardReaderHealth.Describe(statuses, detailed: true);
            Assert.Equal(3, detailed.Count);
            Assert.Contains(@"USB reader USB\VID_0A89&PID_0030", detailed[1], StringComparison.Ordinal);
            Assert.DoesNotContain("serial-must-not-leak", detailed[1], StringComparison.Ordinal);
            Assert.Contains("software reader", detailed[2], StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_UsesGenericWordingForNonCode10Problem()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus
                {
                    HardwareId = @"USB\VID_1234&PID_5678",
                    ProblemCode = 14,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains("PnP-present", line, StringComparison.Ordinal);
            Assert.Contains("Windows reports a PnP problem", line, StringComparison.Ordinal);
            Assert.DoesNotContain("driver did not start", line, StringComparison.Ordinal);
            Assert.Contains("Code 14", line, StringComparison.Ordinal);
        }

        [Fact]
        public void Describe_ReportsNoPresentReaders()
        {
            using var language = Strings.Scope("en");
            Assert.Contains("no PnP-present devices", Assert.Single(
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
                    HardwareId = @"USB\VID_2CE4&PID_7479",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            Assert.Single(lines);
            Assert.Contains("PnP-present", lines[0], StringComparison.Ordinal);
            Assert.DoesNotContain("physically connected", lines[0], StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void Describe_DoesNotCallVirtualNonUsbReaderPhysicallyConnected()
        {
            using var language = Strings.Scope("en");
            var lines = SmartCardReaderHealth.Describe(new[]
            {
                new SmartCardReaderStatus
                {
                    HardwareId = @"ROOT\SMARTCARDREADER",
                    ProblemCode = 10,
                    ProblemStatus = 0xC0000001,
                },
            });

            string line = Assert.Single(lines);
            Assert.Contains("Smart-card reader ?: PnP-present", line, StringComparison.Ordinal);
            Assert.Contains("Code 10", line, StringComparison.Ordinal);
            Assert.Contains("0xC0000001", line, StringComparison.Ordinal);
            Assert.DoesNotContain("physically", line, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("ROOT", line, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("private-serial-must-not-leak", line, StringComparison.Ordinal);
        }
    }
}
