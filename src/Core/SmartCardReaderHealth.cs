using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptoProExport
{
    /// <summary>Безопасное для вывода состояние одного PnP-present считывателя.</summary>
    internal sealed class SmartCardReaderStatus
    {
        public string DisplayName { get; set; }
        public string BusDescription { get; set; }
        public string HardwareId { get; set; }
        public uint ProblemCode { get; set; }
        public uint ProblemStatus { get; set; }
    }

    /// <summary>
    /// Read-only PnP-проверка класса SmartCardReader. PC/SC не перечисляет устройство, если его
    /// драйвер не прошёл start IRP (например, Code 10), поэтому одной проверки readers недостаточно.
    /// Instance ID намеренно не читается и не выводится: его USB-хвост может содержать серийник.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class SmartCardReaderHealth
    {
        // PnP-present не означает физическое подключение: сюда входят и виртуальные устройства.
        private const uint DigcfPresent = 0x00000002;
        private const uint CmProbFailedStart = 10;
        private const int ErrorNoMoreItems = 259;
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        // GUID_DEVCLASS_SMARTCARDREADER
        private static readonly Guid ReaderClass = new Guid("50DD5230-BA8A-11D1-BF5D-0000F805F530");

        private static readonly DevPropKey DeviceDescription = new DevPropKey(
            new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 2);
        private static readonly DevPropKey HardwareIds = new DevPropKey(
            new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 3);
        private static readonly DevPropKey FriendlyName = new DevPropKey(
            new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 14);
        private static readonly DevPropKey ProblemCode = new DevPropKey(
            new Guid("4340A6C5-93FA-4706-972C-7B648008A5A7"), 3);
        private static readonly DevPropKey ProblemStatus = new DevPropKey(
            new Guid("4340A6C5-93FA-4706-972C-7B648008A5A7"), 12);
        private static readonly DevPropKey BusReportedDescription = new DevPropKey(
            new Guid("540B947E-8B40-45BC-A8A2-6A0B894CBDA2"), 4);

        private static readonly Regex VidPid = new Regex(
            @"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        internal static List<string> Report()
        {
            try
            {
                return Describe(Enumerate());
            }
            catch (Exception error)
            {
                // deps — диагностическая команда: сбой самой проверки должен быть виден, но не
                // должен скрывать отчёт по остальным зависимостям. Текст исключения не выводим.
                return new List<string> { Strings.Format("diag.pnp.unavailable", error.GetType().Name) };
            }
        }

        internal static List<string> Describe(IEnumerable<SmartCardReaderStatus> statuses)
        {
            var pnpPresent = (statuses ?? Enumerable.Empty<SmartCardReaderStatus>()).ToList();
            if (pnpPresent.Count == 0)
                return new List<string> { Strings.Get("diag.pnp.none") };

            var problems = pnpPresent.Where(status => status.ProblemCode != 0).ToList();
            if (problems.Count == 0)
                return new List<string> { Strings.Format("diag.pnp.ok", pnpPresent.Count) };

            return problems.Select(status => Strings.Format(
                status.ProblemCode == CmProbFailedStart ? "diag.pnp.failed" : "diag.pnp.problem",
                SafeHardwareId(new[] { status.HardwareId }) ?? "?",
                status.ProblemCode,
                "0x" + status.ProblemStatus.ToString("X8", System.Globalization.CultureInfo.InvariantCulture)))
                .ToList();
        }

        internal static string SafeHardwareId(IEnumerable<string> hardwareIds)
        {
            foreach (string hardwareId in hardwareIds ?? Enumerable.Empty<string>())
            {
                Match match = VidPid.Match(hardwareId ?? string.Empty);
                if (match.Success) return "USB\\" + match.Value.ToUpperInvariant();
            }
            return null;
        }

        private static IReadOnlyList<SmartCardReaderStatus> Enumerate()
        {
            Guid classGuid = ReaderClass;
            IntPtr infoSet = SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, DigcfPresent);
            if (infoSet == InvalidHandleValue)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            try
            {
                var result = new List<SmartCardReaderStatus>();
                for (uint index = 0; ; index++)
                {
                    var device = new SpDevInfoData { Size = (uint)Marshal.SizeOf<SpDevInfoData>() };
                    if (!SetupDiEnumDeviceInfo(infoSet, index, ref device))
                    {
                        int code = Marshal.GetLastWin32Error();
                        if (code == ErrorNoMoreItems) break;
                        throw new Win32Exception(code);
                    }

                    result.Add(new SmartCardReaderStatus
                    {
                        DisplayName = FirstNonEmpty(
                            GetString(infoSet, ref device, FriendlyName),
                            GetString(infoSet, ref device, DeviceDescription)),
                        BusDescription = GetString(infoSet, ref device, BusReportedDescription),
                        HardwareId = SafeHardwareId(GetStringList(infoSet, ref device, HardwareIds)),
                        ProblemCode = GetRequiredUInt32(infoSet, ref device, ProblemCode),
                        ProblemStatus = GetUInt32(infoSet, ref device, ProblemStatus),
                    });
                }
                return result;
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(infoSet);
            }
        }

        private static string GetString(IntPtr infoSet, ref SpDevInfoData device, DevPropKey key)
        {
            byte[] bytes = GetProperty(infoSet, ref device, key);
            if (bytes == null || bytes.Length < 2) return null;
            return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
        }

        private static IReadOnlyList<string> GetStringList(
            IntPtr infoSet,
            ref SpDevInfoData device,
            DevPropKey key)
        {
            byte[] bytes = GetProperty(infoSet, ref device, key);
            if (bytes == null || bytes.Length < 2) return Array.Empty<string>();
            return Encoding.Unicode.GetString(bytes)
                .Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private static uint GetUInt32(IntPtr infoSet, ref SpDevInfoData device, DevPropKey key)
        {
            byte[] bytes = GetProperty(infoSet, ref device, key);
            return bytes != null && bytes.Length >= sizeof(uint) ? BitConverter.ToUInt32(bytes, 0) : 0;
        }

        private static uint GetRequiredUInt32(IntPtr infoSet, ref SpDevInfoData device, DevPropKey key)
        {
            byte[] bytes = GetProperty(infoSet, ref device, key);
            if (bytes == null || bytes.Length < sizeof(uint))
                throw new InvalidOperationException("Required PnP property is unavailable.");
            return BitConverter.ToUInt32(bytes, 0);
        }

        private static byte[] GetProperty(IntPtr infoSet, ref SpDevInfoData device, DevPropKey key)
        {
            uint propertyType;
            uint required;
            SetupDiGetDeviceProperty(infoSet, ref device, ref key, out propertyType,
                null, 0, out required, 0);
            if (required == 0) return null;

            var buffer = new byte[required];
            return SetupDiGetDeviceProperty(infoSet, ref device, ref key, out propertyType,
                buffer, (uint)buffer.Length, out required, 0)
                ? buffer
                : null;
        }

        private static string FirstNonEmpty(params string[] values) =>
            values?.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

        [StructLayout(LayoutKind.Sequential)]
        private struct DevPropKey
        {
            public Guid FormatId;
            public uint PropertyId;

            public DevPropKey(Guid formatId, uint propertyId)
            {
                FormatId = formatId;
                PropertyId = propertyId;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SpDevInfoData
        {
            public uint Size;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "SetupDiGetClassDevsW")]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid classGuid,
            string enumerator,
            IntPtr parent,
            uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr infoSet,
            uint index,
            ref SpDevInfoData device);

        [DllImport("setupapi.dll", SetLastError = true,
            EntryPoint = "SetupDiGetDevicePropertyW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceProperty(
            IntPtr infoSet,
            ref SpDevInfoData device,
            ref DevPropKey key,
            out uint propertyType,
            byte[] buffer,
            uint bufferSize,
            out uint requiredSize,
            uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr infoSet);
    }
}
