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
        public string HardwareId { get; set; }

        /// <summary>
        /// Имя шины из DEVPKEY_Device_EnumeratorName: <c>USB</c>, <c>PCI</c>, <c>ROOT</c>, <c>SWD</c>…
        /// Это и есть признак «железо или программное устройство»; отсутствие USB VID/PID таким
        /// признаком не является — считыватель бывает и на PCI, PCMCIA, ACPI. Строка короткая
        /// и серийного номера не содержит, в отличие от полного Instance ID.
        /// </summary>
        public string Enumerator { get; set; }

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

        private static readonly DevPropKey HardwareIds = new DevPropKey(
            new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 3);
        private static readonly DevPropKey ProblemCode = new DevPropKey(
            new Guid("4340A6C5-93FA-4706-972C-7B648008A5A7"), 3);
        private static readonly DevPropKey ProblemStatus = new DevPropKey(
            new Guid("4340A6C5-93FA-4706-972C-7B648008A5A7"), 12);

        // DEVPKEY_Device_EnumeratorName — короткое имя шины без хвоста Instance ID.
        private static readonly DevPropKey EnumeratorName = new DevPropKey(
            new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 24);

        /// <summary>
        /// Шины программного перечисления: за таким «считывателем» нет отдельного носителя.
        /// ROOT — root-enumerated устройство (например, IFD Handler драйвера Рутокен),
        /// SWD — software device. Всё остальное (USB, PCI, PCMCIA, ACPI…) считается железом.
        /// </summary>
        private static readonly string[] SoftwareBuses = { "ROOT", "SWD" };

        private static readonly Regex VidPid = new Regex(
            @"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        internal static List<string> Report(bool detailed = false)
        {
            try
            {
                return Describe(Enumerate(), detailed);
            }
            catch (Exception error)
            {
                // deps — диагностическая команда: сбой самой проверки должен быть виден, но не
                // должен скрывать отчёт по остальным зависимостям. Текст исключения не выводим.
                return new List<string> { Strings.Format("diag.pnp.unavailable", error.GetType().Name) };
            }
        }

        internal static List<string> Describe(IEnumerable<SmartCardReaderStatus> statuses,
                                              bool detailed = false)
        {
            var pnpPresent = (statuses ?? Enumerable.Empty<SmartCardReaderStatus>()).ToList();
            if (pnpPresent.Count == 0)
                return new List<string> { Strings.Get("diag.pnp.none") };

            var lines = new List<string>();
            var problems = pnpPresent.Where(status => status.ProblemCode != 0).ToList();
            if (problems.Count == 0)
            {
                // Аппаратные и программные считыватели разделены намеренно. Одно число
                // «присутствует N» читается как «подключено N токенов», а это неправда: драйвер
                // Рутокена всегда держит собственный ROOT-считыватель (Aktiv Co. IFD Handler),
                // за которым нет железа, и два вставленных токена дают три PnP-устройства.
                int software = pnpPresent.Count(IsSoftware);
                lines.Add(Strings.Format("diag.pnp.ok", pnpPresent.Count - software, software));
            }
            else
            {
                // Итог «все драйверы запущены» рядом со сбоем противоречил бы сам себе, поэтому
                // при проблеме печатаются только проблемные считыватели.
                lines.AddRange(problems.Select(status => Strings.Format(
                    status.ProblemCode == CmProbFailedStart ? "diag.pnp.failed" : "diag.pnp.problem",
                    SafeId(status) ?? "?",
                    status.ProblemCode,
                    "0x" + status.ProblemStatus.ToString("X8", System.Globalization.CultureInfo.InvariantCulture))));
            }

            if (detailed) lines.AddRange(pnpPresent.Select(status => "  " + Detail(status)));
            return lines;
        }

        /// <summary>Строка одного считывателя в подробном отчёте.</summary>
        private static string Detail(SmartCardReaderStatus status)
        {
            string bus = Bus(status);
            if (IsSoftware(status)) return Strings.Format("diag.pnp.software", bus);

            // У USB-считывателя показываем VID/PID: по ним устройство и опознают. У железа на
            // других шинах безопасного короткого идентификатора нет — называем саму шину.
            string id = SafeId(status);
            return id == null
                ? Strings.Format("diag.pnp.bus", bus)
                : Strings.Format("diag.pnp.usb", id);
        }

        /// <summary>
        /// Программно перечисленное устройство. Считается по имени шины, а не по отсутствию
        /// USB VID/PID: считыватель бывает и на PCI, PCMCIA, ACPI, и он вполне физический
        /// (замечание Codex на PR #70). Шину не прочитали — считаем железом, чтобы не выдать
        /// настоящий считыватель за виртуальный.
        /// </summary>
        internal static bool IsSoftware(SmartCardReaderStatus status) =>
            status?.Enumerator != null
            && SoftwareBuses.Contains(status.Enumerator.Trim(), StringComparer.OrdinalIgnoreCase);

        /// <summary>Имя шины для отчёта; «?» — свойство недоступно.</summary>
        private static string Bus(SmartCardReaderStatus status) =>
            string.IsNullOrWhiteSpace(status?.Enumerator) ? "?" : status.Enumerator.Trim();

        /// <summary>VID/PID устройства или null, если USB-идентичности у него нет.</summary>
        private static string SafeId(SmartCardReaderStatus status) =>
            SafeHardwareId(new[] { status?.HardwareId });

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
                        HardwareId = SafeHardwareId(GetStringList(infoSet, ref device, HardwareIds)),
                        Enumerator = GetString(infoSet, ref device, EnumeratorName),
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

        private static string GetString(IntPtr infoSet, ref SpDevInfoData device, DevPropKey key)
        {
            byte[] bytes = GetProperty(infoSet, ref device, key);
            if (bytes == null || bytes.Length < 2) return null;
            string value = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
            return value.Length == 0 ? null : value;
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
