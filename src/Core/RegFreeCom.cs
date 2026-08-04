using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Создание COM-объекта напрямую из DLL, без регистрации в реестре и без прав администратора:
    /// LoadLibrary → DllGetClassObject → IClassFactory::CreateInstance.
    ///
    /// Так подключается вшитый <c>rtCOMLite.dll</c>: установка «компонента диагностики Рутокен»
    /// на целевой машине не требуется.
    ///
    /// Ограничение: DLL грузится в процесс, поэтому разрядность DLL должна совпадать с разрядностью
    /// процесса (<see cref="MatchesProcess"/>). rtCOMLite 32-битный — приложение собирается x86.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class RegFreeCom
    {
        private static readonly Guid IID_IUnknown      = new Guid("00000000-0000-0000-C000-000000000046");
        private static readonly Guid IID_IClassFactory = new Guid("00000001-0000-0000-C000-000000000046");

        private static readonly Dictionary<string, IntPtr> Loaded =
            new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

        [ComImport, Guid("00000001-0000-0000-C000-000000000046"),
         InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IClassFactory
        {
            [PreserveSig]
            int CreateInstance(
                [MarshalAs(UnmanagedType.IUnknown)] object outer,
                ref Guid iid,
                [MarshalAs(UnmanagedType.IUnknown)] out object instance);

            [PreserveSig]
            int LockServer([MarshalAs(UnmanagedType.Bool)] bool @lock);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int DllGetClassObjectFn(ref Guid clsid, ref Guid iid, out IntPtr ppv);

        /// <summary>Создать экземпляр COM-класса clsid из указанной DLL.</summary>
        public static object CreateInstance(string dllPath, Guid clsid)
        {
            if (!File.Exists(dllPath)) throw new FileNotFoundException("COM-библиотека не найдена", dllPath);

            IntPtr module;
            lock (Loaded)
            {
                if (!Loaded.TryGetValue(dllPath, out module))
                {
                    module = NativeLibrary.Load(dllPath);
                    Loaded[dllPath] = module;
                }
            }

            IntPtr proc = NativeLibrary.GetExport(module, "DllGetClassObject");
            var getClassObject = Marshal.GetDelegateForFunctionPointer<DllGetClassObjectFn>(proc);

            Guid clsidCopy = clsid, iidFactory = IID_IClassFactory;
            int hr = getClassObject(ref clsidCopy, ref iidFactory, out IntPtr pFactory);
            if (hr < 0 || pFactory == IntPtr.Zero)
                throw new COMException($"DllGetClassObject({clsid:B}) вернул 0x{hr:X8}", hr);

            IClassFactory factory;
            try { factory = (IClassFactory)Marshal.GetObjectForIUnknown(pFactory); }
            finally { Marshal.Release(pFactory); }

            try
            {
                Guid iid = IID_IUnknown;
                hr = factory.CreateInstance(null, ref iid, out object instance);
                if (hr < 0 || instance == null)
                    throw new COMException($"IClassFactory::CreateInstance вернул 0x{hr:X8}", hr);
                return instance;
            }
            finally { Marshal.ReleaseComObject(factory); }
        }

        /// <summary>Разрядность PE-файла (null — не PE или неизвестная машина).</summary>
        public static Architecture? ReadMachine(string path)
        {
            try
            {
                using var fs = File.OpenRead(path);
                using var br = new BinaryReader(fs);
                fs.Position = 0x3C;
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset + 6 > fs.Length) return null;
                fs.Position = peOffset;
                if (br.ReadUInt32() != 0x00004550) return null; // "PE\0\0"
                return br.ReadUInt16() switch
                {
                    0x014c => Architecture.X86,
                    0x8664 => Architecture.X64,
                    0xAA64 => Architecture.Arm64,
                    _ => (Architecture?)null,
                };
            }
            catch { return null; }
        }

        /// <summary>Можно ли загрузить эту DLL в текущий процесс (совпадает ли разрядность).</summary>
        public static bool MatchesProcess(string dllPath, out string detail)
        {
            var machine = ReadMachine(dllPath);
            var process = RuntimeInformation.ProcessArchitecture;
            if (machine == null)
            {
                detail = "не удалось определить разрядность библиотеки";
                return false;
            }
            detail = $"библиотека {Name(machine.Value)}, процесс {Name(process)}";
            return machine.Value == process;
        }

        internal static string Name(Architecture a) => a switch
        {
            Architecture.X86 => "x86",
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => a.ToString().ToLowerInvariant(),
        };
    }
}
