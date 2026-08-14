using System;
using System.Collections.Generic;
using System.Dynamic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
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
        private static readonly Guid IID_NULL          = Guid.Empty;

        private static readonly Dictionary<string, IntPtr> Loaded =
            new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, IntPtr> ActivationContexts =
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
            if (!File.Exists(dllPath)) throw new FileNotFoundException(Strings.Get("err.com.notfound"), dllPath);

            IntPtr activationContext = ActivationContext(dllPath);
            using var activation = new ActivationScope(activationContext);

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
                throw new COMException(Strings.Format("err.com.call", $"DllGetClassObject({clsid:B})", $"0x{hr:X8}"), hr);

            IClassFactory factory;
            try { factory = (IClassFactory)Marshal.GetObjectForIUnknown(pFactory); }
            finally { Marshal.Release(pFactory); }

            try
            {
                Guid iid = IID_IUnknown;
                hr = factory.CreateInstance(null, ref iid, out object instance);
                if (hr < 0 || instance == null)
                    throw new COMException(Strings.Format("err.com.call", "IClassFactory::CreateInstance", $"0x{hr:X8}"), hr);
                // Обычный dynamic-RCW запрашивает зарегистрированную type library перед первым
                // вызовом. Это ломает сам смысл reg-free загрузки (TYPE_E_LIBNOTREGISTERED).
                // Наш прокси вызывает IDispatch::GetIDsOfNames/Invoke напрямую: эти операции
                // typelib и записей в HKCR не требуют.
                return new DispatchProxy(instance, activationContext);
            }
            finally { Marshal.ReleaseComObject(factory); }
        }

        [ComImport, Guid("00020400-0000-0000-C000-000000000046"),
         InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IDispatch
        {
            [PreserveSig] int GetTypeInfoCount(out uint count);
            [PreserveSig] int GetTypeInfo(uint index, uint lcid, out IntPtr typeInfo);
            [PreserveSig] int GetIDsOfNames(ref Guid iid,
                [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr)] string[] names,
                uint count, uint lcid, out int dispId);
            [PreserveSig] int Invoke(int dispId, ref Guid iid, uint lcid, ushort flags,
                ref DISPPARAMS parameters,
                [MarshalAs(UnmanagedType.Struct)] out object result,
                ref EXCEPINFO exception, out uint argumentError);
        }

        /// <summary>Минимальный late-binding поверх IDispatch, не использующий type library.</summary>
        private sealed class DispatchProxy : DynamicObject
        {
            private const ushort DispatchMethod = 0x1;
            private readonly object _instance;
            private readonly IDispatch _dispatch;
            private readonly IntPtr _activationContext;

            public DispatchProxy(object instance, IntPtr activationContext)
            {
                _instance = instance ?? throw new ArgumentNullException(nameof(instance));
                _dispatch = (IDispatch)instance;
                _activationContext = activationContext;
            }

            public override bool TryInvokeMember(InvokeMemberBinder binder, object[] args, out object result)
            {
                result = Invoke(binder.Name, args ?? Array.Empty<object>());
                return true;
            }

            private object Invoke(string name, object[] args)
            {
                using var activation = new ActivationScope(_activationContext);
                Guid iid = IID_NULL;
                int hr = _dispatch.GetIDsOfNames(ref iid, new[] { name }, 1, 0, out int dispId);
                if (hr < 0)
                    throw new InvalidOperationException(
                        Strings.Format("err.com.call", name, $"0x{hr:X8}"),
                        Marshal.GetExceptionForHR(hr));

                int variantSize = IntPtr.Size == 8 ? 24 : 16;
                IntPtr variants = args.Length == 0
                    ? IntPtr.Zero
                    : Marshal.AllocCoTaskMem(variantSize * args.Length);
                int initialized = 0;
                try
                {
                    // COM принимает позиционные параметры справа налево.
                    for (int i = 0; i < args.Length; i++)
                    {
                        object argument = args[args.Length - 1 - i];
                        if (argument is DispatchProxy proxy) argument = proxy._instance;
                        Marshal.GetNativeVariantForObject(argument, IntPtr.Add(variants, i * variantSize));
                        initialized++;
                    }

                    var parameters = new DISPPARAMS
                    {
                        rgvarg = variants,
                        cArgs = args.Length,
                        rgdispidNamedArgs = IntPtr.Zero,
                        cNamedArgs = 0,
                    };
                    var exception = new EXCEPINFO();
                    hr = _dispatch.Invoke(dispId, ref iid, 0, DispatchMethod, ref parameters,
                                          out object value, ref exception, out uint argumentError);
                    if (hr < 0)
                    {
                        int code = exception.scode < 0 ? exception.scode : hr;
                        string detail = exception.bstrDescription;
                        if (string.IsNullOrWhiteSpace(detail))
                            detail = $"0x{code:X8}" + (argumentError < args.Length
                                ? $", {ComArgumentDetail(argumentError)}"
                                : string.Empty);
                        throw new InvalidOperationException(
                            Strings.Format("err.com.call", name, detail),
                            Marshal.GetExceptionForHR(code));
                    }
                    return value != null && Marshal.IsComObject(value)
                        ? new DispatchProxy(value, _activationContext)
                        : value;
                }
                finally
                {
                    for (int i = 0; i < initialized; i++)
                        _ = VariantClear(IntPtr.Add(variants, i * variantSize));
                    if (variants != IntPtr.Zero) Marshal.FreeCoTaskMem(variants);
                }
            }
        }

        internal static string ComArgumentDetail(uint index) =>
            Strings.Format("err.com.argument", index);

        [DllImport("oleaut32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int VariantClear(IntPtr variant);

        // rtCOMLite.Acquire внутри DLL обращается к собственной typelib через LoadRegTypeLib.
        // Одной загрузки DllGetClassObject поэтому недостаточно: без этой process-local
        // activation context метод возвращает TYPE_E_LIBNOTREGISTERED.
        private static IntPtr ActivationContext(string dllPath)
        {
            lock (ActivationContexts)
            {
                if (ActivationContexts.TryGetValue(dllPath, out IntPtr existing)) return existing;

                string directory = Path.GetDirectoryName(Path.GetFullPath(dllPath));
                string manifest = Path.Combine(directory, "CryptoProExport.rtCOMLite.manifest");
                const string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" +
                    "<assemblyIdentity type=\"win32\" name=\"CryptoProExport.rtCOMLite\" version=\"1.0.0.0\"/>" +
                    "<file name=\"rtCOMLite.dll\">" +
                    "<comClass clsid=\"{0ACACF07-54A6-4230-8FA2-6CBBE9B87BB9}\" " +
                    "threadingModel=\"Apartment\" progid=\"rtCOMLite.rtContext\" " +
                    "tlbid=\"{3F94932F-F056-4F0D-92EA-AD21DA679191}\"/>" +
                    "<typelib tlbid=\"{3F94932F-F056-4F0D-92EA-AD21DA679191}\" " +
                    "version=\"1.0\" helpdir=\"\" resourceid=\"1\"/>" +
                    "</file></assembly>";
                if (!File.Exists(manifest) || File.ReadAllText(manifest) != xml)
                {
                    string temporary = manifest + "." + Guid.NewGuid().ToString("N") + ".tmp";
                    File.WriteAllText(temporary, xml);
                    try { File.Move(temporary, manifest, overwrite: true); }
                    finally { if (File.Exists(temporary)) File.Delete(temporary); }
                }

                var act = new ACTCTX
                {
                    cbSize = Marshal.SizeOf<ACTCTX>(),
                    dwFlags = 0x4, // ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID
                    lpSource = manifest,
                    lpAssemblyDirectory = directory,
                };
                IntPtr handle = CreateActCtx(ref act);
                if (handle == new IntPtr(-1))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                ActivationContexts[dllPath] = handle;
                return handle;
            }
        }

        private readonly struct ActivationScope : IDisposable
        {
            private readonly IntPtr _cookie;

            public ActivationScope(IntPtr context)
            {
                if (!ActivateActCtx(context, out _cookie))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            public void Dispose()
            {
                if (_cookie != IntPtr.Zero) DeactivateActCtx(0, _cookie);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ACTCTX
        {
            public int cbSize;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpSource;
            public ushort wProcessorArchitecture;
            public ushort wLangId;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpAssemblyDirectory;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpResourceName;
            [MarshalAs(UnmanagedType.LPWStr)] public string lpApplicationName;
            public IntPtr hModule;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern IntPtr CreateActCtx(ref ACTCTX actctx);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ActivateActCtx(IntPtr actctx, out IntPtr cookie);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeactivateActCtx(uint flags, IntPtr cookie);

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
                detail = Strings.Get("diag.arch.unknown");
                return false;
            }
            detail = Strings.Format("diag.arch", Name(machine.Value), Name(process));
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
