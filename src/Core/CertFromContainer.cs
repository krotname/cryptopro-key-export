using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Извлечение сертификата из контейнера КриптоПро через CryptoAPI.
    /// Порт ветки CertFix (CryptAcquireContext → CryptGetUserKey → CryptGetKeyParam(KP_CERTIFICATE)).
    ///
    /// Сертификат в контейнере — открытые данные и доступен без снятия запрета на экспорт,
    /// поэтому его можно вытащить штатно, пока контейнер виден CSP (в т.ч. пока вставлен токен).
    /// Полученный .cer затем передаётся p12utility --cprepair как --cert/--certsg.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class CertFromContainer
    {
        // Типы провайдеров КриптоПро
        public static readonly (uint type, string name)[] Providers =
        {
            (80u, "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider"),        // ГОСТ-2012 256
            (81u, "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider"), // ГОСТ-2012 512
            (75u, "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"),        // ГОСТ-2001
        };

        /// <summary>Ключ обмена (AT_KEYEXCHANGE).</summary>
        public const uint AT_KEYEXCHANGE = 1;
        /// <summary>Ключ подписи (AT_SIGNATURE).</summary>
        public const uint AT_SIGNATURE = 2;

        private const uint KP_CERTIFICATE = 26;
        private const uint KP_PERMISSIONS = 6;
        private const uint CRYPT_EXPORT = 0x0004;
        private const uint PP_ENUMCONTAINERS = 2;
        private const uint CRYPT_FIRST = 1;
        private const uint CRYPT_NEXT  = 2;
        private const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        private const uint CRYPT_SILENT = 0x40;

        public sealed class ContainerRef
        {
            public string Name;      // уникальное имя контейнера
            public string Provider;
            public uint ProvType;
            public override string ToString() => $"{Name} [{ProvType}]";
        }

        public sealed class ExtractedCerts
        {
            public byte[] Exchange;  // DER сертификата ключа обмена (AT_KEYEXCHANGE)
            public byte[] Signature; // DER сертификата ключа подписи (AT_SIGNATURE)
            public bool Any => Exchange != null || Signature != null;
        }

        /// <summary>
        /// Перечислить контейнеры по всем провайдерам КриптоПро (видимые CSP, включая токены).
        /// Имена декодируются из cp1251 (в этой кодировке их отдаёт PP_ENUMCONTAINERS),
        /// дедуп по имени: один контейнер виден сразу под несколькими типами провайдера.
        /// </summary>
        public static List<ContainerRef> EnumContainers()
        {
            var result = new List<ContainerRef>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (type, name) in Providers)
            {
                if (!CryptAcquireContext(out IntPtr hProv, null, name, type, CRYPT_VERIFYCONTEXT))
                    continue;
                try
                {
                    uint flag = CRYPT_FIRST;
                    while (true)
                    {
                        uint len = 0;
                        if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, null, ref len, flag) || len == 0)
                            break;
                        var buf = new byte[len];
                        if (!CryptGetProvParam(hProv, PP_ENUMCONTAINERS, buf, ref len, flag))
                            break;
                        int zero = Array.IndexOf(buf, (byte)0);
                        if (zero < 0) zero = (int)len;
                        string cn = Cp1251.GetString(buf, 0, zero);
                        if (!string.IsNullOrEmpty(cn) && seen.Add(cn))
                            result.Add(new ContainerRef { Name = cn, Provider = name, ProvType = type });
                        flag = CRYPT_NEXT;
                    }
                }
                finally { CryptReleaseContext(hProv, 0); }
            }
            return result;
        }

        /// <summary>
        /// Типы провайдеров КриптоПро, доступных в системе (проверка CryptAcquireContext
        /// с CRYPT_VERIFYCONTEXT — без обращения к контейнеру). Пустой список = CSP не установлен.
        /// </summary>
        public static List<uint> AvailableProviders()
        {
            var list = new List<uint>();
            foreach (var (type, name) in Providers)
            {
                if (!CryptAcquireContext(out IntPtr hProv, null, name, type, CRYPT_VERIFYCONTEXT)) continue;
                CryptReleaseContext(hProv, 0);
                list.Add(type);
            }
            return list;
        }

        /// <summary>Извлечь DER сертификата для заданного keySpec из контейнера.</summary>
        public static byte[] ExtractCert(string container, string provider, uint provType, uint keySpec, bool silent = true)
        {
            uint flags = silent ? CRYPT_SILENT : 0;
            if (!CryptAcquireContext(out IntPtr hProv, container, provider, provType, flags))
                return null;
            try
            {
                if (!CryptGetUserKey(hProv, keySpec, out IntPtr hKey))
                    return null;
                try
                {
                    uint len = 0;
                    if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, null, ref len, 0) || len == 0)
                        return null;
                    var buf = new byte[len];
                    if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, buf, ref len, 0))
                        return null;
                    return buf;
                }
                finally { CryptDestroyKey(hKey); }
            }
            finally { CryptReleaseContext(hProv, 0); }
        }

        /// <summary>Результат проверки «снят ли запрет на экспорт закрытого ключа».</summary>
        public sealed class ExportCheck
        {
            /// <summary>Контейнер найден и в нём есть ключ такого типа.</summary>
            public bool KeyFound;
            /// <summary>Ключ помечен экспортируемым (в KP_PERMISSIONS взведён CRYPT_EXPORT).</summary>
            public bool Exportable;
            /// <summary>Сырое значение KP_PERMISSIONS — полезно в логе при разборе.</summary>
            public uint Permissions;
            /// <summary>Код ошибки, если права прочитать не удалось.</summary>
            public int Error;

            public override string ToString() =>
                !KeyFound ? Strings.Get("key.notfound")
                : Error != 0 ? Strings.Format("key.readfail", CryptoErrors.Describe(Error))
                : Strings.Format(Exportable ? "key.exportable" : "key.locked", Permissions.ToString("X8", CultureInfo.InvariantCulture));
        }

        /// <summary>
        /// Проверить, снят ли запрет на экспорт закрытого ключа: читает права ключа
        /// (KP_PERMISSIONS) и смотрит флаг CRYPT_EXPORT. Сам ключ при этом не выгружается.
        ///
        /// Именно так проверяется, что «Сделать экспортируемым» сработало. Прямой CryptExportKey
        /// для проверки не годится: КриптоПро отвечает NTE_BAD_KEY_STATE и на экспортируемый ключ —
        /// выгрузка идёт другим путём (PFXExportCertStoreEx внутри certmgr).
        /// </summary>
        public static ExportCheck CheckExportable(string container, uint keySpec = AT_KEYEXCHANGE)
        {
            var result = new ExportCheck();
            foreach (var (type, name) in Providers)
            {
                if (!CryptAcquireContext(out IntPtr hProv, container, name, type, CRYPT_SILENT))
                    continue;
                try
                {
                    if (!CryptGetUserKey(hProv, keySpec, out IntPtr hKey))
                        continue;
                    try
                    {
                        result.KeyFound = true;
                        var buf = new byte[4];
                        uint len = (uint)buf.Length;
                        if (!CryptGetKeyParam(hKey, KP_PERMISSIONS, buf, ref len, 0))
                        {
                            result.Error = Marshal.GetLastWin32Error();
                            return result;
                        }
                        result.Permissions = BitConverter.ToUInt32(buf, 0);
                        result.Exportable = (result.Permissions & CRYPT_EXPORT) != 0;
                        return result;
                    }
                    finally { CryptDestroyKey(hKey); }
                }
                finally { CryptReleaseContext(hProv, 0); }
            }
            return result;
        }

        /// <summary>Подобрать провайдер и извлечь оба сертификата (обмена/подписи) по имени контейнера.</summary>
        public static ExtractedCerts Extract(string container)
        {
            foreach (var (type, name) in Providers)
            {
                var ex = ExtractCert(container, name, type, AT_KEYEXCHANGE);
                var sg = ExtractCert(container, name, type, AT_SIGNATURE);
                if (ex != null || sg != null)
                    return new ExtractedCerts { Exchange = ex, Signature = sg };
            }
            return new ExtractedCerts();
        }

        /// <summary>
        /// Извлечь сертификаты по имени контейнера и сохранить .cer в папку.
        /// Возвращает пути (exchangeCerPath, signatureCerPath); любой из них null, если нет.
        /// </summary>
        public static (string exchange, string signature) SaveCerts(string container, string outFolder)
        {
            Directory.CreateDirectory(outFolder);
            var certs = Extract(container);
            string ex = null, sg = null;
            if (certs.Exchange != null)
            {
                ex = Path.Combine(outFolder, "cert_exchange.cer");
                File.WriteAllBytes(ex, certs.Exchange);
            }
            if (certs.Signature != null)
            {
                sg = Path.Combine(outFolder, "cert_signature.cer");
                File.WriteAllBytes(sg, certs.Signature);
            }
            return (ex, sg);
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptAcquireContextW")]
        private static extern bool CryptAcquireContext(out IntPtr phProv, string container, string provider, uint provType, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptReleaseContext(IntPtr hProv, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptGetUserKey(IntPtr hProv, uint keySpec, out IntPtr phUserKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CryptGetKeyParam(IntPtr hKey, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CryptGetProvParam(IntPtr hProv, uint dwParam, byte[] pbData, ref uint pdwDataLen, uint dwFlags);

    }
}
