// Лицензирование CryptoProExport: офлайн-проверка файла лицензии продукта cryptoexport,
// выпущенного сервером активации krotname/license-server. Проверка подписи — вендоренным
// референс-клиентом (src/Core/Licensing/*, инвариант «доверие во вшитом ключе, не в домене»).
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using KrotName.Licensing;
using Microsoft.Win32;

namespace CryptoProExport
{
    /// <summary>Итог проверки лицензии.</summary>
    public enum LicenseState
    {
        /// <summary>Файла лицензии нет.</summary>
        None,

        /// <summary>Лицензия проверена и действительна для этой машины.</summary>
        Valid,

        /// <summary>Файл есть, но не прошёл проверку (чужая машина, битая подпись, истёк срок…).</summary>
        Invalid
    }

    /// <summary>Разобранный статус лицензии для показа и для гейта операций.</summary>
    public sealed class LicenseInfo
    {
        internal LicenseInfo(LicenseState state, LicensePayload? payload = null, string? reason = null)
        {
            State = state;
            Payload = payload;
            Reason = reason;
        }

        /// <summary>Состояние лицензии.</summary>
        public LicenseState State { get; }

        /// <summary>Разобранная нагрузка для <see cref="LicenseState.Valid"/>; иначе <c>null</c>.</summary>
        public LicensePayload? Payload { get; }

        /// <summary>Причина отказа для <see cref="LicenseState.Invalid"/> (для лога, не для пользователя).</summary>
        public string? Reason { get; }

        /// <summary>Действительная лицензия — операции экспорта закрытого ключа разрешены.</summary>
        public bool Ok => State == LicenseState.Valid;
    }

    /// <summary>
    /// Гейт лицензии продукта <c>cryptoexport</c>. Доверие — во <b>вшитом</b> публичном ключе
    /// активации (не в домене и не в TLS): любой файл лицензии проверяется офлайн этим ключом
    /// (PROTOCOL §2.5). Сеть при проверке не используется.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class LicenseGate
    {
        /// <summary>Id продукта в файле лицензии (PROTOCOL §3.1).</summary>
        public const string ProductId = "cryptoexport";

        /// <summary>Id вшитого ключа подписи; должен совпадать с <c>kid</c> заголовка лицензии.</summary>
        public const string Kid = "cryptoexport-2026";

        /// <summary>
        /// Публичный ключ активации (base64 SubjectPublicKeyInfo, P-256). Пара к нему на сервере
        /// активации; приватная часть в код не попадает. Отпечаток — sha256:93cd9447…
        /// (сверка: keytool show --pub &lt;этот ключ&gt;).
        /// </summary>
        public const string PublicKeyB64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHymaM2huAnl1OJezSCr2btoRUp4j3ud3KEEFmnTIjsWSrVpfSqdVlZSs5k0e39yYABbv/d6eM4eP4VGKajgPYg==";

        private static readonly LicenseVerifier Verifier = new(
            ProductId,
            Platform.Windows,
            new Dictionary<string, string> { [Kid] = PublicKeyB64 });

        /// <summary>Файл установленной лицензии (рядом с журналами и настройками языка).</summary>
        public static string LicensePath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CryptoProExport", "license.jws");

        /// <summary>
        /// Отпечаток этой машины (PROTOCOL §1a.3, windows): <c>sha256:&lt;hex&gt;</c> от стабильного
        /// идентификатора установки. Сырой идентификатор наружу не отдаётся — только хэш (§10).
        /// </summary>
        public static string Fingerprint()
        {
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(MachineIdentity()));
            return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        /// <summary>
        /// Стабильный идентификатор установки: MachineGuid из реестра (тот же при переустановке ОС
        /// не сохраняется — это ожидаемо, лицензия привязана к установке). Явно берём 64-битное
        /// представление реестра, чтобы x86-процесс в WOW64 читал тот же ключ, что и 64-битный.
        /// </summary>
        private static string MachineIdentity()
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                if (key?.GetValue("MachineGuid") is string guid && !string.IsNullOrWhiteSpace(guid))
                {
                    return "MachineGuid:" + guid.Trim();
                }
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                // Реестр недоступен — падать нельзя: отпечаток всё равно должен получиться.
            }

            return "MachineName:" + Environment.MachineName;
        }

        /// <summary>Проверить установленную лицензию (читает <see cref="LicensePath"/>).</summary>
        public static LicenseInfo Check()
        {
            string path = LicensePath;
            string jws;
            try
            {
                if (!File.Exists(path))
                {
                    return new LicenseInfo(LicenseState.None);
                }

                jws = File.ReadAllText(path, Encoding.UTF8).Trim();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return new LicenseInfo(LicenseState.Invalid, reason: e.Message);
            }

            return Verify(jws);
        }

        /// <summary>Проверить произвольную строку лицензии, ничего не устанавливая.</summary>
        public static LicenseInfo Verify(string? compactJws)
        {
            try
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                // floor = 0: анти-откат времени (§2.7) не ведём — тестовые лицензии бессрочные,
                // а против отмотки часов у term защита всё равно мягкая (ARCHITECTURE §11).
                LicensePayload payload = Verifier.Verify(compactJws, Fingerprint(), null, now, 0);
                return new LicenseInfo(LicenseState.Valid, payload);
            }
            catch (LicenseException ex)
            {
                return new LicenseInfo(LicenseState.Invalid, reason: ex.Message);
            }
        }

        /// <summary>
        /// Установить файл лицензии: проверить и, только если он действителен для этой машины,
        /// скопировать в <see cref="LicensePath"/>. Недействительный файл не сохраняется.
        /// </summary>
        public static LicenseInfo Install(string sourcePath)
        {
            string jws = File.ReadAllText(sourcePath, Encoding.UTF8).Trim();
            LicenseInfo info = Verify(jws);
            if (!info.Ok)
            {
                return info;
            }

            string dir = Path.GetDirectoryName(LicensePath)!;
            Directory.CreateDirectory(dir);
            // Атомарная замена: пишем во временный файл рядом и подменяем им целевой. Прямой
            // WriteAllText усёк бы прежнюю рабочую лицензию до записи новой — при сбое диска остался
            // бы пустой/битый файл, и все gated-операции стали бы недоступны без причины.
            string tmp = LicensePath + ".tmp";
            File.WriteAllText(tmp, jws, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            File.Move(tmp, LicensePath, overwrite: true);
            return info;
        }

        /// <summary>Действительна ли установленная лицензия.</summary>
        public static bool IsLicensed() => Check().Ok;

        /// <summary>Локализованная строка статуса установленной лицензии (для лога/строки состояния).</summary>
        public static string StatusText() => Describe(Check());

        /// <summary>
        /// Локализованный статус конкретного результата проверки — <b>без повторного чтения файла</b>.
        /// Нужно, чтобы показать итог именно попытки установки, а не перечитать прежнюю лицензию: иначе
        /// отклонение выбранного файла при уже установленной валидной выглядело бы как успех.
        /// </summary>
        public static string Describe(LicenseInfo info) => info.State switch
        {
            LicenseState.Valid => Strings.Format("license.status.valid", TermText(info.Payload!)),
            // Причина отказа (Reason) — из вендоренного верификатора и всегда на русском: это
            // диагностика, а не локализуемый текст. Пользователю — общий локализованный статус,
            // конкретная причина остаётся для лога/stderr (см. Cli.license, MainForm.DoLicense).
            LicenseState.Invalid => Strings.Get("license.status.invalid"),
            _ => Strings.Get("license.status.none"),
        };

        /// <summary>Локализованная строка с отпечатком этой машины (для получения лицензии).</summary>
        public static string FingerprintText() => Strings.Format("license.fp", Fingerprint());

        private static string TermText(LicensePayload payload) =>
            payload.Exp is long exp
                ? Strings.Format("license.until",
                    DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime.ToString("yyyy-MM-dd"))
                : Strings.Get("license.perpetual");
    }
}
