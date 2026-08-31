// Лицензирование CryptoProExport: офлайн-проверка файла лицензии продукта cryptoexport,
// выпущенного сервером активации krotname/license-server. Проверка подписи — вендоренным
// референс-клиентом (src/Core/Licensing/*, инвариант «доверие во вшитом ключе, не в домене»).
#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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

    /// <summary>
    /// Причина отказа в лицензии — код, который переводится таблицей i18n. Сообщение верификатора
    /// для показа не годится: оно всегда на русском (диагностика протокола), а объяснение читает
    /// владелец на своём языке. Имеет смысл только при <see cref="LicenseState.Invalid"/>.
    /// </summary>
    public enum LicenseFailureCode
    {
        /// <summary>Файл не читается как лицензия: нарушен формат или схема нагрузки.</summary>
        Unreadable,

        /// <summary>Подпись не прошла проверку либо её kid отсутствует среди доверенных ключей.</summary>
        InvalidSignature,

        /// <summary>Лицензия выдана другому продукту.</summary>
        OtherProduct,

        /// <summary>Лицензия выдана для другой платформы (частый случай — файл от Android-сборки).</summary>
        OtherPlatform,

        /// <summary>Лицензия выдана для другой машины: отпечаток не совпадает.</summary>
        OtherMachine,

        /// <summary>Срок действия лицензии истёк.</summary>
        Expired
    }

    /// <summary>
    /// Типизированная причина отказа и безопасная деталь для локализованного сообщения.
    /// Значения отпечатка и подписи сюда намеренно не попадают: для них достаточно кода.
    /// </summary>
    /// <param name="Code">Стабильный код причины, не зависящий от языка верификатора.</param>
    /// <param name="Detail">Id продукта, код платформы или дата истечения; иначе <c>null</c>.</param>
    public sealed record LicenseFailureInfo(LicenseFailureCode Code, string? Detail = null);

    /// <summary>Разобранный статус лицензии для показа и для гейта операций.</summary>
    public sealed class LicenseInfo
    {
        internal LicenseInfo(LicenseState state, LicensePayload? payload = null, string? verifierDiagnostic = null,
            LicenseFailureInfo? failure = null)
        {
            State = state;
            Payload = payload;
            VerifierDiagnostic = verifierDiagnostic;
            Failure = failure ?? new LicenseFailureInfo(LicenseFailureCode.Unreadable);
        }

        /// <summary>Состояние лицензии.</summary>
        public LicenseState State { get; }

        /// <summary>Разобранная нагрузка для <see cref="LicenseState.Valid"/>; иначе <c>null</c>.</summary>
        public LicensePayload? Payload { get; }

        /// <summary>
        /// Точная диагностика верификатора для файла журнала. Она не локализована и не должна
        /// попадать в GUI или stderr; пользовательский текст даёт <see cref="LicenseGate.ReasonText"/>.
        /// </summary>
        public string? VerifierDiagnostic { get; }

        /// <summary>Структурированная причина; раскрывается локализованным <see cref="LicenseGate.ReasonText"/>.</summary>
        public LicenseFailureInfo Failure { get; }

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

        /// <summary>Вшитые публичные ключи подписи по kid — единственный источник доверия.</summary>
        private static readonly Dictionary<string, string> SigningKeys = new() { [Kid] = PublicKeyB64 };

        private static readonly LicenseVerifier Verifier = new(ProductId, Platform.Windows, SigningKeys);

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
                return new LicenseInfo(LicenseState.Invalid, verifierDiagnostic: e.Message);
            }

            return Verify(jws);
        }

        /// <summary>Проверить произвольную строку лицензии, ничего не устанавливая.</summary>
        public static LicenseInfo Verify(string? compactJws)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            try
            {
                // floor = 0: анти-откат времени (§2.7) не ведём — тестовые лицензии бессрочные,
                // а против отмотки часов у term защита всё равно мягкая (ARCHITECTURE §11).
                LicensePayload payload = Verifier.Verify(compactJws, Fingerprint(), null, now, 0);
                return new LicenseInfo(LicenseState.Valid, payload);
            }
            catch (LicenseException ex)
            {
                LicenseFailureInfo failure = Classify(compactJws, now);
                return new LicenseInfo(LicenseState.Invalid, verifierDiagnostic: ex.Message, failure: failure);
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
            // VerifierDiagnostic всегда на русском: это диагностика протокола только для файла
            // журнала. Пользователь получает общий статус здесь и локализованный ReasonText ниже.
            LicenseState.Invalid => Strings.Get("license.status.invalid"),
            _ => Strings.Get("license.status.none"),
        };

        /// <summary>Локализованная строка с отпечатком этой машины (для получения лицензии).</summary>
        public static string FingerprintText() => Strings.Format("license.fp", Fingerprint());

        /// <summary>
        /// Локализованная причина отказа — то, что владелец видит в журнале и в stderr вместо
        /// русской диагностики верификатора.
        /// </summary>
        public static string ReasonText(LicenseInfo info) => info.Failure.Code switch
        {
            LicenseFailureCode.InvalidSignature => Strings.Get("license.reason.signature"),
            LicenseFailureCode.OtherProduct => Strings.Format("license.reason.product", info.Failure.Detail ?? "?"),
            LicenseFailureCode.OtherPlatform => Strings.Format("license.reason.platform", info.Failure.Detail ?? "?"),
            LicenseFailureCode.OtherMachine => Strings.Get("license.reason.machine"),
            LicenseFailureCode.Expired => Strings.Format("license.reason.expired", info.Failure.Detail ?? "?"),
            _ => Strings.Get("license.reason.unreadable"),
        };

        /// <summary>
        /// Определяет причину отказа по нагрузке самого файла — только чтобы назвать её владельцу.
        /// Прав это не даёт: решение уже принято верификатором выше, здесь файлу ничему не верят.
        /// Чтобы подделка не объявлялась «лицензией для другой машины», файл сперва проверяется тем же
        /// вендоренным верификатором «сам с собой»: продукт, платформа, отпечаток и время берутся из его
        /// же подписанной нагрузки. Провал подписи получает отдельный безопасный код, но поля нагрузки
        /// при этом не читаются и не раскрываются.
        /// </summary>
        private static LicenseFailureInfo Classify(string? compactJws, long now) =>
            Classify(compactJws, now, SigningKeys);

        /// <summary>Та же разборка причины, но с явным набором ключей подписи — для тестов.</summary>
        internal static LicenseFailureInfo Classify(string? compactJws, long now,
            IReadOnlyDictionary<string, string> signingKeys)
        {
            var unreadable = new LicenseFailureInfo(LicenseFailureCode.Unreadable);
            string[] parts = (compactJws ?? string.Empty).Split('.');
            if (parts.Length != 3 || Array.Exists(parts, string.IsNullOrEmpty)) return unreadable;

            SignatureCheck signature = CheckSignature(parts, signingKeys);
            if (signature == SignatureCheck.Invalid)
                return new LicenseFailureInfo(LicenseFailureCode.InvalidSignature);
            if (signature != SignatureCheck.Valid) return unreadable;

            string? pid, plat, fp;
            long? exp;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(Base64Url(parts[1]));
                JsonElement payload = doc.RootElement;
                if (payload.ValueKind != JsonValueKind.Object) return unreadable;
                pid = Text(payload, "pid");
                plat = Text(payload, "plat");
                fp = Text(payload, "fp");
                exp = payload.TryGetProperty("exp", out JsonElement e) && e.ValueKind == JsonValueKind.Number
                          && e.TryGetInt64(out long seconds)
                      ? seconds
                      : null;
            }
            catch (Exception e) when (e is JsonException or FormatException)
            {
                return unreadable;
            }

            if (pid is null || fp is null || !Codes.TryParsePlatform(plat, out Platform platform)) return unreadable;

            // Момент, в который срок этой лицензии заведомо не истёк: иначе просроченный файл
            // не прошёл бы и проверку «сам с собой», и причина потерялась бы.
            long probe = exp is long until && until <= now
                ? (until == long.MinValue ? long.MinValue : until - 1)
                : now;
            try
            {
                new LicenseVerifier(pid, platform, signingKeys).Verify(compactJws, fp, null, probe, 0);
            }
            catch (LicenseException)
            {
                return unreadable;
            }

            // Порядок — как в §2.5: продукт, платформа, отпечаток, срок.
            if (!string.Equals(pid, ProductId, StringComparison.Ordinal))
                return new LicenseFailureInfo(LicenseFailureCode.OtherProduct, pid);
            if (platform != Platform.Windows)
                return new LicenseFailureInfo(LicenseFailureCode.OtherPlatform, plat);
            if (!string.Equals(fp, Fingerprint(), StringComparison.Ordinal))
                return new LicenseFailureInfo(LicenseFailureCode.OtherMachine);
            if (exp is long stamp && stamp + LicenseVerifier.ClockSkewSeconds <= now)
            {
                return new LicenseFailureInfo(LicenseFailureCode.Expired, Date(stamp));
            }

            return unreadable;
        }

        /// <summary>
        /// Проверяет только JWS-подпись для диагностической классификации. Решение о правах
        /// по-прежнему принимает единственный вендоренный <see cref="LicenseVerifier"/> выше.
        /// Нагрузка читается только после результата <see cref="SignatureCheck.Valid"/>.
        /// </summary>
        private static SignatureCheck CheckSignature(string[] parts,
            IReadOnlyDictionary<string, string> signingKeys)
        {
            string? kid;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(Base64Url(parts[0]));
                JsonElement header = doc.RootElement;
                if (header.ValueKind != JsonValueKind.Object
                    || !string.Equals(Text(header, "alg"), "ES256", StringComparison.Ordinal)
                    || !string.Equals(Text(header, "typ"), "JWT", StringComparison.Ordinal))
                    return SignatureCheck.Unreadable;
                kid = Text(header, "kid");
            }
            catch (Exception e) when (e is JsonException or FormatException)
            {
                return SignatureCheck.Unreadable;
            }

            if (kid is null || !signingKeys.TryGetValue(kid, out string? spkiBase64))
                return SignatureCheck.Invalid;

            byte[] signature;
            try
            {
                signature = Base64Url(parts[2]);
            }
            catch (FormatException)
            {
                return SignatureCheck.Invalid;
            }
            if (signature.Length != 64) return SignatureCheck.Invalid;

            using var ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spkiBase64), out _);
                byte[] signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
                return ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256)
                    ? SignatureCheck.Valid
                    : SignatureCheck.Invalid;
            }
            catch (Exception e) when (e is FormatException or CryptographicException)
            {
                // Битый вшитый публичный ключ — ошибка конфигурации, а не доказанная проблема подписи файла.
                return SignatureCheck.Unreadable;
            }
        }

        private enum SignatureCheck
        {
            Unreadable,
            Invalid,
            Valid,
        }

        /// <summary>Дата протокола, yyyy-MM-dd: инвариантная культура, иначе на персидской или
        /// тайской локали Windows вышел бы другой календарь.</summary>
        private static string Date(long unixSeconds)
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).UtcDateTime
                    .ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            }
            catch (ArgumentOutOfRangeException)
            {
                // Формально корректный Int64 может лежать за пределами календаря .NET.
                return unixSeconds.ToString(CultureInfo.InvariantCulture);
            }
        }

        private static string? Text(JsonElement payload, string name) =>
            payload.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

        /// <summary>base64url без выравнивания — как части JWS лежат в файле (§2.2).</summary>
        private static byte[] Base64Url(string part)
        {
            string b64 = part.Replace('-', '+').Replace('_', '/');
            return Convert.FromBase64String(b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '='));
        }

        private static string TermText(LicensePayload payload) =>
            payload.Exp is long exp
                ? Strings.Format("license.until", Date(exp))
                : Strings.Get("license.perpetual");
    }
}
