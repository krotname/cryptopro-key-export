// Вендорнуто из krotname/license-server, clients/dotnet/KrotName.Licensing (референс-клиент .NET).
// Источник правды — тот репозиторий; здесь копия, чтобы портативный exe оставался self-contained.
// Файл не редактировать вручную — при изменении протокола правится сначала license-server.
#nullable enable
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KrotName.Licensing;

/// <summary>
/// Офлайн-проверка файла лицензии — PROTOCOL §2.5. Референс-реализация для продуктов на .NET.
///
/// <para>Сеть не используется (инвариант №3). Из внешнего — только BCL: <c>System.Security.Cryptography</c>
/// и <c>System.Text.Json</c>; сторонних пакетов нет (инвариант №4).</para>
///
/// <para>Экземпляр создаётся один раз на запуск с вшитыми в сборку параметрами:</para>
/// <code>
/// var verifier = new LicenseVerifier("cryptoexport", Platform.Windows,
///     new Dictionary&lt;string, string&gt; { ["cryptoexport-2026"] = EmbeddedPublicKeyBase64 });
/// var license = verifier.Verify(licenseText, fingerprint, revokedIds, nowUnix, floorUnix);
/// </code>
/// </summary>
public sealed class LicenseVerifier
{
    /// <summary>Допуск на рассинхрон часов, ±24 часа (PROTOCOL §2.5 шаг 9).</summary>
    public const long ClockSkewSeconds = 24 * 60 * 60;

    private const int SignatureLength = 64; // r||s для P-256

    private readonly string _productId;
    private readonly Platform _platform;
    private readonly IReadOnlyDictionary<string, string> _activeKeys;

    /// <param name="productId">Id продукта этой сборки.</param>
    /// <param name="platform">Платформа этой сборки.</param>
    /// <param name="activeKeysBySpkiBase64">
    /// Публичные ключи со статусом active по kid: base64 SubjectPublicKeyInfo. Вшиваются в сборку
    /// и/или берутся из проверенной «карты доверия» (§4).
    /// </param>
    public LicenseVerifier(string productId, Platform platform,
        IReadOnlyDictionary<string, string> activeKeysBySpkiBase64)
    {
        _productId = productId ?? throw new ArgumentNullException(nameof(productId));
        _platform = platform;
        _activeKeys = activeKeysBySpkiBase64 ?? throw new ArgumentNullException(nameof(activeKeysBySpkiBase64));
    }

    /// <summary>
    /// Проверяет лицензию целиком и возвращает нагрузку, если она действительна.
    /// </summary>
    /// <param name="compactJws">Строка лицензии.</param>
    /// <param name="fingerprint">Отпечаток текущей машины/установки, sha256:&lt;64 hex&gt;.</param>
    /// <param name="revoked">
    /// Отозванные lid из последней известной карты доверия; пустой список — не повод для отказа,
    /// карта могла быть недоступна (мягкий отзыв, §4).
    /// </param>
    /// <param name="nowUnixSeconds">Системное время, unix-секунды.</param>
    /// <param name="floorUnixSeconds">
    /// Нижняя граница времени из §2.7 — максимум <b>аутентифицированных</b> значений (iat ранее
    /// проверенных лицензий, iat карты доверия). Неподписанный server_time сюда попадать не должен.
    /// </param>
    /// <exception cref="LicenseException">Проверка не прошла; сообщение указывает, на каком шаге.</exception>
    public LicensePayload Verify(string? compactJws, string? fingerprint, IEnumerable<string>? revoked,
        long nowUnixSeconds, long floorUnixSeconds)
    {
        // Шаг 1: три непустые части.
        var parts = Split(compactJws);

        // Шаг 2: заголовок. Из него берутся только alg/typ/kid — выбор ключа, а не решения о правах.
        var header = ParseObject(Decode(parts[0], "заголовок"), "заголовок");
        RequireEquals(GetString(header, "alg"), "ES256", "alg");
        RequireEquals(GetString(header, "typ"), "JWT", "typ заголовка");
        var kid = GetString(header, "kid") ?? throw new LicenseException("в заголовке нет kid");

        // Шаг 3: ключ по kid. Нет ключа — отказ до всякой криптографии.
        if (!_activeKeys.TryGetValue(kid, out var spkiBase64))
        {
            throw new LicenseException($"нет активного публичного ключа с kid {kid}");
        }

        // Шаг 4: подпись — ДО чтения любого поля нагрузки.
        var signature = Decode64Url(parts[2], "подпись");
        if (signature.Length != SignatureLength)
        {
            throw new LicenseException($"подпись ES256 должна быть {SignatureLength} байта, получено {signature.Length}");
        }

        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        using var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(spkiBase64), out _);
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            throw new LicenseException($"не удалось загрузить публичный ключ {kid}: {e.Message}");
        }

        RequireP256(ecdsa, kid);

        // VerifyData ожидает подпись в формате r||s — ровно так она и лежит в JWS (§2.4).
        if (!ecdsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256))
        {
            throw new LicenseException("подпись лицензии неверна");
        }

        var payload = ParsePayload(Decode(parts[1], "полезная нагрузка"));

        // Шаг 5: kid в нагрузке дублирует заголовок — иначе подменённый заголовок увёл бы выбор ключа.
        if (!string.Equals(payload.Kid, kid, StringComparison.Ordinal))
        {
            throw new LicenseException("kid в заголовке и в нагрузке не совпадают");
        }

        // Шаг 6: продукт и платформа.
        if (!string.Equals(payload.Pid, _productId, StringComparison.Ordinal))
        {
            throw new LicenseException($"лицензия выдана другому продукту: {payload.Pid}");
        }

        if (payload.Plat != _platform)
        {
            throw new LicenseException($"лицензия выдана для платформы {payload.Plat.ToCode()}");
        }

        // Шаг 7: отпечаток.
        if (fingerprint is null || !string.Equals(fingerprint, payload.Fp, StringComparison.Ordinal))
        {
            throw new LicenseException("лицензия выдана для другой машины");
        }

        // Шаг 8: мягкий отзыв.
        if (revoked is not null)
        {
            foreach (var lid in revoked)
            {
                if (string.Equals(lid, payload.Lid, StringComparison.Ordinal))
                {
                    throw new LicenseException("лицензия отозвана");
                }
            }
        }

        // Шаг 9: срок. Часы могли отстать, поэтому нижняя граница — max(системное время, floor).
        if (payload.Exp is { } exp)
        {
            var effectiveNow = Math.Max(nowUnixSeconds, floorUnixSeconds);
            if (exp + ClockSkewSeconds <= effectiveNow)
            {
                throw new LicenseException("срок действия лицензии истёк");
            }
        }

        return payload;
    }

    /// <summary>
    /// Новая нижняя граница времени по §2.7: max(текущая, iat проверенной лицензии).
    /// Метод существует, чтобы в floor не попадал неподписанный server_time.
    /// </summary>
    public static long AdvanceFloor(long currentFloor, LicensePayload verifiedPayload) =>
        Math.Max(currentFloor, verifiedPayload.Iat);

    /// <summary>
    /// Ключ обязан быть ровно на P-256. <c>ImportSubjectPublicKeyInfo</c> примет любую EC-кривую,
    /// и для другой 256-битной (например secp256k1) <c>VerifyData</c> тоже примет 64-байтовую
    /// подпись — то есть заголовок объявлял бы ES256, а проверка шла бы на другой кривой. Java-сторона
    /// (<c>EcKeys.decodePublic</c>) такие ключи отвергает, клиент обязан вести себя так же.
    /// </summary>
    private static void RequireP256(ECDsa ecdsa, string kid)
    {
        ECParameters parameters;
        try
        {
            parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        }
        catch (CryptographicException e)
        {
            throw new LicenseException($"не удалось прочитать параметры ключа {kid}: {e.Message}");
        }

        var curve = parameters.Curve;
        bool isP256;
        if (curve.IsNamed)
        {
            // OID prime256v1 (он же P-256, secp256r1). FriendlyName у разных платформ отличается,
            // поэтому OID — единственное надёжное сравнение, а имя проверяем как запасной вариант.
            isP256 = curve.Oid.Value == P256Oid
                     || (curve.Oid.Value is null && Array.IndexOf(P256Names, curve.Oid.FriendlyName ?? string.Empty) >= 0);
        }
        else
        {
            // Явно заданные параметры: сверяем то же, что и Java — простое поле, коэффициенты,
            // генератор, порядок и кофактор.
            isP256 = curve.IsPrime
                     && Equal(curve.Prime, P256Prime)
                     && Equal(curve.A, P256A)
                     && Equal(curve.B, P256B)
                     && Equal(curve.G.X, P256Gx)
                     && Equal(curve.G.Y, P256Gy)
                     && Equal(curve.Order, P256Order)
                     && (curve.Cofactor is null || IsOne(curve.Cofactor));
        }

        if (!isP256)
        {
            var name = curve.IsNamed ? curve.Oid.Value ?? curve.Oid.FriendlyName ?? "?" : "explicit";
            throw new LicenseException(
                $"ключ {kid} не на кривой P-256 ({name}): протокол зафиксирован на ES256/P-256");
        }
    }

    private const string P256Oid = "1.2.840.10045.3.1.7";

    private static readonly string[] P256Names = { "nistP256", "ECDSA_P256", "prime256v1", "secp256r1" };

    // Параметры P-256 (FIPS 186-4, D.1.2.3) — публичные константы стандарта.
    private static readonly byte[] P256Prime = Convert.FromHexString(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

    private static readonly byte[] P256A = Convert.FromHexString(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

    private static readonly byte[] P256B = Convert.FromHexString(
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

    private static readonly byte[] P256Gx = Convert.FromHexString(
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");

    private static readonly byte[] P256Gy = Convert.FromHexString(
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

    private static readonly byte[] P256Order = Convert.FromHexString(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    /// <summary>Сравнение с игнорированием ведущих нулей: длина представления может отличаться.</summary>
    private static bool Equal(byte[]? actual, byte[] expected)
    {
        if (actual is null)
        {
            return false;
        }

        var start = 0;
        while (start < actual.Length - 1 && actual[start] == 0)
        {
            start++;
        }

        var length = actual.Length - start;
        if (length != expected.Length)
        {
            return false;
        }

        for (var i = 0; i < length; i++)
        {
            if (actual[start + i] != expected[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsOne(byte[] value)
    {
        for (var i = 0; i < value.Length - 1; i++)
        {
            if (value[i] != 0)
            {
                return false;
            }
        }

        return value.Length > 0 && value[^1] == 1;
    }

    private static string[] Split(string? compactJws)
    {
        if (string.IsNullOrWhiteSpace(compactJws))
        {
            throw new LicenseException("лицензия отсутствует");
        }

        var parts = compactJws.Trim().Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
        {
            throw new LicenseException("лицензия должна состоять из трёх непустых частей, разделённых точкой");
        }

        return parts;
    }

    private static LicensePayload ParsePayload(string json)
    {
        var payload = ParseObject(json, "полезная нагрузка");

        var version = GetInt64(payload, "v");
        if (version != LicensePayload.Version)
        {
            throw new LicenseException($"неизвестная версия формата лицензии: {version}");
        }

        if (!Codes.TryParseLicenseType(GetString(payload, "typ"), out var typ))
        {
            throw new LicenseException($"неизвестный typ: {GetString(payload, "typ")}");
        }

        if (!Codes.TryParsePlatform(GetString(payload, "plat"), out var plat))
        {
            throw new LicenseException($"неизвестная платформа: {GetString(payload, "plat")}");
        }

        var exp = GetNullableInt64(payload, "exp");

        // Шаг 10: связь typ ↔ exp. Срочная лицензия без exp иначе стала бы бессрочной, а шаг 9
        // просто не сработал бы.
        if (typ == LicenseType.Perpetual && exp is not null)
        {
            throw new LicenseException("у perpetual не может быть exp");
        }

        if (typ != LicenseType.Perpetual && exp is null)
        {
            throw new LicenseException("у срочной лицензии exp обязателен");
        }

        var seats = GetNullableInt64(payload, "seats");
        if (seats is not null && (seats < 1 || seats > int.MaxValue))
        {
            throw new LicenseException($"поле seats вне допустимого диапазона: {seats}");
        }

        return new LicensePayload(
            RequireString(payload, "lid"),
            RequireString(payload, "aid"),
            RequireString(payload, "pid"),
            typ,
            plat,
            GetInt64(payload, "iat"),
            exp,
            RequireString(payload, "fp"),
            seats is null ? null : (int)seats.Value,
            GetStringArray(payload, "feat"),
            RequireString(payload, "kid"));
    }

    private static JsonElement ParseObject(string json, string what)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException e)
        {
            throw new LicenseException($"{what}: некорректный JSON — {e.Message}");
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new LicenseException($"{what} должна быть JSON-объектом");
            }

            return document.RootElement.Clone();
        }
    }

    private static string Decode(string part, string what) =>
        Encoding.UTF8.GetString(Decode64Url(part, what));

    private static byte[] Decode64Url(string part, string what)
    {
        // base64url без выравнивания (RFC 7515 §2): '-' → '+', '_' → '/', добить '=' до кратности 4.
        var builder = new StringBuilder(part.Length + 3);
        foreach (var c in part)
        {
            builder.Append(c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c
            });
        }

        while (builder.Length % 4 != 0)
        {
            builder.Append('=');
        }

        try
        {
            return Convert.FromBase64String(builder.ToString());
        }
        catch (FormatException)
        {
            throw new LicenseException($"{what}: некорректный base64url");
        }
    }

    private static void RequireEquals(string? actual, string expected, string what)
    {
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new LicenseException($"{what} должен быть {expected}, получено {actual ?? "null"}");
        }
    }

    private static string? GetString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string RequireString(JsonElement obj, string name) =>
        GetString(obj, name) ?? throw new LicenseException($"поле {name} должно быть строкой");

    private static long GetInt64(JsonElement obj, string name)
    {
        if (obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt64(out var result))
        {
            return result;
        }

        throw new LicenseException($"поле {name} должно быть целым числом");
    }

    private static long? GetNullableInt64(JsonElement obj, string name)
    {
        // Отсутствие поля и явный null — разные вещи: §2.3 требует присутствия всех полей.
        if (!obj.TryGetProperty(name, out var value))
        {
            throw new LicenseException($"отсутствует обязательное поле {name}");
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var result))
        {
            return result;
        }

        throw new LicenseException($"поле {name} должно быть целым числом или null");
    }

    private static IReadOnlyList<string> GetStringArray(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var value))
        {
            throw new LicenseException($"отсутствует обязательное поле {name}");
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new LicenseException($"поле {name} должно быть массивом строк");
        }

        var items = new List<string>(value.GetArrayLength());
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new LicenseException($"поле {name} должно содержать только строки");
            }

            items.Add(item.GetString()!);
        }

        return items;
    }
}
