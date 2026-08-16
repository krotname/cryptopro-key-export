// Вендорнуто из krotname/license-server, clients/dotnet/KrotName.Licensing (референс-клиент .NET).
// Источник правды — тот репозиторий; здесь копия, чтобы портативный exe оставался self-contained
// (кросс-репо ProjectReference не собрался бы на CI). При изменении протокола правится сначала
// license-server/docs/PROTOCOL.md, затем обе стороны. Файл не редактировать вручную.
#nullable enable
using System;
using System.Collections.Generic;

namespace KrotName.Licensing;

/// <summary>Тип лицензии — PROTOCOL §1a.1.</summary>
public enum LicenseType
{
    /// <summary>Навсегда: exp = null.</summary>
    Perpetual,

    /// <summary>На срок; продлевается через /v1/renew.</summary>
    Term,

    /// <summary>Ознакомительная: всегда на срок и на одно место, не продлевается.</summary>
    Trial
}

/// <summary>Платформа продукта и активации — PROTOCOL §1a.2.</summary>
public enum Platform
{
    /// <summary>Windows.</summary>
    Windows,

    /// <summary>macOS.</summary>
    MacOs,

    /// <summary>Linux.</summary>
    Linux,

    /// <summary>Android.</summary>
    Android,

    /// <summary>iOS.</summary>
    Ios,

    /// <summary>Веб-приложение, которое покупатель разворачивает у себя (self-hosted).</summary>
    Web
}

/// <summary>Разбор и запись кодов перечислений в том виде, в каком они лежат в JSON.</summary>
internal static class Codes
{
    internal static bool TryParseLicenseType(string? code, out LicenseType value)
    {
        switch (code)
        {
            case "perpetual": value = LicenseType.Perpetual; return true;
            case "term": value = LicenseType.Term; return true;
            case "trial": value = LicenseType.Trial; return true;
            default: value = default; return false;
        }
    }

    internal static bool TryParsePlatform(string? code, out Platform value)
    {
        switch (code)
        {
            case "windows": value = Platform.Windows; return true;
            case "macos": value = Platform.MacOs; return true;
            case "linux": value = Platform.Linux; return true;
            case "android": value = Platform.Android; return true;
            case "ios": value = Platform.Ios; return true;
            case "web": value = Platform.Web; return true;
            default: value = default; return false;
        }
    }

    internal static string ToCode(this Platform platform) => platform switch
    {
        Platform.Windows => "windows",
        Platform.MacOs => "macos",
        Platform.Linux => "linux",
        Platform.Android => "android",
        Platform.Ios => "ios",
        Platform.Web => "web",
        _ => throw new ArgumentOutOfRangeException(nameof(platform))
    };
}

/// <summary>
/// Полезная нагрузка файла лицензии — PROTOCOL §2.3.
/// </summary>
/// <param name="Lid">Id лицензии; по нему идёт продление.</param>
/// <param name="Aid">Id активации (эта машина/установка).</param>
/// <param name="Pid">Id продукта.</param>
/// <param name="Typ">Тип лицензии.</param>
/// <param name="Plat">Платформа этой активации.</param>
/// <param name="Iat">Unix-время выпуска, секунды UTC.</param>
/// <param name="Exp">Unix-время истечения; null — навсегда.</param>
/// <param name="Fp">Отпечаток машины/установки, sha256:&lt;64 hex&gt;.</param>
/// <param name="Seats">Мест в лицензии; null — без лимита. Справочно: лимит применяет сервер.</param>
/// <param name="Feat">Включённые возможности.</param>
/// <param name="Kid">Id ключа подписи.</param>
public sealed record LicensePayload(
    string Lid,
    string Aid,
    string Pid,
    LicenseType Typ,
    Platform Plat,
    long Iat,
    long? Exp,
    string Fp,
    int? Seats,
    IReadOnlyList<string> Feat,
    string Kid)
{
    /// <summary>Версия формата (поле v). Неизвестная версия отвергается.</summary>
    public const int Version = 1;

    /// <summary>Возможность включена в этой лицензии.</summary>
    public bool HasFeature(string feature)
    {
        for (var i = 0; i < Feat.Count; i++)
        {
            if (string.Equals(Feat[i], feature, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>Лицензия недействительна: не разобралась, не сошлась подпись либо не прошла проверку §2.5.</summary>
public sealed class LicenseException : Exception
{
    /// <param name="message">Что именно не сошлось; предназначено логу продукта, не пользователю.</param>
    public LicenseException(string message) : base(message)
    {
    }
}
