// Вендорнуто из krotname/license-server, clients/dotnet/KrotName.Licensing (референс-клиент .NET).
// Источник правды — тот репозиторий; здесь копия, чтобы портативный exe оставался self-contained.
// Файл не редактировать вручную — при изменении протокола правится сначала license-server.
#nullable enable
using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace KrotName.Licensing;

/// <summary>
/// 9-символьный код активации — PROTOCOL §1. Клиентская половина: нормализация ввода и проверка
/// контрольного символа <b>офлайн</b>, до обращения к серверу. Генерация кодов — забота сервера.
/// </summary>
public static class ActivationCode
{
    /// <summary>Основной алфавит Crockford Base32 (без I, L, O, U), индексы 0…31.</summary>
    public const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>Длина нормализованного кода: 8 случайных + 1 контрольный.</summary>
    public const int Length = 9;

    private const int RandomLength = Length - 1;
    private const int Radix = 32;
    private const int CheckModulus = 37;

    /// <summary>
    /// Нормализация ввода (§1.3): убрать всё, кроме латиницы и цифр, поднять регистр, заменить
    /// похожие начертания (I/L→1, O→0). Длину и алфавит не проверяет — это делает <see cref="TryValidate"/>.
    /// </summary>
    public static string Normalize(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(input.Length);
        foreach (var raw in input)
        {
            var c = raw is >= 'a' and <= 'z' ? (char)(raw - 'a' + 'A') : raw;
            if (c is >= '0' and <= '9' or >= 'A' and <= 'Z')
            {
                builder.Append(c switch
                {
                    'I' or 'L' => '1',
                    'O' => '0',
                    _ => c
                });
            }
            // Всё остальное — дефисы, пробелы, невидимые, не-ASCII — отбрасывается.
        }

        return builder.ToString();
    }

    /// <summary>
    /// Полная офлайн-проверка (§1.3–1.4): нормализовать, проверить длину и алфавит, сверить
    /// контрольный символ. Код с контрольным значением ≥ 32 отвергается: такой не выпускается.
    /// </summary>
    public static bool TryValidate(string? input, [NotNullWhen(true)] out string? normalized)
    {
        normalized = null;
        var code = Normalize(input);
        if (code.Length != Length)
        {
            return false;
        }

        for (var i = 0; i < RandomLength; i++)
        {
            if (Alphabet.IndexOf(code[i]) < 0)
            {
                return false;
            }
        }

        var check = CheckValue(code);
        if (check >= Radix || code[RandomLength] != Alphabet[check])
        {
            return false;
        }

        normalized = code;
        return true;
    }

    /// <summary>Короткая форма <see cref="TryValidate"/>.</summary>
    public static bool IsValid(string? input) => TryValidate(input, out _);

    /// <summary>Показ пользователю: XXX-XXX-XXX. На вход — уже нормализованный код.</summary>
    public static string Format(string normalizedCode)
    {
        ArgumentNullException.ThrowIfNull(normalizedCode);
        if (normalizedCode.Length != Length)
        {
            throw new ArgumentException($"ожидался нормализованный код из {Length} символов", nameof(normalizedCode));
        }

        return normalizedCode.Substring(0, 3) + "-" + normalizedCode.Substring(3, 3) + "-"
               + normalizedCode.Substring(6, 3);
    }

    /// <summary>
    /// Контрольное значение по первым восьми символам (§1.4): Σ index(c_i)·32^(7−i) mod 37.
    /// Считается по Горнеру с редукцией на каждом шаге — результат тождествен формуле.
    /// </summary>
    internal static int CheckValue(string first8)
    {
        var acc = 0;
        for (var i = 0; i < RandomLength; i++)
        {
            var index = Alphabet.IndexOf(first8[i]);
            if (index < 0)
            {
                throw new ArgumentException($"символ вне алфавита: {first8[i]}", nameof(first8));
            }

            acc = (acc * Radix + index) % CheckModulus;
        }

        return acc;
    }
}
