using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Мини-кодек Windows-1251 без зависимости от System.Text.Encoding.CodePages
    /// (в .NET кодовая страница 1251 по умолчанию недоступна). Хватает для имён контейнеров:
    /// именно в этой кодировке их отдаёт PP_ENUMCONTAINERS и хранит name.key.
    /// </summary>
    public static class Cp1251
    {
        /// <summary>
        /// Байты 0x80..0xBF — всё, что не считается по формуле «А..я»: кавычки-ёлочки, тире,
        /// градус, №, украинско-белорусские буквы. Раньше из этой половины таблицы кодек знал
        /// только Ё, ё и №, а остальное превращал в «?» — имя вроде «ООО «Ромашка» — обмен»
        /// портилось при первом же перечитывании name.key, и порча уезжала обратно в файл.
        /// Символы заданы кодами: в таблице есть неразрывный пробел (A0) и мягкий перенос (AD),
        /// в исходнике они были бы неотличимы от обычных. 0xFFFD — незанятый байт 0x98.
        /// </summary>
        private static readonly char[] High =
        {
            'Ђ', 'Ѓ', '‚', 'ѓ', '„', '…', '†', '‡', // 80..87
            '€', '‰', 'Љ', '‹', 'Њ', 'Ќ', 'Ћ', 'Џ', // 88..8F
            'ђ', '‘', '’', '“', '”', '•', '–', '—', // 90..97
            '�', '™', 'љ', '›', 'њ', 'ќ', 'ћ', 'џ', // 98..9F
            ' ', 'Ў', 'ў', 'Ј', '¤', 'Ґ', '¦', '§', // A0..A7
            'Ё', '©', 'Є', '«', '¬', '­', '®', 'Ї', // A8..AF
            '°', '±', 'І', 'і', 'ґ', 'µ', '¶', '·', // B0..B7
            'ё', '№', 'є', '»', 'ј', 'Ѕ', 'ѕ', 'ї', // B8..BF
        };

        public static string GetString(byte[] data, int offset, int count)
        {
            var sb = new StringBuilder(count);
            for (int i = 0; i < count; i++)
            {
                byte b = data[offset + i];
                if (b < 0x80) { sb.Append((char)b); continue; }
                if (b >= 0xC0) { sb.Append((char)(0x0410 + (b - 0xC0))); continue; } // А..я
                char c = High[b - 0x80];
                sb.Append(c == '�' ? '?' : c);   // 0x98 в cp1251 не определён
            }
            return sb.ToString();
        }

        /// <summary>Обратное преобразование: строка → cp1251. Непредставимые символы заменяются на «?».</summary>
        public static byte[] GetBytes(string text)
        {
            if (text == null) return new byte[0];
            var bytes = new byte[text.Length];
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (c < 0x80) { bytes[i] = (byte)c; continue; }
                if (c >= 0x0410 && c <= 0x044F) { bytes[i] = (byte)(0xC0 + (c - 0x0410)); continue; }
                bytes[i] = (byte)'?';
                if (c == '�') continue;          // сам заменяющий символ — не байт 0x98
                for (int h = 0; h < High.Length; h++)
                {
                    if (High[h] != c) continue;
                    bytes[i] = (byte)(0x80 + h);
                    break;
                }
            }
            return bytes;
        }
    }
}
