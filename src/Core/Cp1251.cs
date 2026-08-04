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
        public static string GetString(byte[] data, int offset, int count)
        {
            var sb = new StringBuilder(count);
            for (int i = 0; i < count; i++)
            {
                byte b = data[offset + i];
                if (b < 0x80) { sb.Append((char)b); continue; }
                switch (b)
                {
                    case 0xA8: sb.Append('Ё'); break; // Ё
                    case 0xB8: sb.Append('ё'); break; // ё
                    case 0xB9: sb.Append('№'); break; // №
                    default:
                        if (b >= 0xC0) sb.Append((char)(0x0410 + (b - 0xC0))); // А..я
                        else sb.Append('?');
                        break;
                }
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
                switch (c)
                {
                    case 'Ё': bytes[i] = 0xA8; break;
                    case 'ё': bytes[i] = 0xB8; break;
                    case '№': bytes[i] = 0xB9; break;
                    default:
                        bytes[i] = (c >= 0x0410 && c <= 0x044F)
                            ? (byte)(0xC0 + (c - 0x0410))
                            : (byte)'?';
                        break;
                }
            }
            return bytes;
        }
    }
}
