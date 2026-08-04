using System;
using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Мини-декодер Windows-1251 без зависимости от System.Text.Encoding.CodePages
    /// (в .NET кодовая страница 1251 по умолчанию недоступна). Хватает для имён контейнеров.
    /// </summary>
    internal static class Cp1251
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
    }
}
