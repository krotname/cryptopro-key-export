using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Мини-декодер OEM-кодировки 866 без зависимости от System.Text.Encoding.CodePages.
    /// В ней пишут в stdout консольные утилиты КриптоПро (p12utility, certmgr, csptest):
    /// без такого декодера их сообщения попадают в лог кашей.
    /// </summary>
    public static class Cp866
    {
        // 0xB0..0xDF — псевдографика; остальное считается по формуле
        private const string Box =
            "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀";

        // 0xF0..0xFE (0xFF — неразрывный пробел, обрабатывается отдельно)
        private const string Tail = "ЁёЄєЇїЎў°∙·√№¤■";

        public static string GetString(byte[] data) =>
            data == null ? string.Empty : GetString(data, 0, data.Length);

        public static string GetString(byte[] data, int offset, int count)
        {
            var sb = new StringBuilder(count);
            for (int i = 0; i < count; i++)
            {
                byte b = data[offset + i];
                if (b < 0x80) { sb.Append((char)b); continue; }
                if (b <= 0xAF) { sb.Append((char)(0x0410 + (b - 0x80))); continue; }   // А..Я, а..п
                if (b <= 0xDF) { sb.Append(Box[b - 0xB0]); continue; }                 // псевдографика
                if (b <= 0xEF) { sb.Append((char)(0x0440 + (b - 0xE0))); continue; }   // р..я
                if (b == 0xFF) { sb.Append(' '); continue; }                           // NBSP
                sb.Append(Tail[b - 0xF0]);
            }
            return sb.ToString();
        }
    }
}
