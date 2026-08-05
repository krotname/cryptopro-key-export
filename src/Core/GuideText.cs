using System.IO;

namespace CryptoProExport
{
    /// <summary>
    /// Встроенное руководство пользователя: вшито в сборку ресурсом, поэтому доступно
    /// и у портативного exe, рядом с которым нет ни одного файла.
    /// Показывается кнопкой «Справка» в окне и командой <c>help</c> в консоли.
    /// </summary>
    public static class GuideText
    {
        public const string ResourceName = "CryptoProExport.guide.txt";

        /// <summary>Текст руководства. Пустая строка — ресурс не вшит в сборку.</summary>
        public static string Value
        {
            get
            {
                using var stream = typeof(GuideText).Assembly.GetManifestResourceStream(ResourceName);
                if (stream == null) return string.Empty;
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
        }
    }
}
