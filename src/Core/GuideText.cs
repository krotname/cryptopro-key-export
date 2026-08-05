using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;

namespace CryptoProExport
{
    /// <summary>
    /// Встроенное руководство пользователя: вшито в сборку ресурсом, поэтому доступно
    /// и у портативного exe, рядом с которым нет ни одного файла.
    /// Показывается кнопкой «Справка» в окне и командой <c>help</c> в консоли.
    ///
    /// Переведено на русский и английский. Интерфейс локализован на 20 языков, но
    /// руководство — это 150 строк связного текста, и держать его в 20 версиях дороже,
    /// чем полезнее: остальные языки получают английский вариант (решение в AGENTS.md).
    /// </summary>
    public static class GuideText
    {
        private const string ResourcePrefix = "CryptoProExport.guide.";
        private const string ResourceSuffix = ".txt";

        /// <summary>Языки, на которых руководство есть в сборке.</summary>
        public static IReadOnlyList<string> Available { get; } = Discover();

        /// <summary>Руководство на языке интерфейса. Пустая строка — ресурс не вшит.</summary>
        public static string Value => For(Strings.Current);

        /// <summary>
        /// Руководство на конкретном языке. Нет перевода — английский, нет и его —
        /// первый вшитый вариант; совсем ничего — пустая строка.
        /// </summary>
        public static string For(string language)
        {
            return Read(Pick(language)) ?? string.Empty;
        }

        /// <summary>Какой перевод руководства реально покажется для языка интерфейса.</summary>
        public static string Pick(string language)
        {
            if (Available.Count == 0) return null;
            string exact = Available.FirstOrDefault(l => string.Equals(l, language, StringComparison.OrdinalIgnoreCase));
            if (exact != null) return exact;
            return Available.FirstOrDefault(l => string.Equals(l, Strings.Fallback, StringComparison.OrdinalIgnoreCase))
                   ?? Available[0];
        }

        private static IReadOnlyList<string> Discover()
        {
            var codes = typeof(GuideText).Assembly.GetManifestResourceNames()
                .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal) &&
                            n.EndsWith(ResourceSuffix, StringComparison.Ordinal))
                .Select(n => n.Substring(ResourcePrefix.Length, n.Length - ResourcePrefix.Length - ResourceSuffix.Length))
                .Where(c => c.Length > 0)
                .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
                .ToList();
            return new ReadOnlyCollection<string>(codes);
        }

        private static string Read(string language)
        {
            if (language == null) return null;
            using var stream = typeof(GuideText).Assembly
                .GetManifestResourceStream(ResourcePrefix + language + ResourceSuffix);
            if (stream == null) return null;
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }
    }
}
