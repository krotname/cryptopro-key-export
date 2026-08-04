using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CryptoProExport
{
    /// <summary>
    /// Отчёт о внешних зависимостях: что вшито в приложение, что берётся из системы,
    /// чего не хватает. Используется в логе GUI при запуске и командой <c>deps</c>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class Diagnostics
    {
        public static List<string> Report(bool detailed = false)
        {
            var lines = new List<string>();
            var asm = typeof(Diagnostics).Assembly.GetName();
            lines.Add($"Процесс: {RegFreeCom.Name(RuntimeInformation.ProcessArchitecture)}, версия {asm.Version}");

            // 1. p12utility — вшит
            string p12 = P12Utility.Resolve();
            lines.Add("p12utility: " + (p12 == null
                ? "НЕ НАЙДЕН (не вшит в сборку и не найден в системе)"
                : $"{(IsBundled(p12) ? "встроенная копия" : "внешняя копия")}: {p12}"));
            if (detailed) lines.AddRange(P12Utility.DescribeSource());

            // 2. rtCOMLite — вшит, грузится без регистрации
            lines.Add("rtCOMLite: " + RutokenExporter.SourceSummary());
            if (detailed) lines.AddRange(RutokenExporter.DescribeSource());

            // 3. КриптоПро CSP — единственная внешняя зависимость, вшить нельзя
            var provs = CertFromContainer.AvailableProviders();
            lines.Add(provs.Count > 0
                ? "КриптоПро CSP: установлен, провайдеры " + string.Join(", ", provs)
                : "КриптоПро CSP: НЕ НАЙДЕН — установите КриптоПро CSP (единственная внешняя зависимость)");
            if (detailed)
                foreach (var (type, name) in CertFromContainer.Providers)
                    lines.Add($"  {type}: {(provs.Contains(type) ? "доступен" : "нет")} — {name}");

            return lines;
        }

        private static bool IsBundled(string path) =>
            path != null && path.StartsWith(BundledTools.CacheDir, StringComparison.OrdinalIgnoreCase);
    }
}
