using System;
using System.Collections.Generic;
using System.Linq;
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
            lines.Add(Strings.Format("diag.process", RegFreeCom.Name(RuntimeInformation.ProcessArchitecture), asm.Version));

            // 1. p12utility — вшит
            string p12 = P12Utility.Resolve();
            lines.Add(p12 == null
                ? Strings.Get("diag.p12.missing")
                : Strings.Format("diag.p12.found",
                    Strings.Get(IsBundled(p12) ? "diag.copy.bundled" : "diag.copy.external"), p12));
            if (detailed) lines.AddRange(P12Utility.DescribeSource());

            // 2. rtCOMLite — вшит, грузится без регистрации (только в 32-битном процессе)
            lines.Add(Strings.Format("diag.rtcom", RutokenExporter.SourceSummary()));
            if (RuntimeInformation.ProcessArchitecture != Architecture.X86)
                lines.Add("  " + Strings.Get("diag.rtcom.warn"));
            if (detailed) lines.AddRange(RutokenExporter.DescribeSource());

            // 2b. PKCS#11 — путь для смарт-карточных носителей (где rtCOMLite файлы не отдаёт).
            //     Библиотеки берутся из системы (драйверы носителей), не вшиваются. Их может быть
            //     несколько: каждая показывает только своего вендора. В detailed — перечень токенов.
            var p11 = Pkcs11Token.AvailableLibraries();
            lines.Add(Strings.Format("diag.pkcs11", p11.Count == 0
                ? Strings.Get("diag.pkcs11.missing")
                : Strings.Format("diag.pkcs11.found",
                    string.Join("; ", p11.Select(l => l.Vendor + " — " + l.Path)))));
            if (detailed && p11.Count > 0)
            {
                // Сообщения об ошибках PKCS#11 идут в сам отчёт: deps — диагностическая команда,
                // и «токенов не видно» без причины здесь бесполезно.
                var tokens = Pkcs11Token.Enumerate(readContainers: true, log: m => lines.Add("  " + m));
                foreach (var t in tokens)
                {
                    lines.Add("  " + Strings.Format("diag.pkcs11.token",
                        t.Reader ?? "?", Pkcs11Token.KindName(t.Kind),
                        t.Serial ?? "?", Pkcs11Token.PinState(t)));
                    foreach (var c in t.Containers)
                        // Сертификат без парного CKO_DATA контейнером не является — у него своя
                        // формулировка, как в list и token (замечание Codex на PR #24).
                        lines.Add("    " + (c.CertificateOnly
                            ? Strings.Format("diag.pkcs11.certonly",
                                c.Name ?? Strings.Get("log.container.unnamed"))
                            : Strings.Format("diag.pkcs11.container",
                                c.Name ?? Strings.Get("log.container.unnamed"),
                                Strings.Get(c.Certificate != null ? "common.present" : "common.none"))));
                }
            }

            // 3. КриптоПро CSP — единственная внешняя зависимость, вшить нельзя
            var provs = CertFromContainer.AvailableProviders();
            lines.Add(provs.Count > 0
                ? Strings.Format("diag.csp.ok", string.Join(", ", provs))
                : Strings.Get("diag.csp.missing"));
            if (detailed)
                foreach (var (type, name) in CertFromContainer.Providers)
                    lines.Add("  " + Strings.Format("diag.prov", type,
                        Strings.Get(provs.Contains(type) ? "diag.prov.yes" : "diag.prov.no"), name));

            return lines;
        }

        private static bool IsBundled(string path) =>
            path != null && path.StartsWith(BundledTools.CacheDir, StringComparison.OrdinalIgnoreCase);
    }
}
