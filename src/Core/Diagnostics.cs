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

            // 1–2. Вшитые зависимости. В норме о них не пишется ничего: строка «всё вшито,
            //       ставить ничего не нужно» ничего не проверяла и была шумом ровно в том
            //       случае, когда всё в порядке. Наличие компонента теперь проверяется там, где
            //       он нужен (ComponentCheck), а сюда попадает только отклонение от нормы:
            //       внешняя копия, отсутствие или системная регистрация вместо вшитой.
            //       Полные пути и происхождение каждой — в detailed (команда deps).
            string p12 = P12Utility.Resolve();
            if (p12 == null) lines.Add(Strings.Get("diag.p12.missing"));
            else if (!IsBundled(p12))
                lines.Add(Strings.Format("diag.p12.found", Strings.Get("diag.copy.external"), p12));

            // rtCOMLite грузится без регистрации и только в 32-битном процессе.
            if (!RutokenExporter.UsesBundledCopy())
                lines.Add(Strings.Format("diag.rtcom", RutokenExporter.SourceSummary()));
            if (RuntimeInformation.ProcessArchitecture != Architecture.X86)
                lines.Add("  " + Strings.Get("diag.rtcom.warn"));
            if (detailed)
            {
                lines.AddRange(P12Utility.DescribeSource());
                lines.AddRange(RutokenExporter.DescribeSource());
            }

            // 2a. PnP — failed-start reader исчезает из PC/SC и PKCS#11, хотя остаётся PnP-present.
            //     Показываем безопасные VID/PID без полного Instance ID (его хвост бывает серийником).
            lines.AddRange(SmartCardReaderHealth.Report(detailed));

            // 2b. PKCS#11 — путь для смарт-карточных носителей (где rtCOMLite файлы не отдаёт).
            //     Библиотека берётся из системы (драйвер носителя), а если её там нет — из вшитой
            //     копии. Их может быть несколько: каждая показывает только своего вендора.
            //     В detailed — перечень токенов.
            var p11 = Pkcs11Token.AvailableLibraries();
            lines.Add(Strings.Format("diag.pkcs11", p11.Count == 0
                ? Strings.Get("diag.pkcs11.missing")
                : Strings.Format("diag.pkcs11.found", string.Join("; ", p11.Select(l =>
                    l.Vendor + " — " + (IsBundled(l.Path) ? Strings.Get("diag.copy.bundled") : l.Path))))));
            List<Pkcs11TokenInfo> pkcs11Tokens = null;
            if (detailed && p11.Count > 0)
            {
                // Сообщения об ошибках PKCS#11 идут в сам отчёт: deps — диагностическая команда,
                // и «токенов не видно» без причины здесь бесполезно.
                var tokens = Pkcs11Token.Enumerate(readContainers: true, log: m => lines.Add("  " + m));
                pkcs11Tokens = tokens;
                foreach (var t in tokens)
                {
                    lines.Add("  " + Strings.Format("diag.pkcs11.token",
                        t.Reader ?? "?", Pkcs11Token.KindName(t.Kind),
                        t.Serial ?? "?", Pkcs11Token.PinState(t)));
                    lines.Add("    " + Pkcs11Token.CapabilitySummary(t));
                    if (t.Kind == RutokenKind.RutokenEcp)
                        lines.Add("    " + Strings.Get("token.boundary.ecp"));
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

            // 2c. PC/SC — карты, физически стоящие в считывателях, но не показанные ни одной
            //     библиотекой PKCS#11. Пассивный опрос (без подключения к карте) честно отличает
            //     «носитель не вставлен» от «носитель есть, но токеном не является» — например,
            //     JaCarta на платформе Athena IDProtect работает через минидрайвер Microsoft, и
            //     vendor-библиотеки PKCS#11 её как токен не видят.
            if (detailed)
            {
                var pcsc = PcscReaders.List(m => lines.Add("  " + m));
                var readers = new List<string>();
                foreach (var t in pkcs11Tokens ?? new List<Pkcs11TokenInfo>())
                    if (t?.Reader != null) readers.Add(t.Reader);
                lines.AddRange(PcscReaders.CoverageLines(pcsc, readers));
            }

            // 3. КриптоПро CSP — единственная внешняя зависимость, вшить нельзя
            //     Тип провайдера печатается с расшифровкой: голые «80, 81, 75» читателю лога
            //     ничего не говорят, а это и есть ответ на вопрос «какой ГОСТ поддержан».
            var provs = CertFromContainer.AvailableProviders();
            lines.Add(provs.Count > 0
                ? Strings.Format("diag.csp.ok",
                    string.Join("; ", provs.Select(CertFromContainer.DescribeProvider)))
                : Strings.Get("diag.csp.missing"));
            if (detailed)
                foreach (var (type, name) in CertFromContainer.Providers)
                    lines.Add("  " + Strings.Format("diag.prov", CertFromContainer.DescribeProvider(type),
                        Strings.Get(provs.Contains(type) ? "diag.prov.yes" : "diag.prov.no"), name));

            return lines;
        }

        private static bool IsBundled(string path) =>
            path != null && path.StartsWith(BundledTools.CacheDir, StringComparison.OrdinalIgnoreCase);
    }
}
