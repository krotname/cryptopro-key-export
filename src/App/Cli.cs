using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;

namespace CryptoProExport.App
{
    /// <summary>Консольный режим (для скриптов/автоматизации и CI-проверок).</summary>
    [SupportedOSPlatform("windows")]
    internal static class Cli
    {
        /// <summary>Вывод дублируется в журнал сеанса — чтобы было что показать после сбоя.</summary>
        private static readonly Action<string> Out = SessionLog.Tee(Console.WriteLine);
        private static readonly Action<string> Err = SessionLog.Tee(Console.Error.WriteLine);

        /// <summary>
        /// Синтаксис команд не переводится: это литералы, которые набирают в консоли.
        /// Переводится только пояснение — ключ <c>cli.usage.&lt;команда&gt;</c>.
        /// </summary>
        private static readonly (string Syntax, string Key)[] Commands =
        {
            ("deps",                                 "cli.usage.deps"),
            ("list",                                 "cli.usage.list"),
            ("token [outDir]",                       "cli.usage.token"),
            ("extractcert <container> <outDir>",     "cli.usage.extractcert"),
            ("checkexport <container>",              "cli.usage.checkexport"),
            ("export <destDir> [pin]",               "cli.usage.export"),
            ("keyexport <folder> <cert.cer> [pass]", "cli.usage.keyexport"),
            ("install <folder> [name]",              "cli.usage.install"),
            ("installed",                            "cli.usage.installed"),
            ("uninstall <folder>",                   "cli.usage.uninstall"),
            ("topfx <container> <out.pfx> [pass]",   "cli.usage.topfx"),
            ("full <destDir> [cert.cer] [pin]",      "cli.usage.full"),
            ("help",                                 "cli.usage.help"),
            ("--lang <xx>",                          "cli.usage.lang"),
        };

        public static int Run(string[] args)
        {
            try
            {
                switch (args[0].ToLowerInvariant())
                {
                    case "help":
                    case "--help":
                    case "-h":
                    case "/?":
                    {
                        string guide = GuideText.Value;
                        if (string.IsNullOrWhiteSpace(guide)) { Usage(); return 0; }
                        Out(guide);
                        return 0;
                    }
                    case "deps":
                    {
                        foreach (var line in CryptoProExport.Diagnostics.Report(detailed: true))
                            Out(line);
                        // Ненулевой код, только если не хватает того, что нельзя вшить, — КриптоПро CSP
                        return CertFromContainer.AvailableProviders().Count > 0 ? 0 : 2;
                    }
                    case "list":
                    {
                        Out(Strings.Get("cli.list.csp"));
                        foreach (var c in CertFromContainer.EnumContainers())
                            Out($"  {c.Name}  " + Strings.Format("cli.list.provider", c.ProvType));

                        // Токены по PKCS#11 (Рутокен ЭЦП/Lite): контейнеры видны без ввода PIN.
                        var tokens = Pkcs11Token.Enumerate(readContainers: true);
                        if (tokens.Count > 0)
                        {
                            Out(Strings.Get("cli.list.pkcs11"));
                            foreach (var t in tokens)
                            {
                                Out($"  {t.Reader} [{Pkcs11Token.KindName(t.Kind)}]");
                                foreach (var c in t.Containers)
                                    Out("    " + Strings.Format("cli.token.container", c.Name ?? "?",
                                        Strings.Get(c.Certificate != null ? "common.present" : "common.none")));
                            }
                        }

                        Out(Strings.Get("cli.list.tokens"));
                        var exp = new RutokenExporter { Log = Out };
                        foreach (var c in exp.ReadAllContainers())
                            Out($"  {c.TokenName} {c.TokenDir} \"{c.ContainerName}\" " +
                                Strings.Format("cli.list.files", c.Files.Count));
                        return 0;
                    }
                    case "token":
                    {
                        var tokens = Pkcs11Token.Enumerate(readContainers: true, log: Out);
                        if (tokens.Count == 0) { Out(Strings.Get("cli.token.none")); return 2; }
                        string outDir = args.Length > 1 ? args[1] : null;
                        foreach (var t in tokens)
                        {
                            Out(Strings.Format("cli.token.line", t.Reader ?? "?", t.Label ?? "?",
                                Pkcs11Token.KindName(t.Kind), t.Serial ?? "?", t.Firmware ?? "?"));
                            Out("  " + Strings.Format("cli.token.pin", Pkcs11Token.PinState(t)));
                            foreach (var c in t.Containers)
                            {
                                Out("  " + Strings.Format("cli.token.container", c.Name ?? "?",
                                    Strings.Get(c.Certificate != null ? "common.present" : "common.none")));
                                if (outDir != null && c.Certificate != null)
                                    SaveTokenCert(outDir, c);
                            }
                        }
                        return 0;
                    }
                    case "extractcert":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var (ex, sg) = CertFromContainer.SaveCerts(args[1], args[2]);
                        Out(Strings.Format("cli.cert.exchange", ex ?? Strings.Get("common.none")));
                        Out(Strings.Format("cli.cert.sign", sg ?? Strings.Get("common.none")));
                        return (ex != null || sg != null) ? 0 : 2;
                    }
                    case "checkexport":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var ex = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_KEYEXCHANGE);
                        var sg = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_SIGNATURE);
                        Out(Strings.Format("cli.check.exchange", ex));
                        Out(Strings.Format("cli.check.sign", sg));
                        // 2 — проверять нечего (нет контейнера/ключа), 3 — ключ есть, но запрет не снят
                        if (!ex.KeyFound && !sg.KeyFound) return 2;
                        return (ex.Exportable || sg.Exportable) ? 0 : 3;
                    }
                    case "export":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Out };
                        pipe.ExportFromTokens(args[1], args.Length > 2 ? args[2] : null);
                        return 0;
                    }
                    case "keyexport":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var p12 = new P12Utility(P12Utility.Resolve()) { Log = Out };
                        var r = p12.MakeExportable(args[1], args[2], null, args.Length > 3 ? args[3] : null);
                        Out(r.Success ? Strings.Get("cli.keyexport.ok") : Strings.Format("cli.error", r.Explain()));
                        return r.Success ? 0 : 2;
                    }
                    case "install":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var installed = ContainerStore.Install(args[1], args.Length > 2 ? args[2] : null);
                        Out(Strings.Format("log.install.done", installed));
                        if (args.Length > 2 && !installed.Renamed)
                            Out(Strings.Format("cli.install.norename", args[2]));
                        if (installed.Verified && !installed.VisibleToCsp)
                        {
                            Out(Strings.Get("cli.install.invisible"));
                            return 2;
                        }
                        return 0;
                    }
                    case "installed":
                    {
                        Out(Strings.Format("cli.installed.header", ContainerStore.HdImageDir));
                        foreach (var c in ContainerStore.Installed())
                            Out($"  {c.Name}  ->  {c.Folder}");
                        return 0;
                    }
                    case "uninstall":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        ContainerStore.Uninstall(args[1]);
                        Out(Strings.Format("cli.uninstall.done", args[1]));
                        return 0;
                    }
                    case "topfx":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        string exe = CertMgr.Locate();
                        if (exe == null)
                        {
                            Err(Strings.Get("cli.topfx.nocertmgr"));
                            return 2;
                        }
                        var cm = new CertMgr(exe) { Log = Out };
                        var r = cm.ExportContainerToPfx(args[1], args[2], args.Length > 3 ? args[3] : null);
                        Out(r.Success ? Strings.Format("cli.done", args[2]) : Strings.Format("cli.error", r.Output));
                        return r.Success ? 0 : 2;
                    }
                    case "full":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Out };
                        pipe.ExportAndMakeExportable(
                            destParent: args[1],
                            certExchange: args.Length > 2 ? args[2] : null,
                            userPin: args.Length > 3 ? args[3] : null);
                        return 0;
                    }
                    default:
                        Usage();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Err(Strings.Format("cli.failure", ex.Message));
                return 3;
            }
        }

        /// <summary>Сохранить извлечённый с токена сертификат (.cer) — без обращения к CSP.</summary>
        private static void SaveTokenCert(string outDir, Pkcs11Container c)
        {
            try
            {
                Directory.CreateDirectory(outDir);
                string safe = c.Name ?? "cert";
                foreach (char ch in Path.GetInvalidFileNameChars())
                    safe = safe.Replace(ch, '_');
                string path = Path.Combine(outDir, safe + ".cer");
                File.WriteAllBytes(path, c.Certificate);
                Out("    " + Strings.Format("cli.token.cert.saved", path));
            }
            catch (Exception e)
            {
                Out("    " + Strings.Format("cli.token.certfail", c.Name ?? "?", e.Message));
            }
        }

        /// <summary>
        /// Подсказка по командам. Ширина колонки считается по факту: переводы длиннее
        /// русского оригинала, а жёсткий отступ разъехался бы.
        /// </summary>
        private static void Usage()
        {
            Out(Strings.Get("cli.usage.title"));
            int width = Commands.Max(c => c.Syntax.Length) + 2;
            foreach (var (syntax, key) in Commands)
                Out("  " + syntax.PadRight(width, ' ') + Strings.Get(key));
            Out("  " + Strings.Get("cli.usage.gui"));
        }
    }
}
