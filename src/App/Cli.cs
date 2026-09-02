using System;
using System.Collections.Generic;
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
            ("tokenexport <reader> <outDir> [pin] [--container <id>]", "cli.usage.tokenexport"),
            ("tokenfull <reader> <outDir> [pin] [--container <id>]",   "cli.usage.tokenfull"),
            ("keyexport <folder> <cert.cer> [pass]", "cli.usage.keyexport"),
            ("exportable <folder> <outFolder> [pass]", "cli.usage.exportable"),
            ("install <folder> [name]",              "cli.usage.install"),
            ("installed",                            "cli.usage.installed"),
            ("uninstall <folder>",                   "cli.usage.uninstall"),
            ("topfx <container> <out.pfx> [pass]",   "cli.usage.topfx"),
            ("extractkey <folder> <out.pem> [pass]", "cli.usage.extractkey"),
            ("extractpfx <folder> <out.pfx> <pfx-pass> [pass] [cert.cer]", "cli.usage.extractpfx"),
            ("liteexport <reader> <outDir> [pin]",   "cli.usage.liteexport"),
            ("angaraexport <reader> <outDir> [pin]", "cli.usage.angaraexport"),
            ("full <destDir> [cert.cer] [pin]",      "cli.usage.full"),
            ("pins",                                 "cli.usage.pins"),
            ("fingerprint",                          "cli.usage.fingerprint"),
            ("license [file|status]",                "cli.usage.license"),
            ("help",                                 "cli.usage.help"),
            ("--lang <xx>",                          "cli.usage.lang"),
        };

        /// <summary>
        /// Операции, дающие сам экспорт закрытого ключа. Без действительной лицензии они закрыты
        /// (жёсткий гейт). Диагностика (deps/list/checkexport/installed/token/extractcert),
        /// установка лицензии и справка остаются доступными — иначе нельзя было бы узнать отпечаток
        /// и ввести лицензию.
        /// </summary>
        private static readonly string[] LicensedCommands =
            { "export", "tokenexport", "tokenfull", "full", "keyexport", "exportable", "extractkey", "extractpfx", "liteexport", "angaraexport", "topfx" };

        public static int Run(string[] args)
        {
            try
            {
                string cmd = args[0].ToLowerInvariant();

                // Жёсткий гейт: операции экспорта закрытого ключа требуют действительной лицензии
                // (офлайн-проверка вшитым ключом). Диагностика, установка лицензии и справка — свободны.
                if (Array.IndexOf(LicensedCommands, cmd) >= 0 && !LicenseGate.IsLicensed())
                {
                    Err(Strings.Get("license.required"));
                    Out(LicenseGate.StatusText());
                    Out(LicenseGate.FingerprintText());
                    return 4;
                }

                switch (cmd)
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

                        // Токены по PKCS#11: метаданные и профиль механизмов видны без PIN;
                        // публичные сертификаты показываются только когда реально присутствуют.
                        // Лог обязателен: без него сбой драйвера выглядел бы как «токенов нет».
                        var tokens = Pkcs11Token.Enumerate(readContainers: true, log: Out);
                        Out("[PKCS#11] " + Strings.Format("token.found", tokens.Count));
                        Out(Strings.Get("cli.list.pkcs11"));
                        // Секция печатается всегда, даже пустая: молчание читалось бы как
                        // «по PKCS#11 не смотрели», а не как «токенов не вставлено».
                        if (tokens.Count == 0) Out("  " + Strings.Get("cli.token.none"));
                        foreach (var t in tokens)
                        {
                            Out($"  {t.Reader} [{Pkcs11Token.KindName(t.Kind)}]");
                            Out("    " + Pkcs11Token.CapabilitySummary(t));
                            if (t.Kind == RutokenKind.RutokenEcp)
                                Out("    " + Strings.Get("token.boundary.ecp"));
                            foreach (var c in t.Containers)
                                Out("    " + DescribeTokenEntry(c));
                            if (DirectTokenApdu.Supports(t.Kind))
                            {
                                try
                                {
                                    var direct = new DirectTokenApdu { Log = m => Out("[APDU] " + m) };
                                    foreach (var c in direct.ListContainers(t))
                                        Out($"    [APDU {c.OutputName}] {c.Name ?? Strings.Get("log.container.unnamed")}");
                                }
                                catch (Exception e)
                                {
                                    Out("    [APDU] " + Strings.Format("log.tokens.unavailable", e.Message));
                                }
                            }
                        }

                        // Карты, стоящие в PC/SC, но не показанные PKCS#11 — иначе «токенов нет»
                        // читается как «носитель не вставлен», хотя карта физически стоит.
                        ReportUncoveredCards(tokens);

                        Out(Strings.Get("cli.list.tokens"));
                        var exp = new RutokenExporter
                        {
                            // Это отдельный backend, который видит только совместимые с
                            // rtCOMLite Рутокены. Его счётчик нельзя выдавать за общее число
                            // подключённых аппаратных устройств.
                            Log = m => Out("[rtCOMLite] " + m),
                            SkipReaders = Pkcs11Token.SmartCardReaders(tokens),
                        };
                        foreach (var c in exp.ReadAllContainers())
                            Out($"  {c.TokenName} {c.TokenDir} \"{c.ContainerName}\" " +
                                Strings.Format("cli.list.files", c.Files.Count));
                        return 0;
                    }
                    case "token":
                    {
                        var tokens = Pkcs11Token.Enumerate(readContainers: true, log: Out);
                        if (tokens.Count == 0)
                        {
                            Out(Strings.Get("cli.token.none"));
                            // Не молчим о карте, которую PKCS#11 не показал: возможно, носитель
                            // стоит, но обслуживается минидрайвером и токеном не является.
                            ReportUncoveredCards(tokens);
                            return 2;
                        }
                        string outDir = args.Length > 1 ? args[1] : null;
                        bool anySaveFailed = false;
                        bool anyCertificate = false;
                        var usedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);   // защита от коллизии имён
                        foreach (var t in tokens)
                        {
                            Out(Strings.Format("cli.token.line", t.Reader ?? "?", t.Label ?? "?",
                                Pkcs11Token.KindName(t.Kind), t.Serial ?? "?", t.Firmware ?? "?"));
                            Out("  " + Strings.Format("cli.token.pin", Pkcs11Token.PinState(t)));
                            Out("  " + Pkcs11Token.CapabilitySummary(t));
                            if (t.Kind == RutokenKind.RutokenEcp)
                                Out("  " + Strings.Get("token.boundary.ecp"));
                            foreach (var c in t.Containers)
                            {
                                Out("  " + DescribeTokenEntry(c));
                                if (c.Certificate != null)
                                {
                                    anyCertificate = true;
                                    if (outDir != null && !SaveTokenCert(outDir, t, c, usedPaths))
                                        anySaveFailed = true;
                                }
                            }
                        }
                        // Запрошенное извлечение, которое не удалось записать, — это провал команды,
                        // а не тихий успех: иначе скрипт посчитал бы .cer сохранённым (замечание Codex).
                        if (outDir != null && !anyCertificate) return 2;
                        return anySaveFailed ? 3 : 0;
                    }
                    case "extractcert":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        // Сначала сам контейнер: иначе опечатка в имени давала «Обмен: нет,
                        // Подпись: нет» — то же, что у настоящего контейнера без сертификатов.
                        var probe = CertFromContainer.ProbeContainer(args[1]);
                        if (!probe.ContainerOpened)
                        {
                            Err(ContainerFailure(args[1], probe.AcquireError));
                            return 2;
                        }
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
                        // Контейнер не открылся ни одним провайдером — это не «ключ не найден»,
                        // а «нет такого контейнера»: чаще всего опечатка в имени или носитель
                        // не вставлен. Прежний ответ читался как «ключ пропал».
                        if (!ex.ContainerOpened && !sg.ContainerOpened)
                        {
                            Err(ContainerFailure(args[1],
                                ex.AcquireError != 0 ? ex.AcquireError : sg.AcquireError));
                            return 2;
                        }
                        Out(Strings.Format("cli.check.exchange", ex));
                        Out(Strings.Format("cli.check.sign", sg));
                        // 2 — проверять нечего (нет контейнера/ключа), 3 — ключ есть, но запрет не снят
                        if (!ex.KeyFound && !sg.KeyFound) return 2;
                        return CertFromContainer.AllFoundKeysExportable(ex, sg) ? 0 : 3;
                    }
                    case "export":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Out };
                        var saved = pipe.ExportFromTokens(args[1], args.Length > 2 ? args[2] : null);
                        Out(Strings.Format("log.exported", saved.Count));
                        // Ноль снятых контейнеров — не успех: скрипт иначе решил бы, что
                        // файлы на месте (тот же разбор, что у команды token в v1.4.1).
                        return saved.Count > 0 ? 0 : 2;
                    }
                    case "tokenexport":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        string reader = args[1];
                        string outDir = args[2];
                        if (!TryParseDirectOptions(args, 3, out string pin,
                                out string outputName))
                        {
                            Usage();
                            return 1;
                        }
                        Pkcs11TokenInfo token = Pkcs11Token.Enumerate(readContainers: false, log: Out)
                            .Find(candidate => string.Equals(candidate.Reader, reader,
                                StringComparison.OrdinalIgnoreCase));
                        if (token == null)
                        {
                            Err(Strings.Format("err.lite.none", reader));
                            return 2;
                        }
                        if (!DirectTokenApdu.Supports(token.Kind))
                            throw new ArgumentException(Strings.Format("err.reader.unsupported",
                                reader, Pkcs11Token.KindName(token.Kind)));

                        var pipeline = new ExportPipeline { Log = Out };
                        List<DirectTokenContainerRef> containers = pipeline.Direct.ListContainers(token);
                        try
                        {
                            containers = DirectTokenApdu.SelectContainers(token, containers, outputName);
                        }
                        catch (ArgumentException error)
                        {
                            Err(error.Message);
                            return 1;
                        }
                        if (containers.Count == 0)
                        {
                            Err(Strings.Format("err.lite.none", reader));
                            return 2;
                        }
                        int done = 0;
                        foreach (DirectTokenContainerRef selected in containers)
                        {
                            var saved = pipeline.ExportDirectContainer(token, selected, outDir, pin);
                            Out(Strings.Format("cli.done", saved.folder));
                            done++;
                        }
                        return done > 0 ? 0 : 2;
                    }
                    case "tokenfull":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        string reader = args[1];
                        string outDir = args[2];
                        if (!TryParseDirectOptions(args, 3, out string pin,
                                out string outputName))
                        {
                            Usage();
                            return 1;
                        }
                        Pkcs11TokenInfo token = Pkcs11Token.Enumerate(readContainers: false, log: Out)
                            .Find(candidate => string.Equals(candidate.Reader, reader,
                                StringComparison.OrdinalIgnoreCase));
                        if (token == null)
                        {
                            Err(Strings.Format("err.lite.none", reader));
                            return 2;
                        }
                        if (!DirectTokenApdu.Supports(token.Kind))
                            throw new ArgumentException(Strings.Format("err.reader.unsupported",
                                reader, Pkcs11Token.KindName(token.Kind)));

                        var pipeline = new ExportPipeline { Log = Out };
                        List<DirectTokenContainerRef> containers = pipeline.Direct.ListContainers(token);
                        try
                        {
                            containers = DirectTokenApdu.SelectContainers(token, containers, outputName);
                        }
                        catch (ArgumentException error)
                        {
                            Err(error.Message);
                            return 1;
                        }
                        if (containers.Count == 0)
                        {
                            Err(Strings.Format("err.lite.none", reader));
                            return 2;
                        }
                        int exported = 0, completed = 0;
                        foreach (DirectTokenContainerRef selected in containers)
                        {
                            ExportPipelineResult result = pipeline.ExportDirectAndMakeExportable(
                                token, selected, outDir, pin);
                            exported += result.Exported;
                            completed += result.Completed;
                        }
                        Out(Strings.Format("log.exported", exported));
                        return exported == 0 ? 2 : completed == exported ? 0 : 3;
                    }
                    case "keyexport":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var p12 = new P12Utility(P12Utility.Resolve()) { Log = Out };
                        var r = p12.MakeExportable(args[1], args[2], null, args.Length > 3 ? args[3] : null);
                        Out(r.Success ? Strings.Get("cli.keyexport.ok") : Strings.Format("cli.error", r.Explain()));
                        return r.Success ? 0 : 2;
                    }
                    case "exportable":
                    {
                        // Экспортируемая копия контейнера без CSP и p12utility: ключи заново
                        // маскируются, в header.key взводится бит экспорта и пересчитывается MAC.
                        // Исходная папка не изменяется, результат — отдельный контейнер.
                        if (args.Length < 3) { Usage(); return 1; }
                        string containerPassword = args.Length > 3 ? args[3] : "";
                        var source = ContainerFiles.FromDirectory(args[1]);
                        var rebuilt = ExportableContainerBuilder.Build(source, containerPassword);
                        try
                        {
                            rebuilt.WriteTo(args[2]);
                            CryptoProHeaderExportability.RequireExportable(
                                File.ReadAllBytes(Path.Combine(args[2], "header.key")),
                                exchange: File.Exists(Path.Combine(args[2], "primary.key")),
                                signature: File.Exists(Path.Combine(args[2], "primary2.key")));
                            Out(Strings.Format("cli.exportable.ok", args[2]));
                            // Отчёт снимается с того, что реально записано на диск, а не с копии
                            // в памяти: это независимая проверка результата команды.
                            var keys = ContainerKeyExtractor.ExtractAll(args[2], containerPassword);
                            try
                            {
                                foreach (var key in keys)
                                    Out("  " + Strings.Format("cli.exportable.key",
                                        Strings.Get(key.Usage == ContainerKeyExtractor.KeyUsage.Signature
                                            ? "key.usage.signature" : "key.usage.exchange"),
                                        key.Result.CurveOid, Convert.ToHexString(key.Result.PublicX)));
                            }
                            finally { ContainerKeyExtractor.Wipe(keys); }
                        }
                        finally
                        {
                            rebuilt.WipeKeyMaterial();
                            source.WipeKeyMaterial();
                        }
                        return 0;
                    }
                    case "install":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var installed = ContainerStore.Install(args[1], args.Length > 2 ? args[2] : null);
                        Out(Strings.Format("log.install.done", installed));
                        // Сравниваем с итоговым именем, а не с флагом Renamed: когда
                        // запрошенное имя совпадает с нынешним, переименовывать нечего,
                        // и Renamed = false означал бы «КриптоПро не принял копию».
                        if (args.Length > 2 && !string.Equals(installed.Name, args[2], StringComparison.Ordinal))
                            Out(Strings.Format("cli.install.norename", args[2]));
                        if (installed.Verified && !installed.VisibleToCsp)
                        {
                            Out(Strings.Get("cli.install.invisible"));
                            return 2;
                        }
                        if (installed.VisibleToCsp)
                        {
                            string certMgrPath = CertMgr.Locate();
                            if (certMgrPath != null)
                            {
                                var cm = new CertMgr(certMgrPath) { Log = Out };
                                var linked = cm.InstallContainerCertificates(
                                    args[1], CertMgr.HdImageContainer(installed.Name));
                                if (linked.Found > 0 && !linked.AllSucceeded) return 3;
                            }
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
                    case "extractkey":
                    {
                        // Извлечь закрытый ключ прямо из файлового контейнера, без CSP.
                        // .pem — это секрет, поэтому в лог идут только путь и открытый ключ,
                        // а не тело ключа.
                        if (args.Length < 3) { Usage(); return 1; }
                        var r = ContainerKeyExtractor.Extract(args[1], args.Length > 3 ? args[3] : "");
                        File.WriteAllText(args[2], GostKeyExport.ToPkcs8Pem(r));
                        Out(Strings.Format("cli.extractkey.ok", args[2]));
                        Out("  " + Strings.Format("cli.extractkey.pub", r.CurveOid, Convert.ToHexString(r.PublicX)));
                        return 0;
                    }
                    case "extractpfx":
                    {
                        // Собрать .pfx из файлового контейнера целиком своими силами: ни CSP,
                        // ни certmgr. Сертификат берётся из header.key, а если его там нет —
                        // из файла, переданного пятым аргументом.
                        if (args.Length < 4) { Usage(); return 1; }
                        var r = ContainerKeyExtractor.Extract(args[1], args.Length > 4 ? args[4] : "");
                        byte[] cert = args.Length > 5 ? File.ReadAllBytes(args[5]) : null;
                        File.WriteAllBytes(args[2], Pkcs12Export.Build(r, args[3], cert,
                            ContainerStore.ReadName(args[1])));
                        Out(Strings.Format("cli.extractpfx.ok", args[2]));
                        Out("  " + Strings.Get("log.extractpfx.note"));
                        return 0;
                    }
                    case "liteexport":
                    {
                        // Снять контейнер КриптоПро с Рутокен Lite по APDU (мимо CSP, rtCOMLite
                        // Lite не видит) и восстановить закрытый ключ офлайн-разбором §3.1.
                        // PIN не подбираем: если не задан, берём заводской ТОЛЬКО когда PKCS#11
                        // подтверждает дефолтность (счётчик при этом не тратится).
                        if (args.Length < 3) { Usage(); return 1; }
                        string reader = args[1], outDir = args[2];
                        string pin = args.Length > 3 ? args[3] : null;

                        // Явная CLI-команда раньше шла к reader по Rutoken Lite APDU до
                        // классификации. Для известного носителя другого типа это опасная
                        // подмена протокола (в частности, JaCarta LT использует Datastore).
                        // Без положительного распознавания Rutoken Lite APDU не запускаем:
                        // имя штатного reader классифицируется и без PKCS#11-драйвера.
                        var tok = Pkcs11Token.Enumerate(readContainers: false, log: Out)
                            .Find(t => string.Equals(t.Reader, reader, StringComparison.OrdinalIgnoreCase));
                        RutokenKind readerKind = Pkcs11Token.ResolveReaderKind(reader, tok);
                        if (readerKind != RutokenKind.RutokenLite)
                            throw new ArgumentException(Strings.Format("err.reader.unsupported",
                                reader, Pkcs11Token.KindName(readerKind)));

                        var lite = new RutokenLiteApdu { Log = Out };
                        var containers = lite.ListContainers(reader);
                        if (containers.Count == 0) { Err(Strings.Format("err.lite.none", reader)); return 2; }
                        foreach (var c in containers) Out($"  [{c.DfIndex:X2}] {c.Name}");
                        if (string.IsNullOrEmpty(pin))
                        {
                            // Авто-PIN только при заводском PIN И полностью чистом счётчике:
                            // при подъеденном счётчике даже верный ввод рискует, а промах — блокирует.
                            if (tok != null && tok.PinDefault &&
                                !tok.PinCountLow && !tok.PinFinalTry && !tok.PinLocked)
                                pin = StandardPins.AutoFillUserPinFor(RutokenKind.RutokenLite);
                            if (string.IsNullOrEmpty(pin))
                            { Err(Strings.Format("err.lite.pin", "—")); return 2; }
                        }
                        int done = 0;
                        int failed = 0;
                        foreach (var c in containers)
                        {
                            // Имя контейнера может нести ФИО — в путь на диске не кладём, только индекс.
                            string dir = RutokenLiteApdu.ReserveOutputDirectory(outDir, $"lite_{c.DfIndex:X2}");
                            try { lite.ReadContainer(reader, c.DfIndex, pin, dir); }
                            catch
                            {
                                // APDU не успела ничего сохранить — не оставляем ложный пустой результат.
                                try
                                {
                                    if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                                        Directory.Delete(dir);
                                }
                                catch (IOException) { }
                                throw;
                            }
                            Out(Strings.Format("cli.done", dir));
                            try
                            {
                                var r = ContainerKeyExtractor.Extract(dir);
                                File.WriteAllText(Path.Combine(dir, "private.pem"), GostKeyExport.ToPkcs8Pem(r));
                                Out(Strings.Format("cli.extractkey.ok", Path.Combine(dir, "private.pem")));
                                Out("  " + Strings.Format("cli.extractkey.pub", r.CurveOid, Convert.ToHexString(r.PublicX)));
                                done++;
                            }
                            catch (ContainerKeyException ex)
                            {
                                failed++;
                                Err(Strings.Format("cli.error", ex.Message));
                            }
                        }
                        return failed > 0 ? 3 : done > 0 ? 0 : 2;
                    }
                    case "angaraexport":
                    {
                        // Снять контейнер КриптоПро с MS_KEY K «АНГАРА» (БИФИТ) прямым APDU,
                        // минуя CSP, и восстановить закрытый ключ офлайн-разбором. Носитель не
                        // имеет системного PKCS#11-модуля, поэтому вид определяется по имени
                        // считывателя, а фактический гейт — SELECT приложения MSKEYKC на карте
                        // (у iBank2Key его нет). PIN не подбираем: для контейнеров protected=none
                        // это транспортный «11111111», который посылает сам CSP.
                        if (args.Length < 3) { Usage(); return 1; }
                        string reader = args[1], outDir = args[2];
                        string pin = args.Length > 3 ? args[3] : StandardPins.UserPinFor(RutokenKind.Bifit);

                        RutokenKind kind = Pkcs11Token.ResolveReaderKind(reader, null);
                        if (kind != RutokenKind.Bifit)
                            throw new ArgumentException(Strings.Format("err.reader.unsupported",
                                reader, Pkcs11Token.KindName(kind)));
                        var token = new Pkcs11TokenInfo { Reader = reader, Kind = RutokenKind.Bifit };

                        var pipeline = new ExportPipeline { Log = Out };
                        List<DirectTokenContainerRef> containers = pipeline.Direct.ListContainers(token);
                        if (containers.Count == 0) { Err(Strings.Format("err.lite.none", reader)); return 2; }
                        foreach (var c in containers) Out($"  [{c.OutputName}]");
                        int done = 0, failed = 0;
                        foreach (DirectTokenContainerRef selected in containers)
                        {
                            (RutokenContainer container, string folder) saved;
                            try
                            {
                                saved = pipeline.ExportDirectContainer(token, selected, outDir, pin);
                            }
                            catch (LiteApduException ex)
                            {
                                // Отказ карты (неверный VERIFY, блокировка, обрыв) — прекращаем
                                // ПОЛНОСТЬЮ: тот же PIN на следующем контейнере лишь потратит
                                // очередную попытку, а их всего десять до необратимой блокировки.
                                failed++;
                                Err(Strings.Format("cli.error", ex.Message));
                                break;
                            }
                            Out(Strings.Format("cli.done", saved.folder));
                            try
                            {
                                // Пароль контейнера (CPKDF) — не транспортный VERIFY: у
                                // protected=none он пуст. Транспортный «11111111» уже отработал
                                // при чтении файлов с карты.
                                var r = ContainerKeyExtractor.Extract(saved.folder, "");
                                File.WriteAllText(Path.Combine(saved.folder, "private.pem"),
                                    GostKeyExport.ToPkcs8Pem(r));
                                Out(Strings.Format("cli.extractkey.ok", Path.Combine(saved.folder, "private.pem")));
                                Out("  " + Strings.Format("cli.extractkey.pub", r.CurveOid,
                                    Convert.ToHexString(r.PublicX)));
                                done++;
                            }
                            catch (ContainerKeyException ex) { failed++; Err(Strings.Format("cli.error", ex.Message)); }
                        }
                        return failed > 0 ? 3 : done > 0 ? 0 : 2;
                    }
                    case "full":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Out };
                        var result = pipe.ExportAndMakeExportable(
                            destParent: args[1],
                            certExchange: args.Length > 2 ? args[2] : null,
                            userPin: args.Length > 3 ? args[3] : null);
                        Out(Strings.Format("log.exported", result.Exported));
                        return result.AllSucceeded ? 0 : result.Exported == 0 ? 2 : 3;
                    }
                    case "pins":
                    {
                        // Реестр заводских PIN: значения опубликованы производителями и нужны,
                        // когда владелец забыл, менялся ли PIN на его носителе.
                        Out(Strings.Get("cli.pins.header"));
                        foreach (StandardPin pin in StandardPins.All)
                        {
                            string user = string.IsNullOrEmpty(pin.UserPin)
                                ? Strings.Get("cli.pins.unset") : pin.UserPin;
                            string admin = string.IsNullOrEmpty(pin.AdminPin)
                                ? Strings.Get("cli.pins.unset") : pin.AdminPin;
                            Out("  " + Strings.Format("cli.pins.line", pin.Model, user, admin,
                                Strings.Get(pin.Supported ? "cli.pins.supported" : "cli.pins.planned")));
                            if (!string.IsNullOrEmpty(pin.NoteKey))
                                Out("      " + Strings.Get(pin.NoteKey));
                            Out("      " + pin.Source);
                        }
                        Out(Strings.Get("cli.pins.note"));
                        return 0;
                    }
                    case "fingerprint":
                        Out(LicenseGate.FingerprintText());
                        return 0;
                    case "license":
                    {
                        // Без аргумента или `license status` — показать статус и отпечаток;
                        // `license <файл>` — проверить файл и, если он для этой машины, установить.
                        if (args.Length < 2 || string.Equals(args[1], "status", StringComparison.OrdinalIgnoreCase))
                        {
                            Out(LicenseGate.StatusText());
                            Out(LicenseGate.FingerprintText());
                            return LicenseGate.IsLicensed() ? 0 : 2;
                        }
                        if (!File.Exists(args[1]))
                        {
                            // Иначе наружу уходило системное «Could not find a part of the
                            // path …» — по-английски и про путь, а не про лицензию.
                            Err(Strings.Format("err.license.notfound", args[1]));
                            return 3;
                        }
                        var info = LicenseGate.Install(args[1]);
                        if (info.Ok)
                        {
                            Out(Strings.Format("license.installed", LicenseGate.LicensePath));
                            Out(LicenseGate.Describe(info));
                            return 0;
                        }
                        Err(Strings.Get("license.status.invalid"));
                        // Причина — отдельной строкой и на языке интерфейса: «недействительна» не
                        // отличает чужую платформу от чужого отпечатка. Точное сообщение верификатора
                        // (диагностика протокола, всегда по-русски) остаётся в файле журнала.
                        Err(LicenseGate.ReasonText(info));
                        if (!string.IsNullOrEmpty(info.VerifierDiagnostic))
                            SessionLog.Write(info.VerifierDiagnostic);
                        return 2;
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

        /// <summary>
        /// Показать карты, которые физически стоят в считывателях PC/SC, но которых нет среди
        /// перечисленных PKCS#11-токенов. Это честно отличает «носитель не вставлен» от «носитель
        /// есть, но не является поддерживаемым контейнером» (например, JaCarta на платформе Athena
        /// IDProtect: она работает через минидрайвер Microsoft, и ни одна vendor-библиотека PKCS#11
        /// её как токен не показывает). Только диагностика: путь снятия ключа отсюда не выбирается.
        /// </summary>
        private static void ReportUncoveredCards(List<Pkcs11TokenInfo> tokens)
        {
            var pcsc = PcscReaders.List(m => Out("[PC/SC] " + m));
            var readers = new List<string>();
            foreach (var t in tokens) if (t?.Reader != null) readers.Add(t.Reader);

            // Сводка печатается всегда: расхождение «устройств PKCS#11 семь, а считывателей
            // восемь» без неё выглядело ошибкой приложения, хотя считаются разные вещи.
            var lines = PcscReaders.CoverageLines(pcsc, readers);
            if (lines.Count == 0) return;
            foreach (var line in lines) Out("[PC/SC] " + line);
            if (PcscReaders.Uncovered(pcsc, readers).Count > 0)
                Out("  " + Strings.Get("cli.pcsc.hint"));
        }

        /// <summary>
        /// Строка списка для одной записи токена. Сертификат без парного контейнера КриптоПро
        /// называть «контейнером» нельзя — у него отдельная формулировка.
        /// </summary>
        private static string DescribeTokenEntry(Pkcs11Container c) =>
            c.CertificateOnly
                ? Strings.Format("cli.token.certonly", c.Name ?? "?")
                : Strings.Format("cli.token.container", c.Name ?? "?",
                    Strings.Get(c.Certificate != null ? "common.present" : "common.none"));

        /// <summary>
        /// Разобрать единственный позиционный PIN и необязательный точный технический
        /// селектор. Значение можно передать как --container id или --container=id.
        /// Неизвестные опции и дубли отклоняются, а не превращаются в PIN.
        /// </summary>
        private static bool TryParseDirectOptions(string[] args, int firstOptional,
                                                  out string pin, out string outputName)
        {
            pin = null;
            outputName = null;
            for (int i = firstOptional; i < args.Length; i++)
            {
                string argument = args[i];
                if (argument.StartsWith("--container=", StringComparison.OrdinalIgnoreCase))
                {
                    if (outputName != null) return false;
                    outputName = argument.Substring("--container=".Length);
                    if (string.IsNullOrWhiteSpace(outputName)) return false;
                }
                else if (string.Equals(argument, "--container",
                             StringComparison.OrdinalIgnoreCase))
                {
                    if (outputName != null || i + 1 >= args.Length) return false;
                    outputName = args[++i];
                    if (string.IsNullOrWhiteSpace(outputName)
                        || outputName.StartsWith("--", StringComparison.Ordinal))
                        return false;
                }
                else
                {
                    if (argument.StartsWith("--", StringComparison.Ordinal) || pin != null)
                        return false;
                    pin = argument;
                }
            }
            return true;
        }

        /// <summary>
        /// Сохранить извлечённый с токена сертификат (.cer) — без обращения к CSP.
        /// Имя файла включает серийный номер токена, а при совпадении получает числовой
        /// суффикс: у разных токенов/контейнеров метки бывают одинаковые, и без этого
        /// один .cer молча затирал бы другой (замечание Codex). Возвращает успех записи.
        /// </summary>
        private static bool SaveTokenCert(string outDir, Pkcs11TokenInfo t, Pkcs11Container c, HashSet<string> used)
        {
            try
            {
                Directory.CreateDirectory(outDir);
                string path = Pkcs11Token.UniqueCertPath(outDir, c.Name, t.Serial, used);
                File.WriteAllBytes(path, c.Certificate);
                Out("    " + Strings.Format("cli.token.cert.saved", path));
                return true;
            }
            catch (Exception e)
            {
                Out("    " + Strings.Format("cli.token.certfail", c.Name ?? "?", e.Message));
                return false;
            }
        }

        /// <summary>
        /// Подсказка по командам. Ширина колонки считается по факту: переводы длиннее
        /// русского оригинала, а жёсткий отступ разъехался бы.
        /// </summary>
        /// <summary>
        /// Почему контейнер не открылся. «Не найден» говорим только на кодах «нет такого
        /// контейнера»: любой другой отказ (например NTE_SILENT_CONTEXT — носителю нужен диалог
        /// PIN) означает, что контейнер, возможно, есть, и прятать это за «не найден» нельзя.
        /// </summary>
        private static string ContainerFailure(string container, int error) =>
            error == 0 || CertFromContainer.IsMissingContainer(error)
                ? Strings.Format("err.container.missing", container)
                : Strings.Format("err.container.openfail", container, CryptoErrors.Describe(error));

        private static void Usage()
        {
            Out(Strings.Get("cli.usage.title"));
            int width = Commands.Max(c => c.Syntax.Length) + 2;
            foreach (var (syntax, key) in Commands)
                Out("  " + syntax.PadRight(width, ' ') + Strings.Get(key));
            Out("  " + Strings.Get("cli.usage.gui"));
            Out("  " + Strings.Get("token.boundary.ecp"));
        }
    }
}
