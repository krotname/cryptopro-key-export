using System;
using System.IO;
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
                        Out("Контейнеры, видимые CSP:");
                        foreach (var c in CertFromContainer.EnumContainers())
                            Out($"  {c.Name}  (провайдер {c.ProvType})");
                        Out("Контейнеры на подключённых Рутокенах:");
                        var exp = new RutokenExporter { Log = Out };
                        foreach (var c in exp.ReadAllContainers())
                            Out($"  {c.TokenName} {c.TokenDir} \"{c.ContainerName}\" ({c.Files.Count} файлов)");
                        return 0;
                    }
                    case "extractcert":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var (ex, sg) = CertFromContainer.SaveCerts(args[1], args[2]);
                        Out($"Обмен:  {ex ?? "нет"}");
                        Out($"Подпись: {sg ?? "нет"}");
                        return (ex != null || sg != null) ? 0 : 2;
                    }
                    case "checkexport":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var ex = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_KEYEXCHANGE);
                        var sg = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_SIGNATURE);
                        Out($"Ключ обмена:  {ex}");
                        Out($"Ключ подписи: {sg}");
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
                        Out(r.Success ? "Готово: ключ экспортируемый" : "Ошибка: " + r.Explain());
                        return r.Success ? 0 : 2;
                    }
                    case "install":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var installed = ContainerStore.Install(args[1], args.Length > 2 ? args[2] : null);
                        Out("Контейнер установлен: " + installed);
                        if (args.Length > 2 && !installed.Renamed)
                            Out($"Переименование не применилось: КриптоПро не принял копию с именем \"{args[2]}\". " +
                                "Так бывает, пока с контейнера не снят запрет на экспорт (--cprepair).");
                        if (installed.Verified && !installed.VisibleToCsp)
                        {
                            Out("КриптоПро пока не видит контейнер. Обычно помогает повторный запуск " +
                                "или перезаход в систему — CSP кэширует список контейнеров.");
                            return 2;
                        }
                        return 0;
                    }
                    case "installed":
                    {
                        Out("Файловые контейнеры в хранилище КриптоПро (" + ContainerStore.HdImageDir + "):");
                        foreach (var c in ContainerStore.Installed())
                            Out($"  {c.Name}  ->  {c.Folder}");
                        return 0;
                    }
                    case "uninstall":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        ContainerStore.Uninstall(args[1]);
                        Out("Удалено: " + args[1]);
                        return 0;
                    }
                    case "topfx":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        string exe = CertMgr.Locate();
                        if (exe == null)
                        {
                            Err("certmgr не найден — нужен установленный КриптоПро CSP");
                            return 2;
                        }
                        var cm = new CertMgr(exe) { Log = Out };
                        var r = cm.ExportContainerToPfx(args[1], args[2], args.Length > 3 ? args[3] : null);
                        Out(r.Success ? "Готово: " + args[2] : "Ошибка: " + r.Output);
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
                Err("ОШИБКА: " + ex.Message);
                return 3;
            }
        }

        private static void Usage()
        {
            Out("CryptoProExport — экспорт контейнера с Рутокена + снятие запрета на экспорт ключа");
            Out("  deps                                   проверить зависимости (встроенные + КриптоПро CSP)");
            Out("  list                                   перечислить контейнеры (CSP + токены)");
            Out("  extractcert <container> <outDir>       извлечь .cer из контейнера (CryptoAPI)");
            Out("  checkexport <container>                проверить, экспортируемый ли закрытый ключ");
            Out("  export <destDir> [pin]                 снять контейнеры с токенов на диск");
            Out("  keyexport <folder> <cert.cer> [pass]   сделать ключ в папке экспортируемым");
            Out("  install <folder> [name]                установить папку-контейнер в КриптоПро");
            Out("  installed                              показать установленные файловые контейнеры");
            Out("  uninstall <folder>                     удалить установленный контейнер");
            Out("  topfx <container> <out.pfx> [pass]     выгрузить контейнер в PKCS#12 (certmgr)");
            Out("  full <destDir> [cert.cer] [pin]        снять с токена + авто-.cer + keyexport");
            Out("  help                                   встроенное руководство целиком");
            Out("  (без аргументов — графический интерфейс)");
        }
    }
}
