using System;
using System.IO;
using System.Runtime.Versioning;

namespace CryptoProExport.App
{
    /// <summary>Консольный режим (для скриптов/автоматизации и CI-проверок).</summary>
    [SupportedOSPlatform("windows")]
    internal static class Cli
    {
        public static int Run(string[] args)
        {
            try
            {
                switch (args[0].ToLowerInvariant())
                {
                    case "deps":
                    {
                        foreach (var line in CryptoProExport.Diagnostics.Report(detailed: true))
                            Console.WriteLine(line);
                        // Ненулевой код, только если не хватает того, что нельзя вшить, — КриптоПро CSP
                        return CertFromContainer.AvailableProviders().Count > 0 ? 0 : 2;
                    }
                    case "list":
                    {
                        Console.WriteLine("Контейнеры, видимые CSP:");
                        foreach (var c in CertFromContainer.EnumContainers())
                            Console.WriteLine($"  {c.Name}  (провайдер {c.ProvType})");
                        Console.WriteLine("Контейнеры на подключённых Рутокенах:");
                        var exp = new RutokenExporter { Log = Console.WriteLine };
                        foreach (var c in exp.ReadAllContainers())
                            Console.WriteLine($"  {c.TokenName} {c.TokenDir} \"{c.ContainerName}\" ({c.Files.Count} файлов)");
                        return 0;
                    }
                    case "extractcert":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var (ex, sg) = CertFromContainer.SaveCerts(args[1], args[2]);
                        Console.WriteLine($"Обмен:  {ex ?? "нет"}");
                        Console.WriteLine($"Подпись: {sg ?? "нет"}");
                        return (ex != null || sg != null) ? 0 : 2;
                    }
                    case "checkexport":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var ex = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_KEYEXCHANGE);
                        var sg = CertFromContainer.CheckExportable(args[1], CertFromContainer.AT_SIGNATURE);
                        Console.WriteLine($"Ключ обмена:  {ex}");
                        Console.WriteLine($"Ключ подписи: {sg}");
                        if (!ex.KeyFound && !sg.KeyFound) return 2;
                        return (ex.Exportable || sg.Exportable) ? 0 : 3;
                    }
                    case "export":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Console.WriteLine };
                        pipe.ExportFromTokens(args[1], args.Length > 2 ? args[2] : null);
                        return 0;
                    }
                    case "keyexport":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        var p12 = new P12Utility(P12Utility.Resolve()) { Log = Console.WriteLine };
                        var r = p12.MakeExportable(args[1], args[2], null, args.Length > 3 ? args[3] : null);
                        Console.WriteLine(r.Success ? "Готово: ключ экспортируемый" : "Ошибка: " + r.Explain());
                        return r.Success ? 0 : 2;
                    }
                    case "install":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        string folder = args[1];
                        string name = args.Length > 2
                            ? args[2]
                            : NameKey.Parse(ReadNameKey(folder)) ?? Path.GetFileName(Path.GetFullPath(folder));
                        string target = ContainerStore.Install(folder, name);
                        Console.WriteLine($"Контейнер \"{name}\" установлен в КриптоПро: {target}");
                        return 0;
                    }
                    case "installed":
                    {
                        Console.WriteLine("Файловые контейнеры в хранилище КриптоПро (" + ContainerStore.HdImageDir + "):");
                        foreach (var c in ContainerStore.Installed())
                            Console.WriteLine($"  {c.Name}  ->  {c.Folder}");
                        return 0;
                    }
                    case "uninstall":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        ContainerStore.Uninstall(args[1]);
                        Console.WriteLine("Удалено: " + args[1]);
                        return 0;
                    }
                    case "topfx":
                    {
                        if (args.Length < 3) { Usage(); return 1; }
                        string exe = CertMgr.Locate();
                        if (exe == null)
                        {
                            Console.Error.WriteLine("certmgr не найден — нужен установленный КриптоПро CSP");
                            return 2;
                        }
                        var cm = new CertMgr(exe) { Log = Console.WriteLine };
                        var r = cm.ExportContainerToPfx(args[1], args[2], args.Length > 3 ? args[3] : null);
                        Console.WriteLine(r.Success ? "Готово: " + args[2] : "Ошибка: " + r.Output);
                        return r.Success ? 0 : 2;
                    }
                    case "full":
                    {
                        if (args.Length < 2) { Usage(); return 1; }
                        var pipe = new ExportPipeline { Log = Console.WriteLine };
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
                Console.Error.WriteLine("ОШИБКА: " + ex.Message);
                return 3;
            }
        }

        private static byte[] ReadNameKey(string folder)
        {
            string path = Path.Combine(folder, "name.key");
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
        }

        private static void Usage()
        {
            Console.WriteLine("CryptoProExport — экспорт контейнера с Рутокена + снятие запрета на экспорт ключа");
            Console.WriteLine("  deps                                   проверить зависимости (встроенные + КриптоПро CSP)");
            Console.WriteLine("  list                                   перечислить контейнеры (CSP + токены)");
            Console.WriteLine("  extractcert <container> <outDir>       извлечь .cer из контейнера (CryptoAPI)");
            Console.WriteLine("  checkexport <container>                проверить, экспортируемый ли закрытый ключ");
            Console.WriteLine("  export <destDir> [pin]                 снять контейнеры с токенов на диск");
            Console.WriteLine("  keyexport <folder> <cert.cer> [pass]   сделать ключ в папке экспортируемым");
            Console.WriteLine("  install <folder> [name]                установить папку-контейнер в КриптоПро");
            Console.WriteLine("  installed                              показать установленные файловые контейнеры");
            Console.WriteLine("  uninstall <folder>                     удалить установленный контейнер");
            Console.WriteLine("  topfx <container> <out.pfx> [pass]     выгрузить контейнер в PKCS#12 (certmgr)");
            Console.WriteLine("  full <destDir> [cert.cer] [pin]        снять с токена + авто-.cer + keyexport");
            Console.WriteLine("  (без аргументов — графический интерфейс)");
        }
    }
}
