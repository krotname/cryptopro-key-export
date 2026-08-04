using System;
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
                        Console.WriteLine(r.Success ? "Готово: ключ экспортируемый" : $"Ошибка {r.ExitCode}");
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

        private static void Usage()
        {
            Console.WriteLine("CryptoProExport — экспорт контейнера с Рутокена + снятие запрета на экспорт ключа");
            Console.WriteLine("  deps                                   проверить зависимости (встроенные + КриптоПро CSP)");
            Console.WriteLine("  list                                   перечислить контейнеры (CSP + токены)");
            Console.WriteLine("  extractcert <container> <outDir>       извлечь .cer из контейнера (CryptoAPI)");
            Console.WriteLine("  export <destDir> [pin]                 снять контейнеры с токенов на диск");
            Console.WriteLine("  keyexport <folder> <cert.cer> [pass]   сделать ключ в папке экспортируемым");
            Console.WriteLine("  full <destDir> [cert.cer] [pin]        снять с токена + авто-.cer + keyexport");
            Console.WriteLine("  (без аргументов — графический интерфейс)");
        }
    }
}
