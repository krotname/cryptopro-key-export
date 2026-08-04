using System;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    [SupportedOSPlatform("windows")]
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            SessionLog.Prune();

            // Консольный режим и self-test
            if (args.Length > 0)
            {
                if (string.Equals(args[0], "--selftest", StringComparison.OrdinalIgnoreCase))
                    return SelfTest();
                return Cli.Run(args);
            }

            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
            return 0;
        }

        /// <summary>Построить форму и закрыть — проверка, что UI-граф собирается (для headless-сборки/CI).</summary>
        private static int SelfTest()
        {
            try
            {
                ApplicationConfiguration.Initialize();
                using var f = new MainForm();

                var (withTip, missing) = f.CheckTooltips();
                if (missing.Count > 0)
                {
                    Console.Error.WriteLine("SELFTEST FAIL: без всплывающих подсказок остались элементы: "
                                            + string.Join(", ", missing));
                    return 1;
                }

                f.Load += (_, __) => f.BeginInvoke(new Action(f.Close));
                f.ShowInTaskbar = false;
                f.WindowState = FormWindowState.Minimized;
                Application.Run(f);
                Console.WriteLine($"SELFTEST OK: форма построена и закрыта без ошибок, подсказок на элементах: {withTip}");
                foreach (var line in CryptoProExport.Diagnostics.Report())
                    Console.WriteLine("  " + line);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("SELFTEST FAIL: " + ex);
                return 1;
            }
        }
    }
}
