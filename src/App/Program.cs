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
                f.Load += (_, __) => f.BeginInvoke(new Action(f.Close));
                f.ShowInTaskbar = false;
                f.WindowState = FormWindowState.Minimized;
                Application.Run(f);
                Console.WriteLine("SELFTEST OK: форма построена и закрыта без ошибок");
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
