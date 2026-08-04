using System;
using System.IO;
using System.Runtime.Versioning;
using System.Text;
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
            UseUtf8Output();

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

        /// <summary>
        /// Писать вывод в UTF-8. Без этого перенаправленный stdout уходит в кодировке консоли (cp1251),
        /// и русский текст в логах CI и в редакторах превращается в «?????».
        /// У WinExe консоли может не быть вовсе — тогда просто ничего не меняем.
        /// </summary>
        private static void UseUtf8Output()
        {
            // Console.OutputEncoding здесь не годится: у WinExe консоли нет, и присвоение падает.
            // Поэтому подменяем сами писатели поверх стандартных дескрипторов.
            try
            {
                var utf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), utf8) { AutoFlush = true });
                Console.SetError(new StreamWriter(Console.OpenStandardError(), utf8) { AutoFlush = true });
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
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
