using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

            // --lang вырезается из args до разбора команды: Cli.Run по-прежнему видит
            // только позиционные аргументы, и контракт консольного режима не меняется.
            if (!TakeLanguage(ref args, out string language, out string langError))
            {
                Console.Error.WriteLine(langError);
                return 1;
            }
            Strings.Init(language);

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
        /// Вынуть <c>--lang xx</c> (или <c>--lang=xx</c>) из аргументов. Возвращает false
        /// с готовым сообщением, если код языка не указан или не опознан.
        /// </summary>
        private static bool TakeLanguage(ref string[] args, out string language, out string error)
        {
            language = null;
            error = null;
            var rest = new List<string>(args.Length);

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a.StartsWith("--lang=", StringComparison.OrdinalIgnoreCase))
                {
                    language = a.Substring("--lang=".Length);
                }
                else if (string.Equals(a, "--lang", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 >= args.Length)
                    {
                        error = Strings.Format("cli.lang.missing", string.Join(", ", Strings.Available));
                        return false;
                    }
                    language = args[++i];
                }
                else
                {
                    rest.Add(a);
                }
            }

            args = rest.ToArray();
            if (language != null && Strings.Resolve(language) == null)
            {
                error = Strings.Format("cli.lang.unknown", language, string.Join(", ", Strings.Available));
                return false;
            }
            return true;
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

        /// <summary>У каждого элемента есть подсказка, и ни в одной надписи нет маркера пропавшего перевода.</summary>
        private static bool Inspect(MainForm form, string language, string stage, ref int withTip)
        {
            var (tips, missing) = form.CheckTooltips();
            if (missing.Count > 0)
            {
                Console.Error.WriteLine($"SELFTEST FAIL [{language}, {stage}]: без всплывающих подсказок "
                                        + "остались элементы: " + string.Join(", ", missing));
                return false;
            }

            var untranslated = form.MissingTranslations();
            if (untranslated.Count > 0)
            {
                Console.Error.WriteLine($"SELFTEST FAIL [{language}, {stage}]: нет переводов: "
                                        + string.Join(", ", untranslated.Take(10)));
                return false;
            }

            withTip = tips;
            return true;
        }

        /// <summary>
        /// Построить форму и закрыть — проверка, что UI-граф собирается (для headless-сборки/CI).
        /// Форма строится на каждом вшитом языке: так ловятся и потерянные подсказки, и
        /// незаполненные ключи перевода (Strings.Get возвращает заметный маркер, а не пустоту).
        /// </summary>
        private static int SelfTest()
        {
            try
            {
                ApplicationConfiguration.Initialize();

                int checkedTips = 0;

                // 1. Окно строится заново на каждом языке — так проверяется и стартовая раскладка,
                //    включая зеркальную (RightToLeftLayout) у ar/ur/fa.
                foreach (string language in Strings.Available)
                {
                    using var scope = Strings.Scope(language);
                    using var probe = new MainForm();
                    if (!Inspect(probe, language, "построение", ref checkedTips)) return 1;
                }

                // 2. Одно окно проводится по всем языкам подряд — это путь выбора языка в списке:
                //    надписи переставляются на уже построенной форме, а RightToLeft меняется на лету.
                using (var scope = Strings.Scope(Strings.Current))
                using (var switching = new MainForm())
                {
                    foreach (string language in Strings.Available)
                    {
                        switching.SwitchLanguage(language);
                        if (!Inspect(switching, language, "переключение", ref checkedTips)) return 1;
                    }
                }

                using var f = new MainForm();
                var (tips, _) = f.CheckTooltips();
                f.Load += (_, __) => f.BeginInvoke(new Action(f.Close));
                f.ShowInTaskbar = false;
                f.WindowState = FormWindowState.Minimized;
                Application.Run(f);

                Console.WriteLine($"SELFTEST OK: форма построена и закрыта без ошибок, подсказок на элементах: {tips}");
                Console.WriteLine($"  языков интерфейса: {Strings.Available.Count} ({string.Join(", ", Strings.Available)}), "
                                  + $"проверено построением и переключением, подсказок на каждом: {checkedTips}");
                Console.WriteLine($"  руководство переведено на: {string.Join(", ", GuideText.Available)}");
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
