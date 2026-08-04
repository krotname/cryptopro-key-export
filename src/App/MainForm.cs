using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    /// <summary>
    /// Главное окно. Три действия одного конвейера:
    ///   • Обновить — показать контейнеры (видимые CSP + на подключённых Рутокенах);
    ///   • Экспорт с токена — снять 6 .key на диск (rtCOMLite, обход CSP);
    ///   • Извлечь .cer — вытащить сертификат из контейнера (CryptoAPI);
    ///   • Сделать экспортируемым — полный цикл: снять + авто-.cer + p12utility --keyexport.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class MainForm : Form
    {
        private TextBox _txtP12, _txtDest, _txtPin, _txtLog;
        private ListView _lv;
        private Button _btnRefresh, _btnExport, _btnExtract, _btnFull;
        private ToolTip _tips;

        public MainForm()
        {
            BuildUi();
            _txtP12.Text = P12Utility.Locate() ?? "";
            _txtDest.Text = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "RutokenExport");
        }

        /// <summary>После показа окна — сводка по зависимостям в лог (что вшито, чего не хватает).</summary>
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Run(() =>
            {
                Log("Зависимости (скачивать и ставить ничего не нужно, кроме КриптоПро CSP):");
                foreach (var line in CryptoProExport.Diagnostics.Report())
                    Log("  " + line);
                Log("");
            });
        }

        private void BuildUi()
        {
            Text = "Экспорт ключей КриптоПро с Рутокена";
            Font = new Font("Segoe UI", 9f);
            ClientSize = new Size(880, 640);
            MinimumSize = new Size(720, 520);
            StartPosition = FormStartPosition.CenterScreen;

            // Всплывающие подсказки: держим долго открытыми — тексты многострочные и объясняют шаг целиком
            _tips = new ToolTip
            {
                AutoPopDelay = 30000, InitialDelay = 300, ReshowDelay = 100,
                ShowAlways = true, UseAnimation = false, UseFading = false,
            };

            // --- Панель настроек ---
            var settings = new TableLayoutPanel
            {
                Dock = DockStyle.Top, ColumnCount = 3, RowCount = 3,
                Padding = new Padding(10, 10, 10, 4), Height = 116, AutoSize = false,
            };
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));

            _txtP12 = new TextBox
            {
                Dock = DockStyle.Fill,
                PlaceholderText = "встроенная копия — указывать ничего не нужно",
            };
            _txtDest = new TextBox { Dock = DockStyle.Fill };
            _txtPin = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true };

            var lblP12 = new Label { Text = "p12utility.exe:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill };
            settings.Controls.Add(lblP12, 0, 0);
            settings.Controls.Add(_txtP12, 1, 0);
            var btnP12 = new Button { Text = "Обзор…", Dock = DockStyle.Fill };
            btnP12.Click += (_, __) => PickFile(_txtP12, "p12utility|p12utility*.exe|Все файлы|*.*");
            settings.Controls.Add(btnP12, 2, 0);

            var lblDest = new Label { Text = "Папка назначения:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill };
            settings.Controls.Add(lblDest, 0, 1);
            settings.Controls.Add(_txtDest, 1, 1);
            var btnDest = new Button { Text = "Обзор…", Dock = DockStyle.Fill };
            btnDest.Click += (_, __) => PickFolder(_txtDest);
            settings.Controls.Add(btnDest, 2, 1);

            var lblPin = new Label { Text = "PIN (необязат.):", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill };
            settings.Controls.Add(lblPin, 0, 2);
            settings.Controls.Add(_txtPin, 1, 2);
            var lblPinHint = new Label { Text = "пусто → окно ввода", ForeColor = Color.Gray, TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill };
            settings.Controls.Add(lblPinHint, 2, 2);

            const string tipP12 =
                "Путь к утилите КриптоПро p12utility — ею снимается запрет на экспорт ключа.\n" +
                "Оставьте поле пустым: копия утилиты уже встроена в программу и распакуется сама.\n" +
                "Заполняйте, только если нужна другая версия p12utility.";
            Tip(lblP12, tipP12); Tip(_txtP12, tipP12);
            Tip(btnP12, "Выбрать другой файл p12utility.exe вместо встроенного.");

            const string tipDest =
                "Куда складывать результат: папки со снятыми контейнерами (*.key) и файлы сертификатов (.cer).\n" +
                "Внимание: это копия вашего закрытого ключа — храните её как секрет.";
            Tip(lblDest, tipDest); Tip(_txtDest, tipDest);
            Tip(btnDest, "Выбрать папку назначения в проводнике.");

            const string tipPin =
                "PIN пользователя Рутокена.\n" +
                "Пусто → PIN спросит системное окно (а если на токене заводской PIN, подставится 12345678).\n" +
                "Символы скрыты; значение нигде не сохраняется.";
            Tip(lblPin, tipPin); Tip(_txtPin, tipPin); Tip(lblPinHint, tipPin);

            // --- Панель кнопок ---
            var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 46, Padding = new Padding(10, 4, 10, 4) };
            _btnRefresh = MakeButton("Обновить список", 130, (_, __) => Run(RefreshList));
            _btnExport = MakeButton("Экспорт с токена", 150, (_, __) => Run(DoExport));
            _btnExtract = MakeButton("Извлечь сертификат", 160, (_, __) => Run(DoExtract));
            _btnFull = MakeButton("Сделать экспортируемым", 200, (_, __) => Run(DoFull));
            _btnFull.Font = new Font(Font, FontStyle.Bold);
            buttons.Controls.AddRange(new Control[] { _btnRefresh, _btnExport, _btnExtract, _btnFull });

            Tip(_btnRefresh,
                "Шаг 1. Показать список ключевых контейнеров:\n" +
                "  • видимые КриптоПро CSP (в т.ч. на вставленном токене);\n" +
                "  • найденные на подключённых Рутокенах напрямую.\n" +
                "Ничего не изменяет — только читает. С этой кнопки удобно начинать.");
            Tip(_btnExport,
                "Шаг 2. Снять контейнеры со всех подключённых Рутокенов в папку назначения\n" +
                "(по 6 файлов *.key на контейнер). Читает память токена напрямую, минуя CSP,\n" +
                "поэтому работает и при запрете на экспорт. Токен и данные на нём не изменяются.\n" +
                "Ключ в снятой копии остаётся неэкспортируемым — это делает кнопка «Сделать экспортируемым».");
            Tip(_btnExtract,
                "Шаг 3. Сохранить сертификат выбранного в списке контейнера в файл .cer\n" +
                "(открытые данные, извлекаются штатно через CryptoAPI).\n" +
                "Нужен выделенный контейнер в списке, вставленный токен и видимость контейнера в CSP.\n" +
                "Сертификат требуется утилите p12utility для снятия запрета на экспорт.");
            Tip(_btnFull,
                "Всё за один клик: снять контейнеры с токена → извлечь сертификаты →\n" +
                "снять запрет на экспорт закрытого ключа (p12utility --cprepair --keyexport).\n" +
                "Результат: в папке назначения — копия контейнера с экспортируемым ключом\n" +
                "(годится для резервной копии, переноса и конвертации в PFX).\n" +
                "Исходный токен при этом не изменяется; исходный header.key копии сохраняется как header.key.backup.");

            // --- Список + лог ---
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, SplitterDistance = 260 };

            _lv = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                GridLines = true, MultiSelect = false, HideSelection = false,
            };
            _lv.Columns.Add("Расположение", 150);
            _lv.Columns.Add("Контейнер", 360);
            _lv.Columns.Add("Детали", 320);
            Tip(_lv,
                "Найденные ключевые контейнеры.\n" +
                "«Расположение» = CSP (виден КриптоПро) или имя Рутокена (прочитан напрямую с токена).\n" +
                "Выделите строку — выбранный контейнер использует кнопка «Извлечь сертификат».");
            split.Panel1.Controls.Add(_lv);
            split.Panel1.Padding = new Padding(10, 0, 10, 0);

            _txtLog = new TextBox
            {
                Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
                ScrollBars = ScrollBars.Both, WordWrap = false,
                BackColor = Color.FromArgb(30, 30, 30), ForeColor = Color.Gainsboro,
                Font = new Font("Consolas", 9f),
            };
            Tip(_txtLog,
                "Журнал выполнения: команды p12utility, шаги работы с токеном и ошибки.\n" +
                "Текст можно выделить и скопировать (Ctrl+C) — пригодится при разборе проблем.");
            split.Panel2.Controls.Add(_txtLog);
            split.Panel2.Padding = new Padding(10, 0, 10, 10);

            Controls.Add(split);
            Controls.Add(buttons);
            Controls.Add(settings);
        }

        private Button MakeButton(string text, int width, EventHandler onClick)
        {
            var b = new Button { Text = text, Width = width, Height = 34, Margin = new Padding(0, 0, 8, 0) };
            b.Click += onClick;
            return b;
        }

        /// <summary>Всплывающая подсказка: что делает элемент, что для этого нужно и что получится.</summary>
        private void Tip(Control c, string text) => _tips.SetToolTip(c, text);

        /// <summary>
        /// Самопроверка для --selftest: у каждой кнопки, поля ввода и списка должна быть подсказка.
        /// Возвращает количество элементов с подсказкой и описания тех, у кого её нет.
        /// </summary>
        internal (int withTip, List<string> missing) CheckTooltips()
        {
            var missing = new List<string>();
            int withTip = 0;

            void Walk(Control root)
            {
                foreach (Control c in root.Controls)
                {
                    if (c is Button || c is TextBox || c is ListView)
                    {
                        if (string.IsNullOrWhiteSpace(_tips.GetToolTip(c)))
                            missing.Add($"{c.GetType().Name} \"{c.Text}\"");
                        else
                            withTip++;
                    }
                    Walk(c);
                }
            }

            Walk(this);
            return (withTip, missing);
        }

        // ---------- действия ----------

        private void RefreshList()
        {
            Invoke(() => _lv.Items.Clear());
            Log("Обновление списка контейнеров…");
            foreach (var c in CertFromContainer.EnumContainers())
                AddRow("CSP", c.Name, $"провайдер {c.ProvType}");

            try
            {
                var exp = new RutokenExporter { Log = Log };
                foreach (var c in exp.ReadAllContainers())
                    AddRow("Рутокен: " + c.TokenName, c.ContainerName ?? "(без имени)",
                           $"{c.TokenDir}, файлов: {c.Files.Count}");
            }
            catch (Exception e) { Log("Рутокены недоступны: " + e.Message); }
            Log("Готово.");
        }

        private void DoExport()
        {
            string dest = _txtDest.Text.Trim();
            if (string.IsNullOrEmpty(dest)) { Log("Укажите папку назначения."); return; }
            var pipe = new ExportPipeline(NullIfEmpty(_txtP12.Text)) { Log = Log };
            var saved = pipe.ExportFromTokens(dest, NullIfEmpty(_txtPin.Text));
            Log($"Снято контейнеров: {saved.Count}");
            Invoke(RefreshList);
        }

        private void DoExtract()
        {
            string container = SelectedContainerName();
            if (container == null) { Log("Выберите контейнер в списке."); return; }
            string dest = Path.Combine(_txtDest.Text.Trim(), "certs_" + Sanitize(container));
            var (ex, sg) = CertFromContainer.SaveCerts(container, dest);
            Log(ex != null ? "Сертификат обмена:  " + ex : "Сертификат обмена: нет");
            Log(sg != null ? "Сертификат подписи: " + sg : "Сертификат подписи: нет");
            if (ex == null && sg == null)
                Log("Не удалось извлечь. Убедитесь, что токен вставлен и контейнер виден CSP.");
        }

        private void DoFull()
        {
            string dest = _txtDest.Text.Trim();
            if (string.IsNullOrEmpty(dest)) { Log("Укажите папку назначения."); return; }
            var confirm = MessageBox.Show(this,
                "Будут сняты контейнеры со всех подключённых Рутокенов, извлечены сертификаты и снят запрет на экспорт ключей.\n\nПродолжить?",
                "Подтверждение", MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
            if (confirm != DialogResult.OK) { Log("Отменено пользователем."); return; }

            var pipe = new ExportPipeline(NullIfEmpty(_txtP12.Text)) { Log = Log };
            pipe.ExportAndMakeExportable(dest, userPin: NullIfEmpty(_txtPin.Text));
            Log("Полный цикл завершён.");
            Invoke(RefreshList);
        }

        // ---------- helpers ----------

        private void Run(Action work)
        {
            SetBusy(true);
            Task.Run(() =>
            {
                try { work(); }
                catch (Exception ex) { Log("ОШИБКА: " + ex.Message); }
                finally { SetBusy(false); }
            });
        }

        private void SetBusy(bool busy)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetBusy(busy))); return; }
            _btnRefresh.Enabled = _btnExport.Enabled = _btnExtract.Enabled = _btnFull.Enabled = !busy;
            Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
        }

        private void AddRow(string where, string name, string details)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddRow(where, name, details))); return; }
            _lv.Items.Add(new ListViewItem(new[] { where, name, details }));
        }

        private string SelectedContainerName()
        {
            if (InvokeRequired) return (string)Invoke(new Func<string>(SelectedContainerName));
            return _lv.SelectedItems.Count > 0 ? _lv.SelectedItems[0].SubItems[1].Text : null;
        }

        private void Log(string msg)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => Log(msg))); return; }
            _txtLog.AppendText(msg + Environment.NewLine);
        }

        private void PickFile(TextBox target, string filter)
        {
            using var d = new OpenFileDialog { Filter = filter };
            if (File.Exists(target.Text)) d.FileName = target.Text;
            if (d.ShowDialog(this) == DialogResult.OK) target.Text = d.FileName;
        }

        private void PickFolder(TextBox target)
        {
            using var d = new FolderBrowserDialog();
            if (Directory.Exists(target.Text)) d.SelectedPath = target.Text;
            if (d.ShowDialog(this) == DialogResult.OK) target.Text = d.SelectedPath;
        }

        private static string NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

        private static string Sanitize(string s)
        {
            foreach (char c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
            return s.Length > 40 ? s.Substring(0, 40) : s;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _tips?.Dispose();
            base.Dispose(disposing);
        }
    }
}
