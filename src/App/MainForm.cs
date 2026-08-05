using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
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
        private Button _btnRefresh, _btnExport, _btnExtract, _btnFull, _btnInstall, _btnCheck, _btnPfx, _btnLogs, _btnHelp;
        private Button _btnCancel;
        private Button[] _actionButtons;
        private ToolTip _tips;
        private ToolStripStatusLabel _status;
        private ToolStripProgressBar _progress;
        private CancellationTokenSource _cancellation;

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
            Run("Проверка зависимостей…", () =>
            {
                Log("Зависимости (скачивать и ставить ничего не нужно, кроме КриптоПро CSP):");
                foreach (var line in CryptoProExport.Diagnostics.Report())
                    Log("  " + line);
                Log("Журнал этого сеанса: " + SessionLog.FilePath);
                Log("");
            });
        }

        private void BuildUi()
        {
            Text = "Экспорт ключей КриптоПро с Рутокена";
            SetWindowIcon();
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
            var buttons = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = true, Padding = new Padding(10, 4, 10, 4),
            };
            _btnRefresh = MakeButton("Обновить список", 130, (_, __) => Run("Обновление списка контейнеров…", RefreshList));
            _btnExport = MakeButton("Экспорт с токена", 150, (_, __) => Run("Снятие контейнеров с токена…", DoExport));
            _btnExtract = MakeButton("Извлечь сертификат", 160, (_, __) => Run("Извлечение сертификата…", DoExtract));
            _btnFull = MakeButton("Сделать экспортируемым", 200, (_, __) => Run("Снятие запрета на экспорт…", DoFull));
            _btnFull.Font = new Font(Font, FontStyle.Bold);
            _btnCheck = MakeButton("Проверить ключ", 130, (_, __) => Run("Проверка прав ключа…", DoCheckExportable));
            _btnInstall = MakeButton("Установить в КриптоПро", 190, (_, __) => Run("Установка контейнера…", DoInstall));
            _btnPfx = MakeButton("Экспорт в PFX", 130, (_, __) => Run("Экспорт в PFX…", DoExportPfx));
            _btnLogs = MakeButton("Журнал", 90, (_, __) => OpenLogFolder());
            _btnHelp = MakeButton("Справка", 90, (_, __) => Guide.Show(this));
            _btnCancel = MakeButton("Отмена", 90, (_, __) => CancelCurrent());
            _btnCancel.Enabled = false;
            _actionButtons = new[]
            {
                _btnRefresh, _btnExport, _btnExtract, _btnFull,
                _btnCheck, _btnInstall, _btnPfx, _btnLogs, _btnHelp,
            };
            buttons.Controls.AddRange(_actionButtons);
            buttons.Controls.Add(_btnCancel);

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
            Tip(_btnCheck,
                "Проверить выбранный в списке контейнер: снят ли запрет на экспорт закрытого ключа.\n" +
                "Пробует выгрузить ключ (CryptExportKey) и сразу отпускает — сам ключ никуда не сохраняется.\n" +
                "Так проверяется, что «Сделать экспортируемым» действительно сработало.");
            Tip(_btnInstall,
                "Установить снятую с токена папку контейнера (6 файлов *.key) в КриптоПро —\n" +
                "скопировать её в хранилище CSP. После этого контейнер виден в списке и работает\n" +
                "без токена: из него можно извлечь сертификат и сделать экспорт в PFX.\n" +
                "Имя менять не обязательно: КриптоПро сверяет имя с содержимым контейнера и\n" +
                "переименованную копию принимает не всегда. Программа проверит результат и скажет,\n" +
                "увидел ли CSP контейнер на самом деле.");
            Tip(_btnCancel,
                "Прервать текущую операцию.\n" +
                "Работа остановится на ближайшем шаге: обращение к токену или запущенную\n" +
                "утилиту КриптоПро приходится сначала довести до конца — запущенная утилита\n" +
                "при этом снимается. Уже сохранённые файлы остаются на месте.");
            Tip(_btnHelp,
                "Встроенное руководство: с чего начать, что делает каждая кнопка,\n" +
                "команды консольного режима и разбор типичных ошибок.\n" +
                "Лежит внутри программы — интернет и сторонние файлы не нужны.");
            Tip(_btnLogs,
                "Открыть папку с журналами работы программы.\n" +
                "Каждый запуск пишет отдельный файл — его удобно приложить к вопросу,\n" +
                "если что-то не получилось. Пароли в журнал не попадают.");
            Tip(_btnPfx,
                "Выгрузить выбранный в списке контейнер в файл PKCS#12 (.pfx) — сертификат вместе\n" +
                "с закрытым ключом, для переноса в другую систему.\n" +
                "Требуется: запрет на экспорт уже снят («Проверить ключ» показывает «экспортируемый»)\n" +
                "и установлен КриптоПро CSP (используется его certmgr).\n" +
                "Пароль на .pfx программа спросит отдельно.");

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

            // --- Строка состояния: что идёт прямо сейчас ---
            _status = new ToolStripStatusLabel("Готово") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = 140 };
            var statusStrip = new StatusStrip { SizingGrip = false };
            statusStrip.Items.AddRange(new ToolStripItem[] { _status, _progress });

            Controls.Add(split);
            Controls.Add(buttons);
            Controls.Add(settings);
            Controls.Add(statusStrip);
        }

        /// <summary>Иконка окна и панели задач — та же, что у exe, из вшитого ресурса (все размеры).</summary>
        private void SetWindowIcon()
        {
            try
            {
                using var stream = typeof(MainForm).Assembly.GetManifestResourceStream("CryptoProExport.App.app.ico");
                if (stream != null) Icon = new Icon(stream);
            }
            catch (ArgumentException) { }
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

        private void RefreshList(CancellationToken cancel = default)
        {
            Invoke(() => _lv.Items.Clear());
            Log("Обновление списка контейнеров…");
            foreach (var c in CertFromContainer.EnumContainers())
                AddRow("CSP", c.Name, $"провайдер {c.ProvType}");

            cancel.ThrowIfCancellationRequested();
            try
            {
                var exp = new RutokenExporter { Log = Log, Cancel = cancel };
                foreach (var c in exp.ReadAllContainers())
                    AddRow("Рутокен: " + c.TokenName, c.ContainerName ?? "(без имени)",
                           $"{c.TokenDir}, файлов: {c.Files.Count}");
            }
            catch (Exception e) { Log("Рутокены недоступны: " + e.Message); }
            Log("Готово.");
        }

        private void DoExport(CancellationToken cancel)
        {
            string dest = _txtDest.Text.Trim();
            if (string.IsNullOrEmpty(dest)) { Log("Укажите папку назначения."); return; }
            var pipe = new ExportPipeline(NullIfEmpty(_txtP12.Text)) { Log = Log, Cancel = cancel };
            var saved = pipe.ExportFromTokens(dest, NullIfEmpty(_txtPin.Text));
            Log($"Снято контейнеров: {saved.Count}");
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoExtract()
        {
            string container = SelectedContainerName();
            if (container == null) { Log("Выберите контейнер в списке."); return; }
            string destRoot = _txtDest.Text.Trim();
            if (string.IsNullOrEmpty(destRoot)) { Log("Укажите папку назначения."); return; }
            string dest = Path.Combine(destRoot, "certs_" + Sanitize(container));
            var (ex, sg) = CertFromContainer.SaveCerts(container, dest);
            Log(ex != null ? "Сертификат обмена:  " + ex : "Сертификат обмена: нет");
            Log(sg != null ? "Сертификат подписи: " + sg : "Сертификат подписи: нет");
            if (ex == null && sg == null)
                Log("Не удалось извлечь. Убедитесь, что токен вставлен и контейнер виден CSP.");
        }

        private void DoFull(CancellationToken cancel)
        {
            string dest = _txtDest.Text.Trim();
            if (string.IsNullOrEmpty(dest)) { Log("Укажите папку назначения."); return; }
            var confirm = AskConfirm(
                "Будут сняты контейнеры со всех подключённых Рутокенов, извлечены сертификаты и снят запрет на экспорт ключей.\n\nПродолжить?",
                "Подтверждение");
            if (confirm != DialogResult.OK) { Log("Отменено пользователем."); return; }

            var pipe = new ExportPipeline(NullIfEmpty(_txtP12.Text)) { Log = Log, Cancel = cancel };
            pipe.ExportAndMakeExportable(dest, userPin: NullIfEmpty(_txtPin.Text));
            Log("Полный цикл завершён.");
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoCheckExportable()
        {
            string container = SelectedContainerName();
            if (container == null) { Log("Выберите контейнер в списке."); return; }
            var ex = CertFromContainer.CheckExportable(container, CertFromContainer.AT_KEYEXCHANGE);
            var sg = CertFromContainer.CheckExportable(container, CertFromContainer.AT_SIGNATURE);
            Log($"Контейнер \"{container}\":");
            Log($"  ключ обмена:  {ex}");
            Log($"  ключ подписи: {sg}");
        }

        private void DoInstall()
        {
            string folder = AskFolder("Папка со снятым контейнером (6 файлов *.key)", _txtDest.Text.Trim());
            if (folder == null) { Log("Отменено."); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                Log("В выбранной папке нет контейнера (нужны header.key, primary.key, masks.key).");
                return;
            }

            string current = ContainerStore.ReadName(folder)
                             ?? Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar));

            string name = AskText("Установка контейнера в КриптоПро",
                "Имя, под которым контейнер появится в списке КриптоПро.\n" +
                "Менять не обязательно: переименование копии CSP принимает не всегда.",
                current, password: false);
            if (name == null) { Log("Отменено."); return; }
            name = name.Trim();

            var installed = ContainerStore.Install(folder, name == current ? null : name);
            Log("Контейнер установлен: " + installed);
            if (name != current && !installed.Renamed)
                Log($"Имя оставлено прежним (\"{installed.Name}\"): КриптоПро не принял копию с новым именем. " +
                    "Так бывает, пока с контейнера не снят запрет на экспорт.");
            if (installed.Verified && !installed.VisibleToCsp)
                Log("КриптоПро пока не видит контейнер — нажмите «Обновить список» ещё раз " +
                    "или перезайдите в систему: CSP кэширует перечень контейнеров.");
            RefreshList();
        }

        private void DoExportPfx(CancellationToken cancel)
        {
            string container = SelectedContainerName();
            if (container == null) { Log("Выберите контейнер в списке."); return; }

            string exe = CertMgr.Locate();
            if (exe == null) { Log("certmgr не найден — нужен установленный КриптоПро CSP."); return; }

            string dest = AskSaveFile("Куда сохранить PFX", "PKCS#12 (*.pfx)|*.pfx|Все файлы|*.*",
                                      _txtDest.Text.Trim(), Sanitize(container) + ".pfx");
            if (dest == null) { Log("Отменено."); return; }

            string pass = AskText("Пароль PFX",
                "Пароль на файл .pfx (можно оставить пустым — тогда файл будет без пароля):",
                "", password: true);
            if (pass == null) { Log("Отменено."); return; }

            var cm = new CertMgr(exe) { Log = Log, Cancel = cancel };
            var r = cm.ExportContainerToPfx(container, dest, pass);
            Log(r.Success ? "PFX готов: " + dest : "Не удалось выгрузить PFX: " + r.Output);
        }

        private void OpenLogFolder()
        {
            try
            {
                Directory.CreateDirectory(SessionLog.Dir);
                Process.Start(new ProcessStartInfo(SessionLog.Dir) { UseShellExecute = true });
            }
            catch (Exception ex) { Log("Не удалось открыть папку журналов: " + ex.Message); }
        }

        // ---------- helpers ----------

        /// <summary>
        /// Модальный вопрос из рабочего потока. Диалоги WinForms обязаны жить на потоке окна:
        /// MessageBox с чужим владельцем ведёт себя непредсказуемо.
        /// </summary>
        private DialogResult AskConfirm(string text, string caption)
        {
            if (InvokeRequired) return (DialogResult)Invoke(new Func<DialogResult>(() => AskConfirm(text, caption)));
            return MessageBox.Show(this, text, caption, MessageBoxButtons.OKCancel, MessageBoxIcon.Question);
        }

        private string AskFolder(string description, string initial)
        {
            if (InvokeRequired) return (string)Invoke(new Func<string>(() => AskFolder(description, initial)));
            using var d = new FolderBrowserDialog { Description = description, UseDescriptionForTitle = true };
            if (Directory.Exists(initial)) d.SelectedPath = initial;
            return d.ShowDialog(this) == DialogResult.OK ? d.SelectedPath : null;
        }

        private string AskSaveFile(string title, string filter, string initialDir, string suggestedName)
        {
            if (InvokeRequired)
                return (string)Invoke(new Func<string>(() => AskSaveFile(title, filter, initialDir, suggestedName)));
            using var d = new SaveFileDialog
            {
                Title = title, Filter = filter, FileName = suggestedName,
                AddExtension = true, DefaultExt = "pfx", OverwritePrompt = true,
            };
            if (Directory.Exists(initialDir)) d.InitialDirectory = initialDir;
            return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
        }

        private string AskText(string title, string prompt, string initial, bool password)
        {
            if (InvokeRequired)
                return (string)Invoke(new Func<string>(() => AskText(title, prompt, initial, password)));
            return PromptDialog.Ask(this, title, prompt, initial, password);
        }

        /// <summary>Запустить длинную операцию в фоне: с подписью в строке состояния и возможностью отмены.</summary>
        private void Run(string title, Action<CancellationToken> work)
        {
            var cancellation = new CancellationTokenSource();
            _cancellation = cancellation;
            SetBusy(true, title);
            Task.Run(() =>
            {
                try { work(cancellation.Token); }
                catch (OperationCanceledException) { Log("Операция отменена."); }
                catch (Exception ex) { Log("ОШИБКА: " + ex.Message); }
                finally
                {
                    _cancellation = null;
                    cancellation.Dispose();
                    SetBusy(false, null);
                }
            });
        }

        /// <summary>Действия, которым отмена не нужна (всё быстрое), запускаются так же — просто игнорируют токен.</summary>
        private void Run(string title, Action work) => Run(title, _ => work());

        private void CancelCurrent()
        {
            var cancellation = _cancellation;
            if (cancellation == null || cancellation.IsCancellationRequested) return;
            Log("Отмена запрошена — операция прервётся на ближайшем шаге.");
            SetStatus("Отмена…");
            try { cancellation.Cancel(); } catch (ObjectDisposedException) { }
        }

        private void SetBusy(bool busy, string title)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetBusy(busy, title))); return; }
            foreach (var b in _actionButtons) b.Enabled = !busy;
            _btnCancel.Enabled = busy;
            _progress.Visible = busy;
            _status.Text = busy ? title : "Готово";
            Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
        }

        private void SetStatus(string text)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetStatus(text))); return; }
            _status.Text = text;
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
            SessionLog.Write(msg);
            AppendLog(msg);
        }

        private void AppendLog(string msg)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AppendLog(msg))); return; }
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
