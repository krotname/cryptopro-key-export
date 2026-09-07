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
    ///   • Экспорт с токена — снять файловый контейнер S/Lite (не аппаратный ключ ЭЦП);
    ///   • Извлечь .cer — вытащить сертификат из контейнера (CryptoAPI);
    ///   • Сделать экспортируемым — полный цикл: снять + авто-.cer + p12utility --keyexport.
    ///
    /// Все надписи берутся из <see cref="Strings"/> и переставляются на лету
    /// (<see cref="ApplyTexts"/>), поэтому язык можно сменить прямо в окне.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class MainForm : Form
    {
        private TextBox _txtPin, _txtLog, _txtFind;
        /// <summary>
        /// Папка назначения. Поля в окне у неё больше нет (ROADMAP, P2, п. 8): она нужна только
        /// в момент экспорта, там её и спрашивают, а выбор запоминается на сессию.
        /// </summary>
        private string _dest;
        private Button _btnPinReveal;
        /// <summary>Последнее подставленное программой значение PIN — чтобы отличать его от введённого.</summary>
        private string _autoFilledPin;
        /// <summary>Модель, чьё заводское значение подставлено, — для подсказки на текущем языке.</summary>
        private string _autoFilledModel;
        private ListView _lv;
        /// <summary>Объяснение пустого списка поверх него самого; null-ключ — скрыт.</summary>
        private Label _lblEmpty;
        private string _emptyHintKey;
        /// <summary>Идёт пересчёт высоты полосы — чтобы присвоение высоты не вызвало его снова.</summary>
        private bool _sizingHint;
        private SplitContainer _split;
        private ColumnHeader _colWhere, _colBackend, _colName, _colDetails;
        /// <summary>Колонка, по которой отсортирован список; -1 — исходный порядок обхода.</summary>
        private int _sortColumn = -1;
        private bool _sortDesc;
        /// <summary>Номер строки в порядке обхода — по нему список возвращается к исходному виду.</summary>
        private int _rowSeq;
        private Label _lblPin, _lblPinHint, _lblFind;
        private Button _btnRefresh, _btnExport, _btnExtract, _btnFull, _btnInstall, _btnView, _btnPfx, _btnExtractKey, _btnLicense, _btnLogs, _btnHelp;
        private Button _btnCancel;
        /// <summary>Переключатель нижней панели журнала: по умолчанию она свёрнута.</summary>
        private Button _btnLogPane;
        /// <summary>Фильтр видимого журнала; файл сеанса при этом сохраняет все уровни.</summary>
        private Button _btnLogLevel;
        private LogLevel _minimumLogLevel = LogLevel.Information;
        private readonly List<(LogLevel Level, string Message)> _logEntries = new();
        /// <summary>Высота списка при развёрнутом журнале — чтобы вернуть её, а не половину окна.</summary>
        private int _logSplit;
        private Button[] _actionButtons;
        /// <summary>Кнопки, доступность которых зависит от выделенной строки, и их действия.</summary>
        private (Button Button, RowAction Action)[] _rowButtons;
        /// <summary>
        /// Подсказка кнопки без причины отказа. Причина приписывается к ней на лету, поэтому
        /// исходный текст нужно помнить: иначе повторное обновление приписало бы вторую причину
        /// к первой, а смена языка оставила бы прежнюю.
        /// </summary>
        private readonly Dictionary<Button, string> _baseTips = new();
        /// <summary>Лента кнопок целиком — по ней считается ширина окна, при которой группы не рвутся.</summary>
        private FlowLayoutPanel _buttons;
        /// <summary>Группы кнопок: подпись, её ключ перевода и состав. Подписи расставляет <see cref="ApplyTexts"/>.</summary>
        private (Label Caption, string Key, Button[] Buttons)[] _buttonGroups;
        /// <summary>Выключенная кнопка, чью подсказку показали вручную (см. <see cref="ShowDisabledTip"/>).</summary>
        private Button _disabledTipOn;
        /// <summary>Кнопка выбора языка: список из постоянной панели переехал в диалог.</summary>
        private Button _btnLang;
        /// <summary>Все строки обхода. В списке видны те, что подходят под поиск.</summary>
        private readonly List<ListViewItem> _allRows = new();
        private ToolTip _tips;
        private ToolStripStatusLabel _status;
        /// <summary>Последняя строка журнала в строке состояния — то, что видно вместо свёрнутой панели.</summary>
        private ToolStripStatusLabel _lastLog;
        private ToolStripProgressBar _progress;
        private CancellationTokenSource _cancellation;
        private bool _busy;

        /// <summary>
        /// Обновлять список сразу при показе окна. Выключается только в <c>--selftest</c>
        /// (<see cref="Program"/>): там форма закрывается сразу после показа, и фоновая задача
        /// иначе может обратиться к уже уничтоженным элементам управления.
        /// </summary>
        [System.ComponentModel.Browsable(false)]
        [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
        public bool AutoRefreshOnShow { get; set; } = true;

        private sealed class TokenCertificateSelection
        {
            public string Name;
            public string Serial;
            public byte[] Certificate;
            /// <summary>
            /// Сертификат-сирота без парного объекта контейнера (AGENTS п. 30). Имя такой
            /// строки — метка сертификата, а не контейнера: отдавать его CryptoAPI или
            /// certmgr нельзя, они разрешили бы его в посторонний одноимённый контейнер CSP.
            /// </summary>
            public bool CertificateOnly;
        }

        private sealed class ApduContainerSelection
        {
            public Pkcs11TokenInfo Token;
            public DirectTokenContainerRef Container;
        }

        private sealed class TokenDeviceSelection { }
        private sealed class CspContainerSelection
        {
            public string Target;
        }

        private sealed class ContainerSelection
        {
            public string Name;
            public string Target;
            public string Location;
            /// <summary>Способ чтения строки: CSP, PKCS#11, APDU, PC/SC, rtCOMLite.</summary>
            public string Backend;
            public string Details;
            public bool IsCsp;
            public TokenCertificateSelection Token;
            public ApduContainerSelection Apdu;
            public RutokenContainer Direct;
        }

        public MainForm()
        {
            _dest = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "RutokenExport");
            BuildUi();
            ApplyTexts();
        }


        /// <summary>
        /// После показа окна — сводка по зависимостям в лог (что вшито, чего не хватает), а следом
        /// сразу список носителей: раньше список был пуст, пока не нажата «Обновить», и это было
        /// первым действием почти каждого запуска. Один <see cref="Run"/> на оба шага — иначе два
        /// параллельных фоновых прогона делят одно поле <see cref="_busy"/> и путают статус-строку.
        /// </summary>
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            // Окно уже размещено — только теперь известно, на каком мониторе оно оказалось и
            // сколько места там есть на самом деле. Если ширину пришлось добавить, окно снова
            // центрируем по горизонтали на этом же мониторе: прирост вправо от центрированного
            // окна выглядел бы сдвигом.
            if (FitButtonGroups() && StartPosition == FormStartPosition.CenterScreen)
            {
                Rectangle area = Screen.FromControl(this).WorkingArea;
                Left = Math.Max(area.Left, area.Left + (area.Width - Width) / 2);
            }

            Run("status.deps", cancel =>
            {
                LogDebug(Strings.Get("log.deps.header"));
                foreach (var line in CryptoProExport.Diagnostics.Report())
                    LogDebug("  " + line);
                Log(Strings.Format("log.session", SessionLog.FilePath));
                Log(LicenseGate.StatusText());
                // Отпечаток нужен, чтобы получить лицензию, — обещан в подсказке и README, показываем сразу.
                Log(LicenseGate.FingerprintText());
                Log("");
                if (!AutoRefreshOnShow) return;
                SetStatus(Strings.Get("status.refresh"));
                RefreshList(cancel);
            });
        }

        private void BuildUi()
        {
            SetWindowIcon();
            Font = new Font("Segoe UI", 9f);
            ClientSize = new Size(880, 660);
            MinimumSize = new Size(720, 540);
            StartPosition = FormStartPosition.CenterScreen;
            // F5 = «Обновить» из любого места окна, как в проводнике.
            KeyPreview = true;
            KeyDown += (_, e) =>
            {
                if (e.KeyCode != Keys.F5 || !_btnRefresh.Enabled) return;
                e.Handled = true;
                _btnRefresh.PerformClick();
            };

            // Всплывающие подсказки: держим долго открытыми — тексты многострочные и объясняют шаг целиком
            _tips = new ToolTip
            {
                AutoPopDelay = 30000, InitialDelay = 300, ReshowDelay = 100,
                ShowAlways = true, UseAnimation = false, UseFading = false,
            };

            // --- Панель настроек ---
            // Ширины колонок и высота панели считаются по содержимому: переводы длиннее
            // русского оригинала, и жёсткие размеры обрезали бы надписи.
            var settings = new TableLayoutPanel
            {
                Dock = DockStyle.Top, ColumnCount = 3, RowCount = 1,
                Padding = new Padding(10, 10, 10, 4),
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            };
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            // PIN виден по умолчанию: он вводится с клавиатуры за своим столом, а вслепую
            // владелец чаще ошибается — а ошибка здесь стоит попытки носителя. Скрыть можно
            // кнопкой рядом, когда рядом кто-то есть.
            _txtPin = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = false, Margin = new Padding(3, 4, 3, 4) };
            // Правка поля отменяет подстановку: дальше это уже введённый пользователем PIN,
            // и подпись не должна называть его заводским значением модели.
            _txtPin.TextChanged += (_, _) =>
            {
                if (_autoFilledPin == null || _txtPin.Text == _autoFilledPin) return;
                _autoFilledPin = null;
                _autoFilledModel = null;
                if (_lblPinHint != null) _lblPinHint.Text = PinHintText();
            };

            // В постоянной панели осталась одна строка — PIN. Поля пути к p12utility тут не было
            // и раньше (копия вшита), а «Папка назначения» и «Язык интерфейса» уехали туда, где
            // они нужны (ROADMAP, P2, п. 8): папку спрашивает сам экспорт, язык — кнопка «Язык…»
            // в служебной группе. Обе строки занимали место всегда, а требовались по разу.
            _lblPin = MakeFieldLabel();
            settings.Controls.Add(_lblPin, 0, 0);
            // Кнопка живёт в одной ячейке с полем: третья колонка занята подсказкой о PIN.
            var pinCell = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Margin = new Padding(0),
            };
            pinCell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pinCell.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            _btnPinReveal = new Button
            {
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill, Margin = new Padding(0, 4, 3, 4),
            };
            _btnPinReveal.Click += (_, __) =>
            {
                _txtPin.UseSystemPasswordChar = !_txtPin.UseSystemPasswordChar;
                ApplyPinRevealState();
            };
            pinCell.Controls.Add(_txtPin, 0, 0);
            pinCell.Controls.Add(_btnPinReveal, 1, 0);
            settings.Controls.Add(pinCell, 1, 0);
            _lblPinHint = MakeFieldLabel();
            _lblPinHint.ForeColor = Color.Gray;
            settings.Controls.Add(_lblPinHint, 2, 0);

            // --- Панель кнопок: четыре группы по смыслу ---
            // Сплошная лента из тринадцати кнопок не показывала порядок работы (ROADMAP, P2, п. 3):
            // рядом стояли шаг конвейера, выгрузка результата и «Справка». Теперь каждая группа
            // начинается со своей подписи и с новой строки: список → шаги → результат → служебное.
            // Панель осталась одна: вложенные AutoSize-контейнеры (TableLayoutPanel с
            // FlowLayoutPanel внутри) зацикливают раскладку — окно строится бесконечно, --selftest
            // не завершается. Перенос делает SetFlowBreak на последней кнопке группы, а внутри
            // группы кнопки по-прежнему текут: переводы длиннее русского оригинала.
            var buttons = _buttons = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = true, Padding = new Padding(10, 4, 10, 4),
            };
            _btnRefresh = MakeButton((_, __) => Run("status.refresh", RefreshList));
            _btnExport = MakeButton((_, __) => Run("status.export", DoExport));
            _btnExtract = MakeButton((_, __) => Run("status.extract", DoExtract));
            _btnFull = MakeButton((_, __) => Run("status.full", DoFull));
            _btnFull.Font = new Font(Font, FontStyle.Bold);
            _btnView = MakeButton((_, __) => Run("status.check", DoViewContainer));
            _btnInstall = MakeButton((_, __) => Run("status.install", DoInstall));
            // Одна кнопка на оба .pfx: сами файлы разные, и выбор делается в диалоге, где
            // разница написана рядом с вариантами (ROADMAP, P2, п. 4). Двумя соседними кнопками
            // она объяснялась только подсказкой, а замечали её уже после экспорта.
            _btnPfx = MakeButton((_, __) => DoPfxChoice());
            _btnExtractKey = MakeButton((_, __) => Run("status.extractkey", DoExtractKey));
            _btnLicense = MakeButton((_, __) => DoLicense());
            _btnLogs = MakeButton((_, __) => OpenLogFolder());
            // Панель журнала свёрнута по умолчанию (ROADMAP, P2, п. 5), поэтому её переключатель
            // стоит рядом с кнопкой, открывающей папку журналов: обе про одно и то же, но одна
            // разворачивает текст в этом окне, а вторая ведёт к файлам прошлых запусков.
            _btnLogPane = MakeButton((_, __) => ToggleLogPane());
            _btnLogLevel = MakeButton((_, __) => CycleLogLevel());
            _btnLang = MakeButton((_, __) => PickLanguage());
            _btnHelp = MakeButton((_, __) => Guide.Show(this));
            _btnCancel = MakeButton((_, __) => CancelCurrent());
            _btnCancel.Enabled = false;
            // Отмена относится не к группе, а к тому, что идёт прямо сейчас. Она стоит последней
            // в служебном ряду, но с отбивкой слева — чтобы не читалась как ещё одно служебное
            // действие рядом со «Справкой».
            _btnCancel.Margin = new Padding(24, 0, 8, 4);
            _actionButtons = new[]
            {
                _btnRefresh, _btnExport, _btnExtract, _btnFull,
                _btnView, _btnInstall, _btnPfx, _btnExtractKey, _btnLicense, _btnLogs,
                _btnLang, _btnHelp,
            };
            // «Показать журнал» и фильтр уровня занятостью не гасятся: развернуть журнал или
            // включить диагностику нужнее всего как раз во время долгой операции.
            // Остальные кнопки к выделению безразличны: «Обновить» перечитывает весь список,
            // «Установить» и «Извлечь ключ» спрашивают папку диалогом, «Сохранить в PFX»
            // проверяет строку уже в своём диалоге (там же пишет причину отказа), а
            // «Лицензия», управление журналом и «Справка» к носителям вообще не обращаются.
            _rowButtons = new[]
            {
                (_btnExport, RowAction.Export),
                (_btnFull, RowAction.MakeExportable),
                (_btnExtract, RowAction.ExtractCert),
                (_btnView, RowAction.ViewContainer),
            };
            // Порядок групп — порядок работы: сначала найти носитель и посмотреть контейнер,
            // потом шаги снятия, потом файл-результат, и лишь затем служебное.
            _buttonGroups = new[]
            {
                AddButtonRow(buttons, "group.list", _btnRefresh, _btnView),
                AddButtonRow(buttons, "group.steps", _btnExport, _btnExtract, _btnFull, _btnInstall),
                AddButtonRow(buttons, "group.result", _btnPfx, _btnExtractKey),
                AddButtonRow(buttons, "group.service",
                             _btnLicense, _btnLogPane, _btnLogLevel, _btnLogs, _btnLang, _btnHelp, _btnCancel),
            };
            // Подсказка выключенной кнопки: Windows не шлёт мыши сообщения выключенному окну,
            // поэтому ToolTip сам её не покажет — а причина отказа нужна именно там. Сообщения
            // выключенного ребёнка достаются родителю, по ним и показываем подсказку вручную.
            buttons.MouseMove += (_, e) => ShowDisabledTip(buttons, e.Location);
            buttons.MouseLeave += (_, __) => ShowDisabledTip(buttons, new Point(-1, -1));

            // --- Список + лог ---
            // Журнал свёрнут по умолчанию (ROADMAP, P2, п. 5): он занимал половину окна всегда,
            // хотя в норме нужны только последняя строка (она уходит в строку состояния) и само
            // состояние. Полный текст никуда не делся — его разворачивает «Показать журнал».
            // SplitterDistance выставляется в момент разворота: до раскладки высота панели ещё
            // не известна, и значение, заданное здесь, WinForms молча обрезает по факту.
            var split = _split = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, Panel2Collapsed = true,
            };

            _lv = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                GridLines = true, MultiSelect = false, HideSelection = false,
            };
            // «Расположение» держало сразу два разных сведения — устройство и способ чтения
            // («[PKCS#11] Aktiv Rutoken ECP 00 00 [Рутокен ЭЦП]»). Сортировать по ним было
            // нельзя, а именно этого от списка и хочется (ROADMAP, P2, п. 6). Теперь это две
            // колонки: где носитель и чем строка прочитана.
            // Ширины подобраны по фактическому содержимому на машине владельца: имя
            // считывателя с семейством («Aktiv Rutoken ECP 0 [Рутокен ЭЦП]») длиннее прежней
            // колонки, а «Способ чтения» должен вмещать и свой заголовок, и отметку сортировки.
            _colWhere = new ColumnHeader { Width = 280 };
            _colBackend = new ColumnHeader { Width = 160 };
            _colName = new ColumnHeader { Width = 300 };
            _colDetails = new ColumnHeader { Width = 280 };
            _lv.Columns.AddRange(new[] { _colWhere, _colBackend, _colName, _colDetails });
            _lv.ColumnClick += (_, e) => SortByColumn(e.Column);
            // Двойной клик по строке — то же самое, что кнопка «Посмотреть контейнер»:
            // самый частый следующий шаг после того, как строка найдена в списке.
            _lv.MouseDoubleClick += (_, __) =>
            {
                if (_lv.SelectedItems.Count > 0 && _btnView.Enabled) _btnView.PerformClick();
            };
            // Половина действий работает не с каждой строкой. Что именно доступно сейчас, видно
            // по самим кнопкам, а не по сообщению в журнале после нажатия.
            _lv.SelectedIndexChanged += (_, __) => UpdateRowActions();
            split.Panel1.Controls.Add(_lv);
            // Пустой список раньше не объяснял себя ничем: причина уходила только в журнал,
            // а журнал теперь свёрнут (ROADMAP, P2, п. 7). Подпись перекрывает список целиком
            // и появляется, только когда показывать в нём нечего.
            _lblEmpty = new Label
            {
                Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter,
                AutoSize = false, ForeColor = Color.Gray, Visible = false,
                BackColor = SystemColors.Control, Padding = new Padding(16, 10, 16, 10),
            };
            // Поиск по списку: личных контейнеров у владельца больше пяти, и глазами искать
            // строку дольше, чем набрать три буквы (ROADMAP, P2, п. 8). Фильтр только прячет
            // строки — сам обход и его порядок не меняются.
            var find = new TableLayoutPanel
            {
                Dock = DockStyle.Top, ColumnCount = 2, RowCount = 1,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(0, 0, 0, 4),
            };
            find.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            find.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            _lblFind = MakeFieldLabel();
            _txtFind = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(3, 4, 3, 4) };
            _txtFind.TextChanged += (_, __) => ApplyFilter();
            find.Controls.Add(_lblFind, 0, 0);
            find.Controls.Add(_txtFind, 1, 0);

            split.Panel1.Controls.Add(_lblEmpty);
            // SendToBack, а не BringToFront: WinForms раскладывает пристыкованных детей от
            // последнего к первому, поэтому Dock=Fill списка должен разбираться последним —
            // иначе полоса просто легла бы поверх нижних строк, не подвинув их.
            _lblEmpty.SendToBack();
            // Ширина полосы меняется вместе с окном, а с ней и число строк переноса.
            split.Panel1.ClientSizeChanged += (_, __) => SizeEmptyHint();
            split.Panel1.Controls.Add(find);
            split.Panel1.Padding = new Padding(10, 0, 10, 0);

            _txtLog = new TextBox
            {
                Dock = DockStyle.Fill, Multiline = true, ReadOnly = true,
                ScrollBars = ScrollBars.Both, WordWrap = false,
                BackColor = Color.FromArgb(30, 30, 30), ForeColor = Color.Gainsboro,
                Font = new Font("Consolas", 9f),
            };
            split.Panel2.Controls.Add(_txtLog);
            split.Panel2.Padding = new Padding(10, 0, 10, 10);

            // --- Строка состояния: что идёт прямо сейчас ---
            // Состояние и последняя строка журнала стоят рядом и в покое читаются похоже
            // («Готово» и «Готово.»), поэтому между ними разделитель: это два разных поля.
            _status = new ToolStripStatusLabel
            {
                TextAlign = ContentAlignment.MiddleLeft,
                BorderSides = ToolStripStatusLabelBorderSides.Right,
                BorderStyle = Border3DStyle.Etched,
            };
            // Последняя строка журнала рядом с состоянием: со свёрнутой панелью это всё, что
            // нужно в норме, — что идёт сейчас и чем закончился предыдущий шаг.
            _lastLog = new ToolStripStatusLabel
            {
                Spring = true, TextAlign = ContentAlignment.MiddleLeft, ForeColor = Color.Gray,
                AutoToolTip = false,
            };
            _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = 140 };
            var statusStrip = new StatusStrip { SizingGrip = false };
            statusStrip.Items.AddRange(new ToolStripItem[] { _status, _lastLog, _progress });

            Controls.Add(split);
            Controls.Add(buttons);
            Controls.Add(settings);
            Controls.Add(statusStrip);
        }

        /// <summary>
        /// Расставить все надписи и подсказки по действующему языку. Вызывается из конструктора
        /// и при смене языка — второй раз по тем же ссылкам на элементы.
        /// </summary>
        private void ApplyTexts()
        {
            Text = Strings.Get("app.title");

            // Арабский, урду и фарси пишутся справа налево: без зеркальной раскладки
            // подписи и поля разъезжаются в разные стороны.
            bool rtl = Strings.CurrentIsRightToLeft;
            RightToLeft = rtl ? RightToLeft.Yes : RightToLeft.No;
            RightToLeftLayout = rtl;

            _lblPin.Text = Strings.Get("field.pin");
            _lblPinHint.Text = PinHintText();
            ApplyPinRevealState();
            _lblFind.Text = Strings.Get("field.find");

            Tip(_lblPin, "tip.pin"); Tip(_txtPin, "tip.pin"); Tip(_lblPinHint, "tip.pin");
            Tip(_lblFind, "tip.find"); Tip(_txtFind, "tip.find");

            // Подписи групп выравниваются по самой длинной из них: иначе кнопки начинались бы
            // с разного отступа и колонка групп читалась бы хуже сплошной ленты. MinimumSize,
            // а не фиксированная ширина: подпись всё так же меряется по своему тексту, а на
            // смене языка запас пересчитывается заново (в другом языке длиннее другая строка).
            int captions = 0;
            foreach (var (label, key, _) in _buttonGroups)
            {
                label.MinimumSize = Size.Empty;
                label.Text = Strings.Get(key);
                captions = Math.Max(captions, label.PreferredWidth);
            }
            foreach (var (label, _, _) in _buttonGroups) label.MinimumSize = new Size(captions, 0);

            SetButton(_btnRefresh, "btn.refresh", "tip.refresh");
            // Автообновление и F5 подсказаны отдельным ключом, только по-русски (AGENTS п. 17):
            // добавлять их дублем текста в двадцать уже переведённых подсказок не стали.
            _tips.SetToolTip(_btnRefresh, _tips.GetToolTip(_btnRefresh) + "\n\n" + Strings.Get("tip.refresh.auto"));
            SetButton(_btnExport, "btn.export", "tip.export");
            SetButton(_btnExtract, "btn.extract", "tip.extract");
            SetButton(_btnFull, "btn.full", "tip.full");
            SetButton(_btnView, "btn.check", "tip.check");
            SetButton(_btnInstall, "btn.install", "tip.install");
            SetButton(_btnPfx, "btn.pfx.choice", "tip.pfx.choice");
            SetButton(_btnExtractKey, "btn.extractkey", "tip.extractkey");
            SetButton(_btnLicense, "btn.license", "tip.license");
            SetButton(_btnLogs, "btn.logs", "tip.logs");
            // Надпись переключателя зависит от текущего состояния панели, поэтому её ставит
            // ApplyLogPaneState — и здесь, и на каждом нажатии.
            ApplyLogPaneState();
            ApplyLogLevelState(rebuild: false);
            SetButton(_btnLang, "btn.lang", "tip.lang");
            SetButton(_btnHelp, "btn.help", "tip.help");
            SetButton(_btnCancel, "btn.cancel", "tip.cancel");

            // Общие названия кнопок исторически говорят «с токена». Явно добавляем границу
            // аппаратного ЭЦП прямо в обе подсказки на каждом из 20 языков.
            string ecpBoundary = "\n\n" + Strings.Get("token.boundary.ecp");
            _tips.SetToolTip(_btnExport, _tips.GetToolTip(_btnExport) + ecpBoundary);
            _tips.SetToolTip(_btnFull, _tips.GetToolTip(_btnFull) + ecpBoundary);

            ApplyColumnHeaders();
            ApplyEmptyHint();
            Tip(_lv, "tip.list");
            _tips.SetToolTip(_lv, _tips.GetToolTip(_lv) + "\n\n" + Strings.Get("tip.list.dblclick")
                                  + "\n\n" + Strings.Get("tip.list.columns"));
            Tip(_txtLog, "tip.log");

            // Запоминаем подсказки в готовом виде (вместе с приписками про ЭЦП) и заново
            // приписываем причину отказа: после смены языка она должна быть на новом языке.
            foreach (var (button, _) in _rowButtons) _baseTips[button] = _tips.GetToolTip(button);
            UpdateRowActions();

            // Надписи кнопок только что сменились — ширина групп вместе с ними.
            FitButtonGroups();

            if (!_busy) _status.Text = Strings.Get("status.ready");
            ShowLastLogLine();
        }

        /// <summary>
        /// Спросить язык интерфейса. Список уехал из постоянной панели в диалог: выбирают его
        /// один раз, а место он занимал всегда (ROADMAP, P2, п. 8).
        /// </summary>
        private void PickLanguage()
        {
            string code = LanguageDialog.Ask(this);
            if (code == null) return;
            Strings.Use(code);
            Strings.Remember(code);
            ApplyTexts();
            Log(Strings.Format("log.lang.changed", Strings.NativeName(code)));
        }

        /// <summary>
        /// Переключить язык уже построенного окна — ровно то, что делает выбор в списке,
        /// но без запоминания выбора. Нужно самопроверке: она гоняет одно окно по всем языкам,
        /// проверяя, что повторная раскладка надписей (и смена RightToLeftLayout) не ломает форму.
        /// </summary>
        internal void SwitchLanguage(string code)
        {
            if (!Strings.Use(code)) return;
            ApplyTexts();
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

        private static Label MakeFieldLabel() => new Label
        {
            AutoSize = true, TextAlign = ContentAlignment.MiddleLeft,
            Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 8, 8),
        };

        /// <summary>
        /// Группа кнопок в общей ленте: подпись, свои кнопки и перенос строки после последней —
        /// так следующая группа всегда начинается с новой строки, а внутри группы кнопки текут
        /// сами (на длинных переводах группа переносится, жёсткая ширина обрезала бы надписи).
        /// Возвращает группу — текст подписи расставляет <see cref="ApplyTexts"/> по действующему языку.
        /// </summary>
        private (Label Caption, string Key, Button[] Buttons) AddButtonRow(
            FlowLayoutPanel host, string captionKey, params Button[] items)
        {
            var caption = MakeFieldLabel();
            // Серый: это подпись группы, а не ещё одна надпись, спорящая с кнопками.
            caption.ForeColor = Color.Gray;
            host.Controls.Add(caption);
            host.Controls.AddRange(items);
            host.SetFlowBreak(items[items.Length - 1], true);
            return (caption, captionKey, items);
        }

        /// <summary>
        /// Расширить окно так, чтобы самая длинная группа кнопок помещалась в одну строку.
        /// Иначе перенос внутри группы уводит её хвост под подпись, и колонка кнопок ломается —
        /// а именно её ради порядка работы и заводили. Ширина считается по фактическим размерам:
        /// они зависят и от языка (переводы длиннее русского), и от масштаба экрана (на 150 %
        /// прежние 880 точек уже не вмещали ряд «Шаги»). Окно только расширяется, не выходит за
        /// рабочую область экрана и уже достаточную ширину — в том числе выбранную пользователем
        /// или развёрнутое окно — не меняет. Возвращает true, если ширину пришлось менять.
        ///
        /// До показа окна ничего не делает: пока хендла нет, оно стоит в своей исходной точке, а
        /// <see cref="FormStartPosition.CenterScreen"/> применяется позже — <c>Screen.FromControl</c>
        /// вернул бы основной монитор, а не тот, на котором окно окажется (замечание Codex на
        /// PR #78). Поэтому первый расчёт делает <see cref="OnShown"/>, когда окно уже размещено.
        /// </summary>
        private bool FitButtonGroups()
        {
            if (_buttons == null || _buttonGroups == null || !IsHandleCreated) return false;

            static int Span(Control c) => c.PreferredSize.Width + c.Margin.Horizontal;

            int need = 0;
            foreach (var (caption, _, items) in _buttonGroups)
            {
                int row = Span(caption);
                foreach (Button b in items) row += Span(b);
                need = Math.Max(need, row);
            }
            need += _buttons.Padding.Horizontal;

            Rectangle area = Screen.FromControl(this).WorkingArea;
            int frame = Width - ClientSize.Width;
            int target = Math.Min(need, area.Width - frame);
            if (ClientSize.Width >= target) return false;

            ClientSize = new Size(target, ClientSize.Height);
            // Окно у правого края экрана: расти вправо ему некуда, поэтому сдвигаем влево —
            // иначе как раз правые кнопки группы уехали бы за рабочую область (замечание
            // Codex на PR #78). Ширина уже ограничена шириной области, так что места хватит.
            if (Right > area.Right) Left = Math.Max(area.Left, area.Right - Width);
            return true;
        }

        /// <summary>Кнопки растягиваются под текст: длина надписи зависит от языка.</summary>
        private Button MakeButton(EventHandler onClick)
        {
            var b = new Button
            {
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                MinimumSize = new Size(90, 34), Padding = new Padding(10, 0, 10, 0),
                Margin = new Padding(0, 0, 8, 4),
            };
            b.Click += onClick;
            return b;
        }

        private void SetButton(Button b, string textKey, string tipKey)
        {
            b.Text = Strings.Get(textKey);
            Tip(b, tipKey);
        }

        /// <summary>Всплывающая подсказка: что делает элемент, что для этого нужно и что получится.</summary>
        private void Tip(Control c, string key) => _tips.SetToolTip(c, Strings.Get(key));

        /// <summary>
        /// Самопроверка для --selftest: у каждой кнопки, поля ввода, списка и выпадающего
        /// списка должна быть подсказка. Возвращает количество элементов с подсказкой
        /// и описания тех, у кого её нет.
        /// </summary>
        internal (int withTip, List<string> missing) CheckTooltips() => CheckTooltips(this, _tips);

        /// <summary>
        /// То же самое для любого окна и его набора подсказок. Отдельным методом, потому что
        /// проверять надо не только главную форму: диалог выбора языка в её дерево не входит,
        /// и без этого его подсказки не проверялись бы ничем (замечание Codex на PR #86).
        /// </summary>
        internal static (int withTip, List<string> missing) CheckTooltips(Control root, ToolTip tips)
        {
            var missing = new List<string>();
            int withTip = 0;

            Walk(root, c =>
            {
                if (c is not (Button or TextBox or ListView or ListBox or ComboBox)) return;
                if (string.IsNullOrWhiteSpace(tips.GetToolTip(c))) missing.Add($"{c.GetType().Name} \"{c.Text}\"");
                else withTip++;
            });

            return (withTip, missing);
        }

        /// <summary>
        /// Самопроверка для --selftest: ни одна надпись и ни одна подсказка не должны содержать
        /// маркер отсутствующего перевода. Так потерянный ключ виден сразу, а не пустотой в окне.
        /// </summary>
        internal List<string> MissingTranslations()
        {
            var bad = new List<string>();

            void Check(string where, string text)
            {
                if (!string.IsNullOrEmpty(text) && text.Contains(Strings.MissingMarkerStart, StringComparison.Ordinal))
                    bad.Add(where + ": " + text);
            }

            Check("Form.Text", Text);
            Check("StatusBar", _status.Text);
            foreach (ColumnHeader col in _lv.Columns) Check("Column", col.Text);
            Walk(this, c =>
            {
                Check(c.GetType().Name, c.Text);
                Check(c.GetType().Name + ".Tip", _tips.GetToolTip(c));
            });
            return bad;
        }

        /// <summary>Те же проверки надписей для чужого окна — см. <see cref="CheckTooltips(Control, ToolTip)"/>.</summary>
        internal static List<string> MissingTranslations(Control root, ToolTip tips)
        {
            var bad = new List<string>();

            void Check(string where, string text)
            {
                if (!string.IsNullOrEmpty(text) && text.Contains(Strings.MissingMarkerStart, StringComparison.Ordinal))
                    bad.Add(where + ": " + text);
            }

            Check("Form.Text", root.Text);
            Walk(root, c =>
            {
                Check(c.GetType().Name, c.Text);
                Check(c.GetType().Name + ".Tip", tips.GetToolTip(c));
            });
            return bad;
        }

        private static void Walk(Control root, Action<Control> visit)
        {
            foreach (Control c in root.Controls)
            {
                visit(c);
                Walk(c, visit);
            }
        }

        // ---------- действия ----------

        private void RefreshList(CancellationToken cancel = default)
        {
            // Снимаем своё прежнее значение до опроса, а не после: список успевает наполниться
            // строками нового носителя ещё до конца обхода, и прерванное обновление (отмена,
            // ошибка) оставило бы в поле PIN уже вынутого токена — он ушёл бы дальше как явный.
            ClearAutoFilledPin();
            // Прежнее объяснение снимаем сразу: пока обход идёт, оно относилось бы к старому
            // состоянию, а прерванное обновление оставило бы его на пустом списке навсегда.
            SetEmptyHint(null);
            Invoke(() => { _lv.Items.Clear(); _allRows.Clear(); _rowSeq = 0; });
            // Сорвавшийся опрос нельзя выдавать за «контейнеров нет»: у Рутокен Lite и
            // JaCarta LT контейнеры КриптоПро видны только прямым APDU, и его ошибка означает
            // «неизвестно», а не «пусто» (замечание Codex на PR #83).
            bool scanFailed = false;
            Log(Strings.Get("status.refresh"));

            // HDIMAGE-копия и исходный токен часто имеют одно логическое имя. Показываем
            // файловую копию отдельной строкой и адресуем её полным именем, иначе CryptoAPI
            // снова выбирает токен и показывает старые права ключа.
            var installedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in ContainerStore.Installed())
            {
                // Папка могла остаться после неудачной установки, хотя CSP точный
                // HDIMAGE-контейнер не принял. Такая строка не должна скрывать рабочий
                // одноимённый контейнер на токене.
                if (!ContainerStore.IsVisibleToCsp(c.Name)) continue;
                if (!installedNames.Add(c.Name)) continue;
                AddRow("HDIMAGE", Strings.Get("log.container.csp"), c.Name, c.Folder,
                    new CspContainerSelection { Target = CertMgr.HdImageContainer(c.Name) });
            }
            foreach (var c in CertFromContainer.EnumContainers())
            {
                if (installedNames.Contains(c.Name)) continue;
                // Носитель здесь неизвестен по существу: PP_ENUMCONTAINERS отдаёт только имя
                // контейнера, а на каком устройстве он лежит — нет. Прочерк честнее выдуманного
                // «HDIMAGE»: контейнер может быть и на токене, и в реестре.
                AddRow("—", Strings.Get("log.container.csp"), c.Name,
                       Strings.Format("log.container.provider", c.ProvType),
                       new CspContainerSelection { Target = c.Name });
            }

            // Токены по PKCS#11: метаданные и профиль механизмов видны без PIN;
            // публичные сертификаты показываются только когда реально присутствуют.
            cancel.ThrowIfCancellationRequested();
            var tokens = Pkcs11Token.Enumerate(readContainers: true, log: LogDebug, cancel: cancel);
            // Библиотека токен показала — это ещё не значит, что его объекты прочитаны:
            // сессия могла не открыться, а поиск объектов упасть. Тогда пустой перечень
            // контейнеров ничего не доказывает (замечание Codex на PR #83). Флаг осмыслен
            // именно здесь: контейнеры мы как раз просили прочитать.
            foreach (var t in tokens) if (t != null && !t.ContainersKnown) scanFailed = true;
            LogDebug("[PKCS#11] " + Strings.Format("token.found", tokens.Count));
            foreach (var t in tokens)
            {
                LogDebug("  " + Strings.Format("cli.token.line",
                    t.Reader ?? "?", t.Label ?? "?", Pkcs11Token.KindName(t.Kind),
                    t.Serial ?? "?", t.Firmware ?? "?"));
                LogDebug("    " + Strings.Format("cli.token.pin", Pkcs11Token.PinState(t)));
                LogDebug("    " + Pkcs11Token.CapabilitySummary(t));
                if (t.Kind == RutokenKind.RutokenEcp)
                    LogDebug("    " + Strings.Get("token.boundary.ecp"));

                bool hasDirectRow = false;
                foreach (var c in t.Containers)
                {
                    AddRow($"{t.Reader} [{Pkcs11Token.KindName(t.Kind)}]", "PKCS#11",
                           c.Name ?? Strings.Get("log.container.unnamed"),
                           "PKCS#11 · " + Strings.Get(c.CertificateOnly ? "common.certonly"
                                                      : c.Certificate != null ? "common.present" : "common.none"),
                           new TokenCertificateSelection
                           {
                               Name = c.Name,
                               Serial = t.Serial,
                               Certificate = c.Certificate,
                               CertificateOnly = c.CertificateOnly,
                           });
                    hasDirectRow = true;
                }

                // Пассивные Rutoken S/Lite, JaCarta LT/PRO и ESMART хранят шесть файлов контейнера,
                // которые PKCS#11 обычно не показывает. Имена перечисляем без PIN
                // только проверенным APDU конкретного семейства.
                if (DirectTokenApdu.Supports(t.Kind))
                {
                    try
                    {
                        var direct = new DirectTokenApdu
                            { Log = m => LogDebug("[APDU] " + m), Cancel = cancel };
                        foreach (var c in direct.ListContainers(t))
                        {
                            AddRow($"{t.Reader} [{Pkcs11Token.KindName(t.Kind)}]", "APDU",
                                   c.Name ?? Strings.Get("log.container.unnamed"),
                                   $"APDU · {Strings.Format("cli.token.pin", Pkcs11Token.PinState(t))}",
                                   new ApduContainerSelection { Token = t, Container = c });
                            hasDirectRow = true;
                        }
                    }
                    catch (Exception e)
                    {
                        scanFailed = true;
                        LogWarning("[APDU] " + Strings.Format("log.tokens.unavailable", e.Message));
                    }
                }

                // Пустой PKCS#11-слот всё равно показываем: пользователь должен видеть все
                // подключённые устройства, а не только те, где драйвер отдал публичный объект.
                if (!hasDirectRow)
                    AddRow($"{t.Reader} [{Pkcs11Token.KindName(t.Kind)}]", "PKCS#11",
                           Strings.Get("common.none"),
                           "PKCS#11 · " + Pkcs11Token.CapabilityProfileName(t.CapabilityProfile),
                           new TokenDeviceSelection());
            }

            // Считыватель без библиотеки PKCS#11 иначе исчезал бы из окна совсем: число
            // устройств PKCS#11 не сходилось с числом считывателей, и понять, какой носитель
            // потерялся, было нельзя. Опрос PC/SC пассивный — к карте он не подключается.
            cancel.ThrowIfCancellationRequested();
            // Сбой опроса PC/SC оставляет пустой список — но это «неизвестно», а не «носителей
            // нет»: звать вставить носитель по нему нельзя (замечание Codex на PR #83).
            var pcscReaders = PcscReaders.List(m => LogDebug("[PC/SC] " + m), out bool pcscComplete);
            if (!pcscComplete) scanFailed = true;
            var pkcs11Readers = new List<string>();
            foreach (var t in tokens)
                if (t?.Reader != null) pkcs11Readers.Add(t.Reader);
            foreach (var line in PcscReaders.CoverageLines(pcscReaders, pkcs11Readers))
                LogDebug("[PC/SC] " + line);
            var uncovered = PcscReaders.Uncovered(pcscReaders, pkcs11Readers);
            foreach (var r in uncovered)
                // В колонке контейнера — вендор носителя, а не «нет»: контейнеры КриптоПро на
                // таком носителе быть могут (проверено на BIFIT ANGARA), просто показывает их
                // не PKCS#11, а CSP — отдельной строкой выше.
                AddRow(r.Name, "PC/SC", Strings.Get(PcscReaders.CarrierHintKey(r.Name, r.Atr)),
                       Strings.Format("cli.pcsc.row", r.Atr ?? "?"),
                       new TokenDeviceSelection());

            cancel.ThrowIfCancellationRequested();
            var exp = new RutokenExporter
            {
                Log = m => LogDebug("[rtCOMLite] " + m),
                Cancel = cancel,
                SkipReaders = Pkcs11Token.SmartCardReaders(tokens),
            };
            try
            {
                foreach (var c in exp.ReadAllContainers())
                    AddRow(Strings.Format("log.container.token", c.TokenName), "rtCOMLite",
                           c.ContainerName ?? Strings.Get("log.container.unnamed"),
                           Strings.Format("log.container.files", c.TokenDir, c.Files.Count), c);
            }
            catch (Exception e)
            {
                // Недоступность самого rtCOMLite неполным обходом не считается: это legacy-путь,
                // и на x64/ARM64 без зарегистрированного компонента CreateContext падает всегда,
                // ещё не дойдя ни до одного носителя. Иначе «опрос не завершился» показывалось бы
                // и на машине вовсе без носителей. А вот ошибка уже начатого обхода — неполный
                // обход: контекст создан, носители пошли, и пустота больше не доказана
                // (замечания Codex на PR #83).
                if (exp.Started) scanFailed = true;
                LogWarning(Strings.Format("log.tokens.unavailable", e.Message));
            }
            SuggestFactoryPin(tokens);
            // Считаем носители, а не считыватели: пустой слот — это «вставьте носитель», а не
            // «нет библиотеки». Строку в списке PcscReaders.Uncovered даёт тоже только по
            // вставленной карте, поэтому иначе пустой считыватель объяснялся бы неверно
            // (замечание Codex на PR #83).
            int carriers = 0;
            foreach (var r in pcscReaders) if (r != null && r.CardPresent) carriers++;
            SetEmptyHint(carriers, tokens.Count, uncovered.Count, scanFailed);
            Log(Strings.Get("log.done"));
        }

        /// <summary>
        /// Подставить в поле PIN заводское значение подключённой модели: владелец чаще всего
        /// PIN не менял, а вводить «12345678» руками каждый раз бессмысленно. Что именно можно
        /// подставить, решает <see cref="StandardPins.SuggestFor"/> — там же и границы: ровно
        /// один носитель, подтверждённое драйвером заводское состояние PIN и чистый счётчик.
        ///
        /// Своё прежнее значение снимает <see cref="ClearAutoFilledPin"/> в начале обновления,
        /// поэтому прерванный обход не оставляет в поле PIN уже вынутого носителя. Введённое
        /// пользователем не трогается, а отправки PIN на карту подстановка не делает — это
        /// по-прежнему явное действие.
        /// </summary>
        private void SuggestFactoryPin(IEnumerable<Pkcs11TokenInfo> tokens)
        {
            StandardPin suggestion = StandardPins.SuggestFor(tokens);
            if (suggestion == null) return;
            Invoke(() =>
            {
                if (_txtPin.Text.Length != 0) return;
                // Сначала запоминаем своё значение, потом ставим текст: обработчик TextChanged
                // иначе принял бы собственную подстановку за правку пользователя.
                _autoFilledPin = suggestion.UserPin;
                _autoFilledModel = suggestion.Model;
                _txtPin.Text = suggestion.UserPin;
                _lblPinHint.Text = PinHintText();
            });
        }

        /// <summary>
        /// Перечитать состояние выбранного носителя перед операцией и вернуть <c>null</c>, если
        /// работать по строке списка больше нельзя. Строка несёт снимок прошлого обновления, а
        /// токен могли заменить в том же считывателе: индексы контейнеров и флаги PIN тогда
        /// относятся к другой карте, и операция сожгла бы её попытку на чужом значении.
        ///
        /// Поэтому здесь fail-closed: заменённый носитель (другой серийный номер), исчезнувший
        /// из перечисления или недоступное перечисление — все три случая прекращают операцию с
        /// сообщением в журнале, а не продолжают её по устаревшему снимку.
        /// </summary>
        private Pkcs11TokenInfo CurrentStateOf(Pkcs11TokenInfo snapshot, CancellationToken cancel)
        {
            if (snapshot == null || string.IsNullOrEmpty(snapshot.Reader)) return snapshot;
            List<Pkcs11TokenInfo> live;
            try { live = Pkcs11Token.Enumerate(readContainers: false, cancel: cancel); }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                LogWarning(Strings.Format("log.tokens.unavailable", e.Message));
                LogWarning(Strings.Get("log.token.state.unknown"));
                return null;
            }
            foreach (var token in live)
            {
                if (!string.Equals(token.Reader, snapshot.Reader, StringComparison.OrdinalIgnoreCase))
                    continue;
                // Серийный номер — единственное, чем «тот же носитель» отличается от подменённого
                // в том же считывателе. PKCS#11 разрешает его не сообщать, и тогда подтвердить
                // тождество нечем: пустой серийник считаем неизвестным состоянием, а не совпадением.
                if (string.IsNullOrEmpty(snapshot.Serial) || string.IsNullOrEmpty(token.Serial))
                {
                    LogWarning(Strings.Get("log.token.state.unknown"));
                    return null;
                }
                if (!string.Equals(token.Serial, snapshot.Serial, StringComparison.Ordinal))
                {
                    LogWarning(Strings.Get("log.token.replaced"));
                    return null;
                }
                return token;
            }
            LogWarning(Strings.Get("log.token.state.unknown"));
            return null;
        }

        /// <summary>
        /// Значок и подсказка кнопки показа PIN по текущему состоянию поля. Значок называет
        /// то, что видно сейчас, а подсказка — что сделает нажатие.
        /// </summary>
        private void ApplyPinRevealState()
        {
            if (_btnPinReveal == null) return;
            bool hidden = _txtPin.UseSystemPasswordChar;
            _btnPinReveal.Text = hidden ? "•••" : "👁";
            Tip(_btnPinReveal, hidden ? "tip.pin.show" : "tip.pin.hide");
        }

        /// <summary>
        /// Текст подсказки у поля PIN. Пока в поле лежит подставленное программой значение,
        /// подсказка называет модель — иначе смена языка стёрла бы единственный признак того,
        /// что PIN заводской, а не введённый владельцем.
        /// </summary>
        private string PinHintText()
        {
            return _autoFilledModel != null && _txtPin.Text == _autoFilledPin
                ? Strings.Format("field.pin.hint.factory", _autoFilledModel)
                : Strings.Get("field.pin.hint");
        }

        /// <summary>
        /// PIN для операции. Подставленное самой программой значение явным вводом не считается:
        /// оно уходит как <c>null</c>, и PIN выбирает <c>DirectTokenApdu.ResolvePin</c> по
        /// актуальным флагам носителя. Иначе горячая замена токена без обновления списка
        /// отправила бы заводское значение на носитель со сменённым PIN и сожгла бы попытку.
        /// Отредактированный пользователем текст перестаёт совпадать с подставленным и идёт
        /// дальше как явный PIN — как и любое значение, введённое руками.
        /// </summary>
        private string OperationPin()
        {
            string text = TextOf(_txtPin);
            if (_autoFilledPin != null && string.Equals(text, _autoFilledPin, StringComparison.Ordinal))
                return null;
            return NullIfEmpty(text);
        }

        /// <summary>
        /// Убрать из поля значение, подставленное самой программой. Введённый пользователем
        /// текст остаётся: его судьбу решает только он сам.
        /// </summary>
        private void ClearAutoFilledPin()
        {
            Invoke(() =>
            {
                if (_autoFilledPin == null) return;
                bool ours = _txtPin.Text == _autoFilledPin;
                _autoFilledPin = null;
                _autoFilledModel = null;
                if (ours)
                {
                    _txtPin.Text = string.Empty;
                    _lblPinHint.Text = PinHintText();
                }
            });
        }

        /// <summary>
        /// Гейт лицензии для операций экспорта закрытого ключа. Без действительной лицензии
        /// операция не выполняется; в журнал идут статус и отпечаток этой машины, чтобы было
        /// понятно, как получить лицензию (активация обменивает код на подписанный файл лицензии).
        /// </summary>
        private bool RequireLicense()
        {
            if (LicenseGate.IsLicensed()) return true;
            LogWarning(Strings.Get("license.required"));
            Log(LicenseGate.StatusText());
            Log(LicenseGate.FingerprintText());
            return false;
        }

        /// <summary>Выбрать файл лицензии (.jws), проверить его для этой машины и установить.</summary>
        private void DoLicense()
        {
            using var dlg = new OpenFileDialog
            {
                Title = Strings.Get("dlg.license.title"),
                // keytool выдаёт файл с расширением .license, приложение хранит его как .jws —
                // маска обязана покрывать оба, иначе выданный сервером файл в диалоге не виден
                // и владелец выбирает случайный .jws (например, от другой платформы).
                Filter = Strings.Get("license.filter") + "|*.jws;*.license;*.lic;*.txt|"
                         + Strings.Get("files.all") + "|*.*",
                CheckFileExists = true,
            };
            if (dlg.ShowDialog(this) != DialogResult.OK) { Log(Strings.Get("log.cancelled")); return; }
            try
            {
                var info = LicenseGate.Install(dlg.FileName);
                if (info.Ok) Log(Strings.Format("license.installed", LicenseGate.LicensePath));
                // Показываем итог именно этой попытки (info), а не перечитанную прежнюю лицензию:
                // иначе отклонение выбранного файла выглядело бы как успех при уже установленной.
                Log(LicenseGate.Describe(info));
                // Одного «недействительна» мало: без причины владелец не отличит чужую платформу
                // от чужого отпечатка и будет искать проблему в приложении. Причина идёт отдельной
                // строкой и на языке интерфейса; точное сообщение верификатора (диагностика
                // протокола, всегда по-русски) остаётся в файле журнала.
                if (!info.Ok)
                {
                    LogWarning("  " + LicenseGate.ReasonText(info));
                    if (!string.IsNullOrEmpty(info.VerifierDiagnostic))
                        SessionLog.Write("  " + info.VerifierDiagnostic, LogLevel.Debug);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                LogError(Strings.Format("log.error", e.Message));
            }
        }

        private void DoExport(CancellationToken cancel)
        {
            if (!RequireLicense()) return;
            string dest = AskDestination();
            if (dest == null) { Log(Strings.Get("log.cancelled.user")); return; }
            ContainerSelection selected = SelectedContainer();
            if (selected != null && selected.Apdu == null && selected.Direct == null)
            {
                Log(Strings.Get("log.export.directonly"));
                return;
            }
            var pipe = new ExportPipeline() { Log = LogDebug, Cancel = cancel };
            int saved;
            if (selected?.Apdu != null)
            {
                Pkcs11TokenInfo live = CurrentStateOf(selected.Apdu.Token, cancel);
                if (live == null) return;
                pipe.ExportDirectContainer(live, selected.Apdu.Container, dest, OperationPin());
                saved = 1;
            }
            else if (selected?.Direct != null)
            {
                pipe.ExportContainer(selected.Direct, dest);
                saved = 1;
            }
            else
            {
                saved = pipe.ExportFromTokens(dest, OperationPin()).Count;
            }
            Log(Strings.Format("log.exported", saved));
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoExtract()
        {
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }
            string destRoot = AskDestination();
            if (destRoot == null) { Log(Strings.Get("log.cancelled.user")); return; }
            string dest = Path.Combine(destRoot, "certs_" + Sanitize(selected.Name));

            // Для строки PKCS#11 сохраняем именно сертификат выбранного токена. Поиск заново
            // только по метке раньше брал первый попавшийся токен с тем же именем контейнера.
            var tokenSelection = selected.Token;
            if (tokenSelection != null)
            {
                if (tokenSelection.Certificate == null)
                {
                    LogError(Strings.Get("log.cert.fail"));
                    return;
                }
                Directory.CreateDirectory(dest);
                string path = Pkcs11Token.UniqueCertPath(dest, tokenSelection.Name,
                    tokenSelection.Serial, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                File.WriteAllBytes(path, tokenSelection.Certificate);
                Log(Strings.Format("cli.token.cert.saved", path));
                return;
            }

            var (ex, sg) = CertFromContainer.SaveCerts(container, dest);
            Log(Strings.Format("log.cert.exchange", ex ?? Strings.Get("common.none")));
            Log(Strings.Format("log.cert.sign", sg ?? Strings.Get("common.none")));
            if (ex == null && sg == null)
                LogError(Strings.Get("log.cert.fail"));
        }

        private void DoFull(CancellationToken cancel)
        {
            ContainerSelection selected = SelectedContainer();
            if (selected != null && selected.Apdu == null && selected.Direct == null)
            {
                // Строка CSP не является источником для APDU-копирования. Но если все её
                // реальные ключи уже имеют CRYPT_EXPORT, говорим точную причину вместо
                // общего сообщения про неподходящую строку и не требуем лицензию зря.
                if (selected.IsCsp && !string.IsNullOrEmpty(selected.Name))
                {
                    var (exchange, signature) = CheckExportability(selected.Target);
                    if (CertFromContainer.AllFoundKeysExportable(exchange, signature))
                    {
                        LogError(Strings.Format("log.error", Strings.Get("err.container.exportable")));
                        return;
                    }
                }
                Log(Strings.Get("log.export.directonly"));
                return;
            }
            if (!RequireLicense()) return;
            var confirm = AskConfirm(
                Strings.Get(selected == null ? "dlg.confirm.full" : "dlg.confirm.full.selected"),
                Strings.Get("dlg.confirm.title"));
            if (confirm != DialogResult.OK) { Log(Strings.Get("log.cancelled.user")); return; }
            // Папку спрашиваем после подтверждения: отказавшемуся не за чем выбирать её вовсе.
            string dest = AskDestination();
            if (dest == null) { Log(Strings.Get("log.cancelled.user")); return; }

            var pipe = new ExportPipeline() { Log = LogDebug, Cancel = cancel };
            ExportPipelineResult result;
            if (selected?.Apdu != null)
            {
                Pkcs11TokenInfo live = CurrentStateOf(selected.Apdu.Token, cancel);
                if (live == null) return;
                result = pipe.ExportDirectAndMakeExportable(
                    live, selected.Apdu.Container, dest, userPin: OperationPin());
            }
            else if (selected?.Direct != null)
                result = pipe.ExportAndMakeExportable(selected.Direct, dest);
            else
                result = pipe.ExportAndMakeExportable(dest, userPin: OperationPin());
            if (result.AllSucceeded) Log(Strings.Get("log.full.done"));
            else Log(Strings.Format("log.exported", result.Exported));
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoViewContainer()
        {
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }
            if (IsCertificateOnly(selected)) { LogWarning(Strings.Get("hint.row.certonly")); return; }
            var (ex, sg) = CheckExportability(container);
            Log(Strings.Format("log.check.container", container));
            Log("  " + Strings.Get("col.location") + ": " + selected.Location);
            Log("  " + Strings.Get("col.backend") + ": " + selected.Backend);
            Log("  " + Strings.Get("col.details") + ": " + selected.Details);
            Log("  " + Strings.Format("log.check.exchange", ex));
            Log("  " + Strings.Format("log.check.sign", sg));

            string text = Strings.Format("log.check.container", container) + Environment.NewLine
                        + Strings.Get("col.location") + ": " + selected.Location + Environment.NewLine
                        + Strings.Get("col.backend") + ": " + selected.Backend + Environment.NewLine
                        + Strings.Get("col.details") + ": " + selected.Details + Environment.NewLine
                        + Environment.NewLine
                        + Strings.Format("log.check.exchange", ex) + Environment.NewLine
                        + Strings.Format("log.check.sign", sg);
            ShowInfo(text, Strings.Get("col.container"));
        }

        private static (CertFromContainer.ExportCheck exchange,
                        CertFromContainer.ExportCheck signature) CheckExportability(string container) =>
            (CertFromContainer.CheckExportable(container, CertFromContainer.AT_KEYEXCHANGE),
             CertFromContainer.CheckExportable(container, CertFromContainer.AT_SIGNATURE));

        private void DoInstall(CancellationToken cancel)
        {
            string folder = AskFolder(Strings.Get("dlg.folder.container"), _dest);
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                LogWarning(Strings.Get("log.install.notcontainer"));
                return;
            }

            string current = ContainerStore.ReadName(folder)
                             ?? Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar));

            string name = AskText(Strings.Get("dlg.install.title"), Strings.Get("dlg.install.prompt"),
                                  current, password: false);
            if (name == null) { Log(Strings.Get("log.cancelled")); return; }
            name = name.Trim();

            var installed = ContainerStore.Install(folder, name == current ? null : name);
            Log(Strings.Format("log.install.done", installed));
            if (name != current && !installed.Renamed)
                Log(Strings.Format("log.install.norename", installed.Name));
            if (installed.Verified && !installed.VisibleToCsp)
                LogWarning(Strings.Get("log.install.invisible"));
            else if (installed.VisibleToCsp)
            {
                string certMgrPath = CertMgr.Locate();
                if (certMgrPath != null)
                {
                    var cm = new CertMgr(certMgrPath) { Log = LogDebug, Cancel = cancel };
                    var linked = cm.InstallContainerCertificates(
                        folder, CertMgr.HdImageContainer(installed.Name));
                    foreach (ToolResult failure in linked.Results)
                        if (!failure.Success)
                            Log(Strings.Format("tool.certmgr.installwarn", failure.Explain()));
                }
            }
            RefreshList();
        }

        /// <summary>
        /// Спросить, какой .pfx нужен, и запустить выбранный способ. Файлы получаются разные:
        /// «Экспорт в PFX» идёт через certmgr КриптоПро, и такой файл КриптоПро примет обратно;
        /// «Собрать PFX (без CSP)» собирает файл сам из папки снятого контейнера, и КриптоПро
        /// его не импортирует (AGENTS п. 39). Раньше это были две соседние кнопки, а разницу
        /// объясняла только подсказка — теперь она написана прямо рядом с выбором.
        ///
        /// Причина, по которой первый способ сейчас недоступен, берётся из той же таблицы
        /// <see cref="ActionAvailability"/>, что гасит кнопки по выделенной строке: второй
        /// способ строки не требует, поэтому гасить всю кнопку в ленте больше нельзя.
        /// </summary>
        private void DoPfxChoice()
        {
            string reason = ActionAvailability.ReasonKey(RowAction.ExportPfx, CurrentRow());
            // Главное различие — примет ли файл обратно сам КриптоПро — в подсказках кнопок не
            // сказано: они объясняют, как файл собирается. Дописываем его к обоим пояснениям,
            // иначе о нём узнают из журнала после экспорта (замечание Codex на PR #79). Для
            // способа без CSP берём ту же фразу, что уходит в журнал, — она уже переведена.
            int choice = ChoiceDialog.Ask(
                this, Strings.Get("dlg.pfx.choice.title"), Strings.Get("dlg.pfx.choice.prompt"),
                new ChoiceDialog.Option(Strings.Get("btn.pfx"),
                                        Strings.Get("tip.pfx") + "\n\n" + Strings.Get("dlg.pfx.choice.csp"),
                                        reason == null ? null : Strings.Get(reason)),
                new ChoiceDialog.Option(Strings.Get("btn.extractpfx"),
                                        Strings.Get("tip.extractpfx") + "\n\n" + Strings.Get("log.extractpfx.note")));

            switch (choice)
            {
                case 0: Run("status.pfx", DoExportPfx); break;
                case 1: Run("status.extractpfx", DoExtractPfx); break;
                default: Log(Strings.Get("log.cancelled")); break;
            }
        }

        private void DoExportPfx(CancellationToken cancel)
        {
            if (!RequireLicense()) return;
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }
            if (IsCertificateOnly(selected)) { LogWarning(Strings.Get("hint.row.certonly")); return; }

            string exe = CertMgr.Locate();
            if (exe == null) { LogError(Strings.Get("log.pfx.nocertmgr")); return; }

            string dest = AskSaveFile(Strings.Get("dlg.pfx.save"),
                                      "PKCS#12 (*.pfx)|*.pfx|" + Strings.Get("files.all") + "|*.*",
                                      _dest, Sanitize(selected.Name) + ".pfx");
            if (dest == null) { Log(Strings.Get("log.cancelled")); return; }

            string pass = AskText(Strings.Get("dlg.pfx.pass.title"), Strings.Get("dlg.pfx.pass.prompt"),
                                  "", password: true);
            if (pass == null) { Log(Strings.Get("log.cancelled")); return; }

            var cm = new CertMgr(exe) { Log = LogDebug, Cancel = cancel };
            var r = cm.ExportContainerToPfx(container, dest, pass);
            if (r.Success) Log(Strings.Format("log.pfx.done", dest));
            else LogError(Strings.Format("log.pfx.fail", r.Output));
        }

        /// <summary>
        /// Извлечь закрытый ключ из файлового контейнера без CSP и сохранить в PKCS#8/PEM.
        /// В журнал пишутся только путь и открытый ключ: тело закрытого ключа — секрет.
        /// </summary>
        private void DoExtractKey()
        {
            if (!RequireLicense()) return;
            string folder = AskFolder(Strings.Get("dlg.folder.container"), _dest);
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                LogWarning(Strings.Get("log.install.notcontainer"));
                return;
            }

            string pass = AskText(Strings.Get("dlg.extractkey.pass.title"),
                                  Strings.Get("dlg.extractkey.pass.prompt"), "", password: true);
            if (pass == null) { Log(Strings.Get("log.cancelled")); return; }

            string dest = AskSaveFile(Strings.Get("dlg.extractkey.save"),
                                      "PEM (*.pem)|*.pem|" + Strings.Get("files.all") + "|*.*",
                                      _dest, "privatekey.pem", "pem");
            if (dest == null) { Log(Strings.Get("log.cancelled")); return; }

            try
            {
                var r = ContainerKeyExtractor.Extract(folder, pass);
                File.WriteAllText(dest, GostKeyExport.ToPkcs8Pem(r));
                Log(Strings.Format("log.extractkey.done", dest));
                Log("  " + Strings.Format("log.extractkey.pub", r.CurveOid));
            }
            catch (ContainerKeyException e)
            {
                LogError(Strings.Format("log.extractkey.fail", e.Message));
            }
        }

        /// <summary>
        /// Собрать .pfx из файлового контейнера без CSP: ключ из *.key, сертификат из header.key.
        /// Если сертификата в контейнере нет, спрашиваем файл .cer — остальное не меняется.
        /// </summary>
        private void DoExtractPfx()
        {
            if (!RequireLicense()) return;
            string folder = AskFolder(Strings.Get("dlg.folder.container"), _dest);
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                LogWarning(Strings.Get("log.install.notcontainer"));
                return;
            }

            string pass = AskText(Strings.Get("dlg.extractkey.pass.title"),
                                  Strings.Get("dlg.extractkey.pass.prompt"), "", password: true);
            if (pass == null) { Log(Strings.Get("log.cancelled")); return; }

            string pfxPass = AskText(Strings.Get("dlg.extractpfx.pass.title"),
                                     Strings.Get("dlg.extractpfx.pass.prompt"), "", password: true);
            if (pfxPass == null) { Log(Strings.Get("log.cancelled")); return; }

            string name = ContainerStore.ReadName(folder)
                          ?? Path.GetFileName(folder.TrimEnd(Path.DirectorySeparatorChar));
            string dest = AskSaveFile(Strings.Get("dlg.extractpfx.save"),
                                      "PKCS#12 (*.pfx)|*.pfx|" + Strings.Get("files.all") + "|*.*",
                                      _dest, Sanitize(name) + ".pfx");
            if (dest == null) { Log(Strings.Get("log.cancelled")); return; }

            try
            {
                var r = ContainerKeyExtractor.Extract(folder, pass);
                byte[] cert = r.Certificate;
                if (cert == null)
                {
                    Log(Strings.Get("log.extractpfx.nocert"));
                    string certFile = AskOpenFile(Strings.Get("dlg.extractpfx.cert"),
                                                  "X.509 (*.cer;*.crt;*.der)|*.cer;*.crt;*.der|"
                                                  + Strings.Get("files.all") + "|*.*");
                    if (certFile == null) { Log(Strings.Get("log.cancelled")); return; }
                    cert = File.ReadAllBytes(certFile);
                }

                File.WriteAllBytes(dest, Pkcs12Export.Build(r, pfxPass, cert, name));
                Log(Strings.Format("log.extractpfx.done", dest));
                // Совместимость сообщаем сразу и на месте: это полноценная резервная
                // копия, которую КриптоПро принимает при обратном импорте.
                Log("  " + Strings.Get("log.extractpfx.note"));
            }
            catch (ContainerKeyException e)
            {
                LogError(Strings.Format("log.extractpfx.fail", e.Message));
            }
        }

        private void OpenLogFolder()
        {
            try
            {
                Directory.CreateDirectory(SessionLog.Dir);
                Process.Start(new ProcessStartInfo(SessionLog.Dir) { UseShellExecute = true });
            }
            catch (Exception ex) { LogError(Strings.Format("log.logs.fail", ex.Message)); }
        }

        // ---------- helpers ----------

        /// <summary>
        /// Модальный вопрос из рабочего потока. Диалоги WinForms обязаны жить на потоке окна:
        /// MessageBox с чужим владельцем ведёт себя непредсказуемо.
        /// </summary>
        private DialogResult AskConfirm(string text, string caption)
        {
            if (InvokeRequired) return (DialogResult)Invoke(new Func<DialogResult>(() => AskConfirm(text, caption)));
            var options = Strings.CurrentIsRightToLeft
                ? MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign
                : default;
            return MessageBox.Show(this, text, caption, MessageBoxButtons.OKCancel, MessageBoxIcon.Question,
                                   MessageBoxDefaultButton.Button1, options);
        }

        private void ShowInfo(string text, string caption)
        {
            if (InvokeRequired) { Invoke(new Action(() => ShowInfo(text, caption))); return; }
            var options = Strings.CurrentIsRightToLeft
                ? MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign
                : default;
            MessageBox.Show(this, text, caption, MessageBoxButtons.OK, MessageBoxIcon.Information,
                            MessageBoxDefaultButton.Button1, options);
        }

        private string AskFolder(string description, string initial)
        {
            if (InvokeRequired) return (string)Invoke(new Func<string>(() => AskFolder(description, initial)));
            using var d = new FolderBrowserDialog { Description = description, UseDescriptionForTitle = true };
            if (Directory.Exists(initial)) d.SelectedPath = initial;
            return d.ShowDialog(this) == DialogResult.OK ? d.SelectedPath : null;
        }

        private string AskSaveFile(string title, string filter, string initialDir, string suggestedName, string defaultExt = "pfx")
        {
            if (InvokeRequired)
                return (string)Invoke(new Func<string>(() => AskSaveFile(title, filter, initialDir, suggestedName, defaultExt)));
            using var d = new SaveFileDialog
            {
                Title = title, Filter = filter, FileName = suggestedName,
                AddExtension = true, DefaultExt = defaultExt, OverwritePrompt = true,
            };
            if (Directory.Exists(initialDir)) d.InitialDirectory = initialDir;
            return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
        }

        private string AskOpenFile(string title, string filter)
        {
            if (InvokeRequired) return (string)Invoke(new Func<string>(() => AskOpenFile(title, filter)));
            using var d = new OpenFileDialog { Title = title, Filter = filter, CheckFileExists = true };
            return d.ShowDialog(this) == DialogResult.OK ? d.FileName : null;
        }

        private string AskText(string title, string prompt, string initial, bool password)
        {
            if (InvokeRequired)
                return (string)Invoke(new Func<string>(() => AskText(title, prompt, initial, password)));
            return PromptDialog.Ask(this, title, prompt, initial, password);
        }

        /// <summary>Запустить длинную операцию в фоне: с подписью в строке состояния и возможностью отмены.</summary>
        private void Run(string titleKey, Action<CancellationToken> work)
        {
            var cancellation = new CancellationTokenSource();
            _cancellation = cancellation;
            SetBusy(true, Strings.Get(titleKey));
            Task.Run(() =>
            {
                try { work(cancellation.Token); }
                catch (OperationCanceledException) { Log(Strings.Get("log.cancel.done")); }
                catch (Exception ex) { LogError(Strings.Format("log.error", ex.Message)); }
                finally
                {
                    _cancellation = null;
                    cancellation.Dispose();
                    SetBusy(false, null);
                }
            });
        }

        /// <summary>Действия, которым отмена не нужна (всё быстрое), запускаются так же — просто игнорируют токен.</summary>
        private void Run(string titleKey, Action work) => Run(titleKey, _ => work());

        private void CancelCurrent()
        {
            var cancellation = _cancellation;
            if (cancellation == null || cancellation.IsCancellationRequested) return;
            Log(Strings.Get("log.cancel.requested"));
            SetStatus(Strings.Get("status.cancelling"));
            try { cancellation.Cancel(); } catch (ObjectDisposedException) { }
        }

        private void SetBusy(bool busy, string title)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetBusy(busy, title))); return; }
            _busy = busy;
            foreach (var b in _actionButtons) b.Enabled = !busy;
            // Занятость гасит всё, выделение — только своё подмножество. Второй проход после
            // общего нужен и на входе, и на выходе: список мог обновиться самой операцией.
            UpdateRowActions();
            _btnCancel.Enabled = busy;
            // Кнопка языка гасится вместе с остальными служебными: она в _actionButtons;
            // фильтр журнала, как и его панель, остаётся доступен во время операции.
            _progress.Visible = busy;
            _status.Text = busy ? title : Strings.Get("status.ready");
            ShowLastLogLine();
            Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
        }

        private void SetStatus(string text)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetStatus(text))); return; }
            _status.Text = text;
            ShowLastLogLine();
        }

        /// <summary>
        /// Погасить кнопки, которым выделенная строка не подходит, и написать причину в их же
        /// подсказках. Раньше все кнопки были активны всегда, а несовпадение строки и действия
        /// выяснялось уже после нажатия — сообщением в журнале (ROADMAP, P2, п. 2).
        ///
        /// Сама проверка в <c>Do*</c> остаётся: строку читает фоновая задача, и между нажатием
        /// и выполнением выделение успевает смениться. Здесь только видимость запрета.
        /// </summary>
        private void UpdateRowActions()
        {
            if (InvokeRequired) { BeginInvoke(new Action(UpdateRowActions)); return; }
            SelectedRow row = CurrentRow();
            foreach (var (button, action) in _rowButtons)
            {
                string reason = ActionAvailability.ReasonKey(action, row);
                button.Enabled = !_busy && reason == null;
                string tip = _baseTips.TryGetValue(button, out string known) ? known : _tips.GetToolTip(button);
                _tips.SetToolTip(button, reason == null ? tip : tip + "\n\n" + Strings.Get(reason));
            }
        }

        /// <summary>
        /// За строкой стоит сертификат-сирота: контейнера с таким именем на носителе нет.
        /// Кнопка на такой строке погашена, но строку читает фоновая задача уже после
        /// нажатия — выделение успевает смениться, поэтому проверка нужна и здесь.
        /// </summary>
        private static bool IsCertificateOnly(ContainerSelection selected) =>
            selected?.Token != null && selected.Token.CertificateOnly;

        /// <summary>Тип выделенной строки — всё, что нужно знать о ней для доступности кнопок.</summary>
        private SelectedRow CurrentRow() =>
            _lv.SelectedItems.Count == 0 ? SelectedRow.None : RowKind(_lv.SelectedItems[0].Tag);

        /// <summary>
        /// Тип строки по её <c>Tag</c>. Отдельно от <see cref="CurrentRow"/>, потому что тот
        /// же вопрос задаётся не только про выделенную строку: по нему же считаются строки с
        /// контейнерами для объяснения пустого списка.
        /// </summary>
        private static SelectedRow RowKind(object tag)
        {
            return tag switch
            {
                CspContainerSelection => SelectedRow.Csp,
                ApduContainerSelection => SelectedRow.Apdu,
                RutokenContainer => SelectedRow.Direct,
                // Сертификат прочитан при обновлении списка: пустое поле здесь означает, что
                // извлекать нечего, и это видно до нажатия, а не после попытки. Сертификат-сирота
                // выделен отдельно: контейнера за ним нет вовсе, адресовать по имени нечего.
                TokenCertificateSelection t => t.CertificateOnly ? SelectedRow.TokenCertificateOnly
                    : t.Certificate != null ? SelectedRow.TokenWithCert : SelectedRow.TokenWithoutCert,
                // TokenDeviceSelection и любая строка без своего Tag: контейнера в ней нет.
                _ => SelectedRow.Device,
            };
        }

        /// <summary>
        /// Показать подсказку выключенной кнопки. Windows не доставляет выключенному окну
        /// сообщений мыши, поэтому <see cref="ToolTip"/> сам её не покажет, а причина отказа
        /// нужна именно там, где кнопка. Сообщения при этом приходят родителю — по ним и
        /// определяем, над какой погашенной кнопкой стоит курсор.
        /// </summary>
        private void ShowDisabledTip(Control host, Point at)
        {
            Button target = null;
            foreach (Control c in host.Controls)
                if (c is Button b && !b.Enabled && b.Bounds.Contains(at)) { target = b; break; }

            // Пока курсор на той же кнопке, ничего не трогаем: повторный Show моргал бы окном.
            if (ReferenceEquals(target, _disabledTipOn)) return;
            _disabledTipOn = target;
            _tips.Hide(host);
            if (target == null) return;

            string text = _tips.GetToolTip(target);
            if (!string.IsNullOrEmpty(text))
                _tips.Show(text, host, target.Left, target.Bottom + 4, _tips.AutoPopDelay);
        }

        /// <summary>
        /// Строка списка: где носитель, чем она прочитана, имя контейнера и подробности.
        /// Устройство и способ чтения — разные колонки (ROADMAP, P2, п. 6): по ним сортируют
        /// порознь. Имя строки — её номер в порядке обхода: по нему список возвращается к
        /// исходному виду, когда сортировку снимают.
        /// </summary>
        private void AddRow(string where, string how, string name, string details, object tag = null)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddRow(where, how, name, details, tag))); return; }
            var row = new ListViewItem(new[] { where, how, name, details })
            {
                Tag = tag,
                Name = _rowSeq++.ToString("D5", System.Globalization.CultureInfo.InvariantCulture),
            };
            // Полный перечень держим отдельно: в списке видно только то, что подходит под поиск,
            // а решать «показывать нечего» и считать контейнеры нужно по всему обходу.
            _allRows.Add(row);
            if (Matches(row)) _lv.Items.Add(row);
        }

        /// <summary>Подходит ли строка под поиск: подстрока без учёта регистра в любой колонке.</summary>
        private bool Matches(ListViewItem row)
        {
            string needle = _txtFind?.Text?.Trim();
            if (string.IsNullOrEmpty(needle)) return true;
            foreach (ListViewItem.ListViewSubItem cell in row.SubItems)
                if (cell.Text != null
                    && cell.Text.IndexOf(needle, StringComparison.CurrentCultureIgnoreCase) >= 0)
                    return true;
            return false;
        }

        /// <summary>
        /// Пересобрать видимую часть списка по строке поиска. Сам обход не повторяется: строки
        /// уже собраны, меняется только то, что показано. Сортировка сохраняется — сравниватель
        /// остаётся на списке, и строки встают на свои места при добавлении.
        /// </summary>
        private void ApplyFilter()
        {
            if (InvokeRequired) { BeginInvoke(new Action(ApplyFilter)); return; }

            _lv.BeginUpdate();
            try
            {
                _lv.Items.Clear();
                foreach (ListViewItem row in _allRows)
                    if (Matches(row)) _lv.Items.Add(row);
            }
            finally { _lv.EndUpdate(); }

            UpdateRowActions();
            ApplyEmptyHint();
        }

        /// <summary>
        /// Отсортировать список по колонке. Три состояния по кругу: по возрастанию, по убыванию
        /// и назад в порядок обхода носителей — он сам по себе осмыслен (сначала контейнеры CSP,
        /// потом каждый носитель со своими строками), и терять его насовсем не хочется.
        /// Сортировка переживает «Обновить»: сравниватель остаётся на списке, и новые строки
        /// встают на свои места сразу.
        /// </summary>
        private void SortByColumn(int column)
        {
            if (column == _sortColumn && _sortDesc) { _sortColumn = -1; _sortDesc = false; }
            else if (column == _sortColumn) _sortDesc = true;
            else { _sortColumn = column; _sortDesc = false; }

            _lv.ListViewItemSorter = new RowComparer(_sortColumn, _sortDesc);
            _lv.Sort();
            ApplyColumnHeaders();
        }

        /// <summary>
        /// Объяснить в самом списке, почему в нём нет ни одного контейнера. Считаются именно
        /// контейнерные строки: строка «только устройство» список наполняет, но показывать в
        /// нём всё равно нечего, — а по общему числу строк объяснение никогда бы и не
        /// показалось (замечание Codex на PR #83). Что именно написать, решает
        /// <see cref="ListEmptyHint"/>: причин три и действия у них разные.
        /// </summary>
        private void SetEmptyHint(int? carriers, int pkcs11Tokens = 0,
                                  int uncoveredCarriers = 0, bool scanFailed = false)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action(
                    () => SetEmptyHint(carriers, pkcs11Tokens, uncoveredCarriers, scanFailed)));
                return;
            }
            if (carriers == null) { _emptyHintKey = null; ApplyEmptyHint(); return; }

            int containers = 0;
            foreach (ListViewItem row in _allRows)
                if (ListEmptyHint.IsContainerRow(RowKind(row.Tag))) containers++;

            _emptyHintKey = ListEmptyHint.KeyFor(containers, carriers.Value, pkcs11Tokens,
                                                 uncoveredCarriers, scanFailed);
            ApplyEmptyHint();
        }

        /// <summary>
        /// Самопроверка для --selftest: показать объяснение, чтобы его текст попал в общую
        /// проверку переводов. Все причины проверяются на каждом языке — иначе пропавший ключ
        /// был бы виден только на машине без единого носителя.
        /// </summary>
        internal void PreviewEmptyHint(string key)
        {
            _emptyHintKey = key;
            ApplyEmptyHint();
        }

        /// <summary>
        /// Показать объяснение на действующем языке — и после смены языка тоже. Пустой список
        /// подпись занимает целиком: показывать там больше нечего. Если строки устройств есть,
        /// она встаёт полосой под ними — сами устройства видеть нужно, они и есть половина
        /// ответа на вопрос «почему пусто».
        /// </summary>
        private void ApplyEmptyHint()
        {
            if (_lblEmpty == null) return;
            // Список пуст из-за поиска — это другое дело: обход прошёл, строки есть, их просто
            // не видно. Звать вставить носитель тут было бы неправдой.
            string key = _allRows.Count > 0 && _lv.Items.Count == 0
                ? "list.empty.filter"
                : _emptyHintKey;

            _lblEmpty.Text = key == null ? string.Empty : Strings.Get(key);
            _lblEmpty.Visible = key != null;
            if (!_lblEmpty.Visible) { _lv.Visible = true; return; }

            // Пустой список подпись занимает целиком — сам список тогда прячем, показывать
            // в нём нечего и его заголовки только мешали бы читать объяснение. Если строки
            // устройств есть, они остаются на месте, а подпись встаёт полосой под ними.
            bool wholeList = _lv.Items.Count == 0;
            _lblEmpty.Dock = wholeList ? DockStyle.Fill : DockStyle.Bottom;
            _lv.Visible = !wholeList;
            SizeEmptyHint();
        }

        /// <summary>
        /// Высота полосы с объяснением: текст переносится по ширине панели, и сколько строк
        /// получится, известно только после замера. AutoSize не годится (меряет без переноса
        /// и перекрывает список), а пересчёт защищён флагом: присвоение высоты само вызывает
        /// раскладку, и без него получилась бы та же петля, что от вложенных AutoSize-панелей
        /// (AGENTS п. 46).
        /// </summary>
        private void SizeEmptyHint()
        {
            if (_sizingHint || _lblEmpty == null || !_lblEmpty.Visible) return;
            if (_lblEmpty.Dock != DockStyle.Bottom) return;

            _sizingHint = true;
            try
            {
                var panel = _split.Panel1;
                int width = Math.Max(160, panel.ClientSize.Width - panel.Padding.Horizontal);
                int height = _lblEmpty.GetPreferredSize(new Size(width, 0)).Height;
                if (_lblEmpty.Height != height) _lblEmpty.Height = height;
            }
            finally { _sizingHint = false; }
        }

        /// <summary>Заголовки колонок с отметкой сортировки на текущей.</summary>
        private void ApplyColumnHeaders()
        {
            string Mark(int index, string key)
            {
                string text = Strings.Get(key);
                return index == _sortColumn ? text + (_sortDesc ? " ▼" : " ▲") : text;
            }

            _colWhere.Text = Mark(0, "col.location");
            _colBackend.Text = Mark(1, "col.backend");
            _colName.Text = Mark(2, "col.container");
            _colDetails.Text = Mark(3, "col.details");
        }

        /// <summary>
        /// Сравниватель строк списка. Равные значения колонки оставляет в порядке обхода:
        /// иначе одинаковые «PKCS#11» перемешивались бы при каждой сортировке, и найти
        /// прежнюю строку было бы нельзя.
        /// </summary>
        private sealed class RowComparer : System.Collections.IComparer
        {
            private readonly int _column;
            private readonly bool _desc;

            public RowComparer(int column, bool desc) { _column = column; _desc = desc; }

            public int Compare(object x, object y)
            {
                var a = (ListViewItem)x;
                var b = (ListViewItem)y;
                int order = 0;
                if (_column >= 0 && _column < a.SubItems.Count && _column < b.SubItems.Count)
                {
                    order = string.Compare(a.SubItems[_column].Text, b.SubItems[_column].Text,
                                           StringComparison.CurrentCultureIgnoreCase);
                    if (_desc) order = -order;
                }
                return order != 0 ? order : string.CompareOrdinal(a.Name, b.Name);
            }
        }

        /// <summary>
        /// Прочитать текст поля с потока окна. Действия идут в <see cref="Task.Run"/>, а
        /// свойства контролов из чужого потока трогать нельзя: при закрытии окна или
        /// пересоздании хендла обращение бросает ObjectDisposedException, и операция падает
        /// на ровном месте. Остальные обращения к UI (список, диалоги) уже идут через Invoke.
        /// </summary>
        private string TextOf(TextBox box)
        {
            if (InvokeRequired) return (string)Invoke(new Func<string>(() => TextOf(box)));
            return box.Text;
        }

        /// <summary>Имя и Tag одной строки снимаются одним UI-вызовом, без selection race.</summary>
        private ContainerSelection SelectedContainer()
        {
            if (InvokeRequired)
                return (ContainerSelection)Invoke(new Func<ContainerSelection>(SelectedContainer));
            if (_lv.SelectedItems.Count == 0) return null;
            ListViewItem item = _lv.SelectedItems[0];
            bool deviceOnly = item.Tag is TokenDeviceSelection;
            var csp = item.Tag as CspContainerSelection;
            return new ContainerSelection
            {
                Name = deviceOnly ? null : item.SubItems[2].Text,
                Target = deviceOnly ? null : csp?.Target ?? item.SubItems[2].Text,
                Location = item.SubItems[0].Text,
                Backend = item.SubItems[1].Text,
                Details = item.SubItems[3].Text,
                IsCsp = item.Tag is CspContainerSelection,
                Token = item.Tag as TokenCertificateSelection,
                Apdu = item.Tag as ApduContainerSelection,
                Direct = item.Tag as RutokenContainer,
            };
        }

        private void Log(string msg) => Log(LogLevel.Information, msg);
        private void LogDebug(string msg) => Log(LogLevel.Debug, msg);
        private void LogWarning(string msg) => Log(LogLevel.Warning, msg);
        private void LogError(string msg) => Log(LogLevel.Error, msg);

        private void Log(LogLevel level, string msg)
        {
            SessionLog.Write(msg, level);
            AppendLog(level, msg);
        }

        private void AppendLog(LogLevel level, string msg)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AppendLog(level, msg))); return; }
            _logEntries.Add((level, msg));
            if (!LogLevels.IsVisible(level, _minimumLogLevel)) return;
            AppendVisibleLog(level, msg);
        }

        private void AppendVisibleLog(LogLevel level, string msg)
        {
            _txtLog.AppendText(VisibleLogLine(level, msg) + Environment.NewLine);
            // Со свёрнутой панелью журнал виден одной последней строкой в строке состояния.
            // Пустые строки — это отбивки между разделами: держим на месте предыдущую строку,
            // иначе после каждого раздела состояние обнулялось бы в пустоту.
            if (string.IsNullOrWhiteSpace(msg)) return;
            _lastLog.Text = OneLine(VisibleLogLine(level, msg));
            // Строка состояния узкая — целиком сообщение показывает своя подсказка.
            _lastLog.ToolTipText = _lastLog.Text;
            ShowLastLogLine();
        }

        /// <summary>INFO остаётся без шума; уровни, требующие внимания, помечаются явно.</summary>
        private static string VisibleLogLine(LogLevel level, string message) => level == LogLevel.Information
            ? message
            : "[" + LogLevels.Tag(level) + "] " + message;

        private void RebuildVisibleLog()
        {
            if (InvokeRequired) { BeginInvoke(new Action(RebuildVisibleLog)); return; }
            _txtLog.Clear();
            _lastLog.Text = string.Empty;
            _lastLog.ToolTipText = string.Empty;
            foreach (var entry in _logEntries)
                if (LogLevels.IsVisible(entry.Level, _minimumLogLevel))
                    AppendVisibleLog(entry.Level, entry.Message);
            ShowLastLogLine();
        }

        /// <summary>
        /// Показывать последнюю строку журнала рядом с состоянием, только если она добавляет
        /// новое. Половина шагов пишет в журнал ровно то же, что уходит в состояние
        /// («Обновление списка контейнеров…», «Готово»), и рядом это читалось бы как сбой.
        /// При развёрнутом журнале строка не нужна вовсе — весь текст и так на виду.
        /// </summary>
        private void ShowLastLogLine()
        {
            if (InvokeRequired) { BeginInvoke(new Action(ShowLastLogLine)); return; }
            _lastLog.Visible = _split.Panel2Collapsed
                               && !string.IsNullOrWhiteSpace(_lastLog.Text)
                               && !SameLine(_lastLog.Text, _status.Text);
        }

        /// <summary>Одна и та же мысль с точкой на конце и без неё — это одна строка.</summary>
        private static bool SameLine(string a, string b)
        {
            static string Core(string s) => (s ?? string.Empty).Trim().TrimEnd('.', '…', ':');
            return string.Equals(Core(a), Core(b), StringComparison.CurrentCultureIgnoreCase);
        }

        /// <summary>
        /// Строка состояния — одна строка: переводы строк в ней превращаются в пробелы, а
        /// слишком длинное сообщение обрезается. Полный текст всегда остаётся в журнале.
        /// </summary>
        private static string OneLine(string msg)
        {
            string s = msg.Replace('\r', ' ').Replace('\n', ' ').Trim();
            while (s.Contains("  ", StringComparison.Ordinal)) s = s.Replace("  ", " ", StringComparison.Ordinal);
            return s.Length > 200 ? s.Substring(0, 200) + "…" : s;
        }

        /// <summary>
        /// Развернуть или свернуть журнал. Свёрнут он по умолчанию (ROADMAP, P2, п. 5): половину
        /// окна он занимал всегда, а нужен целиком только при разборе. Высота, на которой журнал
        /// оставили, запоминается — второй разворот возвращает её, а не половину окна.
        /// </summary>
        private void ToggleLogPane()
        {
            if (_split.Panel2Collapsed)
            {
                _split.Panel2Collapsed = false;
                // Только теперь у Panel2 есть высота: до разворота SplitContainer молча
                // обрезал бы SplitterDistance по фактическому (нулевому) размеру панели.
                int room = _split.Height - _split.SplitterWidth - _split.Panel2MinSize;
                if (room > _split.Panel1MinSize)
                {
                    int want = _logSplit > 0 ? _logSplit : _split.Height / 2;
                    _split.SplitterDistance = Math.Clamp(want, _split.Panel1MinSize, room);
                }
            }
            else
            {
                _logSplit = _split.SplitterDistance;
                _split.Panel2Collapsed = true;
            }

            ApplyLogPaneState();
        }

        /// <summary>Надпись переключателя и видимость последней строки — по состоянию панели.</summary>
        private void ApplyLogPaneState()
        {
            bool collapsed = _split.Panel2Collapsed;
            SetButton(_btnLogPane, collapsed ? "btn.logpane.show" : "btn.logpane.hide", "tip.logpane");
            ShowLastLogLine();
        }

        /// <summary>
        /// Переключить фильтр по кругу. Уже полученные DEBUG-строки не теряются: они остаются
        /// в файле и памяти сеанса и появляются, если включить подробный режим позже.
        /// </summary>
        private void CycleLogLevel()
        {
            _minimumLogLevel = LogLevels.Next(_minimumLogLevel);
            ApplyLogLevelState(rebuild: true);
        }

        private void ApplyLogLevelState(bool rebuild)
        {
            _btnLogLevel.Text = Strings.Format("btn.loglevel", Strings.Get(LogLevels.NameKey(_minimumLogLevel)));
            Tip(_btnLogLevel, "tip.loglevel");
            if (rebuild) RebuildVisibleLog();
            FitButtonGroups();
        }

        /// <summary>
        /// Спросить папку назначения — в момент экспорта, а не в постоянной панели окна
        /// (ROADMAP, P2, п. 8). Выбор запоминается на сессию и подставляется в следующий раз:
        /// подряд идущие шаги одного конвейера ведут в одно место. Возвращает <c>null</c>,
        /// если пользователь отказался.
        /// </summary>
        private string AskDestination()
        {
            string picked = AskFolder(Strings.Get("dlg.folder.dest"), _dest);
            if (picked != null) _dest = picked;
            return picked;
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
