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
        private TextBox _txtP12, _txtDest, _txtPin, _txtLog;
        private ListView _lv;
        private SplitContainer _split;
        private ColumnHeader _colWhere, _colName, _colDetails;
        private Label _lblP12, _lblDest, _lblPin, _lblPinHint, _lblLang;
        private Button _btnP12, _btnDest;
        private Button _btnRefresh, _btnExport, _btnExtract, _btnFull, _btnInstall, _btnView, _btnPfx, _btnExtractKey, _btnExtractPfx, _btnLicense, _btnLogs, _btnHelp;
        private Button _btnCancel;
        private Button[] _actionButtons;
        private ComboBox _cmbLang;
        private ToolTip _tips;
        private ToolStripStatusLabel _status;
        private ToolStripProgressBar _progress;
        private CancellationTokenSource _cancellation;
        private bool _busy;

        private sealed class TokenCertificateSelection
        {
            public string Name;
            public string Serial;
            public byte[] Certificate;
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
            public string Details;
            public bool IsCsp;
            public TokenCertificateSelection Token;
            public ApduContainerSelection Apdu;
            public RutokenContainer Direct;
        }

        public MainForm()
        {
            BuildUi();
            ApplyTexts();
            _txtP12.Text = P12Utility.Locate() ?? "";
            _txtDest.Text = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "RutokenExport");
        }

        /// <summary>Список и журнал делят место пополам — журнал читают не реже перечня.</summary>
        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            if (_split.Height > 200) _split.SplitterDistance = _split.Height / 2;
        }

        /// <summary>После показа окна — сводка по зависимостям в лог (что вшито, чего не хватает).</summary>
        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Run("status.deps", () =>
            {
                Log(Strings.Get("log.deps.header"));
                foreach (var line in CryptoProExport.Diagnostics.Report())
                    Log("  " + line);
                Log(Strings.Format("log.session", SessionLog.FilePath));
                Log(LicenseGate.StatusText());
                // Отпечаток нужен, чтобы получить лицензию, — обещан в подсказке и README, показываем сразу.
                Log(LicenseGate.FingerprintText());
                Log("");
            });
        }

        private void BuildUi()
        {
            SetWindowIcon();
            Font = new Font("Segoe UI", 9f);
            ClientSize = new Size(880, 660);
            MinimumSize = new Size(720, 540);
            StartPosition = FormStartPosition.CenterScreen;

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
                Dock = DockStyle.Top, ColumnCount = 3, RowCount = 4,
                Padding = new Padding(10, 10, 10, 4),
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            };
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            _txtP12 = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(3, 4, 3, 4) };
            _txtDest = new TextBox { Dock = DockStyle.Fill, Margin = new Padding(3, 4, 3, 4) };
            _txtPin = new TextBox { Dock = DockStyle.Fill, UseSystemPasswordChar = true, Margin = new Padding(3, 4, 3, 4) };

            _lblP12 = MakeFieldLabel();
            settings.Controls.Add(_lblP12, 0, 0);
            settings.Controls.Add(_txtP12, 1, 0);
            _btnP12 = new Button { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill };
            _btnP12.Click += (_, __) => PickFile(_txtP12,
                "p12utility|p12utility*.exe|" + Strings.Get("files.all") + "|*.*");
            settings.Controls.Add(_btnP12, 2, 0);

            _lblDest = MakeFieldLabel();
            settings.Controls.Add(_lblDest, 0, 1);
            settings.Controls.Add(_txtDest, 1, 1);
            _btnDest = new Button { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Fill };
            _btnDest.Click += (_, __) => PickFolder(_txtDest);
            settings.Controls.Add(_btnDest, 2, 1);

            _lblPin = MakeFieldLabel();
            settings.Controls.Add(_lblPin, 0, 2);
            settings.Controls.Add(_txtPin, 1, 2);
            _lblPinHint = MakeFieldLabel();
            _lblPinHint.ForeColor = Color.Gray;
            settings.Controls.Add(_lblPinHint, 2, 2);

            _lblLang = MakeFieldLabel();
            settings.Controls.Add(_lblLang, 0, 3);
            _cmbLang = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Width = 260, Anchor = AnchorStyles.Left, Margin = new Padding(3, 4, 3, 4),
            };
            foreach (string code in Strings.Available) _cmbLang.Items.Add(new LanguageChoice(code));
            SelectCurrentLanguage();
            _cmbLang.SelectedIndexChanged += (_, __) => OnLanguagePicked();
            settings.Controls.Add(_cmbLang, 1, 3);

            // --- Панель кнопок ---
            var buttons = new FlowLayoutPanel
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
            _btnPfx = MakeButton((_, __) => Run("status.pfx", DoExportPfx));
            _btnExtractKey = MakeButton((_, __) => Run("status.extractkey", DoExtractKey));
            _btnExtractPfx = MakeButton((_, __) => Run("status.extractpfx", DoExtractPfx));
            _btnLicense = MakeButton((_, __) => DoLicense());
            _btnLogs = MakeButton((_, __) => OpenLogFolder());
            _btnHelp = MakeButton((_, __) => Guide.Show(this));
            _btnCancel = MakeButton((_, __) => CancelCurrent());
            _btnCancel.Enabled = false;
            _actionButtons = new[]
            {
                _btnRefresh, _btnExport, _btnExtract, _btnFull,
                _btnView, _btnInstall, _btnPfx, _btnExtractKey, _btnExtractPfx, _btnLicense, _btnLogs, _btnHelp,
            };
            buttons.Controls.AddRange(_actionButtons);
            buttons.Controls.Add(_btnCancel);

            // --- Список + лог ---
            // SplitterDistance выставляется в OnLoad: до раскладки высота панели ещё не известна,
            // и значение, заданное здесь, WinForms молча обрезает по фактическому размеру.
            var split = _split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };

            _lv = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                GridLines = true, MultiSelect = false, HideSelection = false,
            };
            _colWhere = new ColumnHeader { Width = 150 };
            _colName = new ColumnHeader { Width = 360 };
            _colDetails = new ColumnHeader { Width = 320 };
            _lv.Columns.AddRange(new[] { _colWhere, _colName, _colDetails });
            split.Panel1.Controls.Add(_lv);
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
            _status = new ToolStripStatusLabel { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = 140 };
            var statusStrip = new StatusStrip { SizingGrip = false };
            statusStrip.Items.AddRange(new ToolStripItem[] { _status, _progress });

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

            _lblP12.Text = Strings.Get("field.p12");
            _lblDest.Text = Strings.Get("field.dest");
            _lblPin.Text = Strings.Get("field.pin");
            _lblPinHint.Text = Strings.Get("field.pin.hint");
            _lblLang.Text = Strings.Get("field.lang");
            _btnP12.Text = Strings.Get("common.browse");
            _btnDest.Text = Strings.Get("common.browse");
            _txtP12.PlaceholderText = Strings.Get("field.p12.placeholder");

            Tip(_lblP12, "tip.p12"); Tip(_txtP12, "tip.p12"); Tip(_btnP12, "tip.p12.browse");
            Tip(_lblDest, "tip.dest"); Tip(_txtDest, "tip.dest"); Tip(_btnDest, "tip.dest.browse");
            Tip(_lblPin, "tip.pin"); Tip(_txtPin, "tip.pin"); Tip(_lblPinHint, "tip.pin");
            Tip(_lblLang, "tip.lang"); Tip(_cmbLang, "tip.lang");

            SetButton(_btnRefresh, "btn.refresh", "tip.refresh");
            SetButton(_btnExport, "btn.export", "tip.export");
            SetButton(_btnExtract, "btn.extract", "tip.extract");
            SetButton(_btnFull, "btn.full", "tip.full");
            SetButton(_btnView, "btn.check", "tip.check");
            SetButton(_btnInstall, "btn.install", "tip.install");
            SetButton(_btnPfx, "btn.pfx", "tip.pfx");
            SetButton(_btnExtractKey, "btn.extractkey", "tip.extractkey");
            SetButton(_btnExtractPfx, "btn.extractpfx", "tip.extractpfx");
            SetButton(_btnLicense, "btn.license", "tip.license");
            SetButton(_btnLogs, "btn.logs", "tip.logs");
            SetButton(_btnHelp, "btn.help", "tip.help");
            SetButton(_btnCancel, "btn.cancel", "tip.cancel");

            // Общие названия кнопок исторически говорят «с токена». Явно добавляем границу
            // аппаратного ЭЦП прямо в обе подсказки на каждом из 20 языков.
            string ecpBoundary = "\n\n" + Strings.Get("token.boundary.ecp");
            _tips.SetToolTip(_btnExport, _tips.GetToolTip(_btnExport) + ecpBoundary);
            _tips.SetToolTip(_btnFull, _tips.GetToolTip(_btnFull) + ecpBoundary);

            _colWhere.Text = Strings.Get("col.location");
            _colName.Text = Strings.Get("col.container");
            _colDetails.Text = Strings.Get("col.details");
            Tip(_lv, "tip.list");
            Tip(_txtLog, "tip.log");

            if (!_busy) _status.Text = Strings.Get("status.ready");
        }

        private void OnLanguagePicked()
        {
            if (_cmbLang.SelectedItem is not LanguageChoice choice) return;
            if (string.Equals(choice.Code, Strings.Current, StringComparison.OrdinalIgnoreCase)) return;
            Strings.Use(choice.Code);
            Strings.Remember(choice.Code);
            ApplyTexts();
            Log(Strings.Format("log.lang.changed", Strings.NativeName(choice.Code)));
        }

        /// <summary>
        /// Переключить язык уже построенного окна — ровно то, что делает выбор в списке,
        /// но без запоминания выбора. Нужно самопроверке: она гоняет одно окно по всем языкам,
        /// проверяя, что повторная раскладка надписей (и смена RightToLeftLayout) не ломает форму.
        /// </summary>
        internal void SwitchLanguage(string code)
        {
            if (!Strings.Use(code)) return;
            SelectCurrentLanguage();
            ApplyTexts();
        }

        private void SelectCurrentLanguage()
        {
            for (int i = 0; i < _cmbLang.Items.Count; i++)
            {
                if (_cmbLang.Items[i] is LanguageChoice c &&
                    string.Equals(c.Code, Strings.Current, StringComparison.OrdinalIgnoreCase))
                {
                    _cmbLang.SelectedIndex = i;
                    return;
                }
            }
            if (_cmbLang.Items.Count > 0) _cmbLang.SelectedIndex = 0;
        }

        /// <summary>Строка списка языков: код скрыт в объекте, пользователю видно родное название.</summary>
        private sealed class LanguageChoice
        {
            public LanguageChoice(string code) => Code = code;
            public string Code { get; }
            public override string ToString() => Strings.NativeName(Code) + " (" + Code + ")";
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
        internal (int withTip, List<string> missing) CheckTooltips()
        {
            var missing = new List<string>();
            int withTip = 0;

            Walk(this, c =>
            {
                if (c is not (Button or TextBox or ListView or ComboBox)) return;
                if (string.IsNullOrWhiteSpace(_tips.GetToolTip(c))) missing.Add($"{c.GetType().Name} \"{c.Text}\"");
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
            Check("Placeholder", _txtP12.PlaceholderText);
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
            Invoke(() => _lv.Items.Clear());
            Log(Strings.Get("status.refresh"));

            // HDIMAGE-копия и исходный токен часто имеют одно логическое имя. Показываем
            // файловую копию отдельной строкой и адресуем её полным именем, иначе CryptoAPI
            // снова выбирает токен и показывает старые права ключа.
            var installedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in ContainerStore.Installed())
            {
                if (!installedNames.Add(c.Name)) continue;
                AddRow("HDIMAGE", c.Name, c.Folder,
                    new CspContainerSelection { Target = CertMgr.HdImageContainer(c.Name) });
            }
            foreach (var c in CertFromContainer.EnumContainers())
            {
                if (installedNames.Contains(c.Name)) continue;
                AddRow(Strings.Get("log.container.csp"), c.Name,
                       Strings.Format("log.container.provider", c.ProvType),
                       new CspContainerSelection { Target = c.Name });
            }

            // Токены по PKCS#11: метаданные и профиль механизмов видны без PIN;
            // публичные сертификаты показываются только когда реально присутствуют.
            cancel.ThrowIfCancellationRequested();
            var tokens = Pkcs11Token.Enumerate(readContainers: true, log: Log, cancel: cancel);
            Log("[PKCS#11] " + Strings.Format("token.found", tokens.Count));
            foreach (var t in tokens)
            {
                Log("  " + Strings.Format("cli.token.line",
                    t.Reader ?? "?", t.Label ?? "?", Pkcs11Token.KindName(t.Kind),
                    t.Serial ?? "?", t.Firmware ?? "?"));
                Log("    " + Strings.Format("cli.token.pin", Pkcs11Token.PinState(t)));
                Log("    " + Pkcs11Token.CapabilitySummary(t));
                if (t.Kind == RutokenKind.RutokenEcp)
                    Log("    " + Strings.Get("token.boundary.ecp"));

                bool hasDirectRow = false;
                foreach (var c in t.Containers)
                {
                    AddRow($"[PKCS#11] {t.Reader} [{Pkcs11Token.KindName(t.Kind)}]",
                           c.Name ?? Strings.Get("log.container.unnamed"),
                           "PKCS#11 · " + Strings.Get(c.CertificateOnly ? "common.certonly"
                                                      : c.Certificate != null ? "common.present" : "common.none"),
                           new TokenCertificateSelection
                           {
                               Name = c.Name,
                               Serial = t.Serial,
                               Certificate = c.Certificate,
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
                            { Log = m => Log("[APDU] " + m), Cancel = cancel };
                        foreach (var c in direct.ListContainers(t))
                        {
                            AddRow($"[APDU] {t.Reader} [{Pkcs11Token.KindName(t.Kind)}]",
                                   c.Name ?? Strings.Get("log.container.unnamed"),
                                   $"APDU · {Strings.Format("cli.token.pin", Pkcs11Token.PinState(t))}",
                                   new ApduContainerSelection { Token = t, Container = c });
                            hasDirectRow = true;
                        }
                    }
                    catch (Exception e)
                    {
                        Log("[APDU] " + Strings.Format("log.tokens.unavailable", e.Message));
                    }
                }

                // Пустой PKCS#11-слот всё равно показываем: пользователь должен видеть все
                // подключённые устройства, а не только те, где драйвер отдал публичный объект.
                if (!hasDirectRow)
                    AddRow($"[PKCS#11] {t.Reader} [{Pkcs11Token.KindName(t.Kind)}]",
                           Strings.Get("common.none"),
                           "PKCS#11 · " + Pkcs11Token.CapabilityProfileName(t.CapabilityProfile),
                           new TokenDeviceSelection());
            }

            cancel.ThrowIfCancellationRequested();
            try
            {
                var exp = new RutokenExporter
                {
                    Log = m => Log("[rtCOMLite] " + m),
                    Cancel = cancel,
                    SkipReaders = Pkcs11Token.SmartCardReaders(tokens),
                };
                foreach (var c in exp.ReadAllContainers())
                    AddRow(Strings.Format("log.container.token", c.TokenName),
                           c.ContainerName ?? Strings.Get("log.container.unnamed"),
                           Strings.Format("log.container.files", c.TokenDir, c.Files.Count), c);
            }
            catch (Exception e) { Log(Strings.Format("log.tokens.unavailable", e.Message)); }
            Log(Strings.Get("log.done"));
        }

        /// <summary>
        /// Гейт лицензии для операций экспорта закрытого ключа. Без действительной лицензии
        /// операция не выполняется; в журнал идут статус и отпечаток этой машины, чтобы было
        /// понятно, как получить лицензию (активация обменивает код на подписанный файл лицензии).
        /// </summary>
        private bool RequireLicense()
        {
            if (LicenseGate.IsLicensed()) return true;
            Log(Strings.Get("license.required"));
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
                Filter = Strings.Get("license.filter") + "|*.jws;*.lic;*.txt|"
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
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Log(Strings.Format("log.error", e.Message));
            }
        }

        private void DoExport(CancellationToken cancel)
        {
            if (!RequireLicense()) return;
            string dest = TextOf(_txtDest).Trim();
            if (string.IsNullOrEmpty(dest)) { Log(Strings.Get("log.need.dest")); return; }
            ContainerSelection selected = SelectedContainer();
            if (selected != null && selected.Apdu == null && selected.Direct == null)
            {
                Log(Strings.Get("log.export.directonly"));
                return;
            }
            var pipe = new ExportPipeline(NullIfEmpty(TextOf(_txtP12))) { Log = Log, Cancel = cancel };
            int saved;
            if (selected?.Apdu != null)
            {
                pipe.ExportDirectContainer(selected.Apdu.Token, selected.Apdu.Container,
                    dest, NullIfEmpty(TextOf(_txtPin)));
                saved = 1;
            }
            else if (selected?.Direct != null)
            {
                pipe.ExportContainer(selected.Direct, dest);
                saved = 1;
            }
            else
            {
                saved = pipe.ExportFromTokens(dest, NullIfEmpty(TextOf(_txtPin))).Count;
            }
            Log(Strings.Format("log.exported", saved));
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoExtract()
        {
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }
            string destRoot = TextOf(_txtDest).Trim();
            if (string.IsNullOrEmpty(destRoot)) { Log(Strings.Get("log.need.dest")); return; }
            string dest = Path.Combine(destRoot, "certs_" + Sanitize(selected.Name));

            // Для строки PKCS#11 сохраняем именно сертификат выбранного токена. Поиск заново
            // только по метке раньше брал первый попавшийся токен с тем же именем контейнера.
            var tokenSelection = selected.Token;
            if (tokenSelection != null)
            {
                if (tokenSelection.Certificate == null)
                {
                    Log(Strings.Get("log.cert.fail"));
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
                Log(Strings.Get("log.cert.fail"));
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
                        Log(Strings.Format("log.error", Strings.Get("err.container.exportable")));
                        return;
                    }
                }
                Log(Strings.Get("log.export.directonly"));
                return;
            }
            if (!RequireLicense()) return;
            string dest = TextOf(_txtDest).Trim();
            if (string.IsNullOrEmpty(dest)) { Log(Strings.Get("log.need.dest")); return; }
            var confirm = AskConfirm(
                Strings.Get(selected == null ? "dlg.confirm.full" : "dlg.confirm.full.selected"),
                Strings.Get("dlg.confirm.title"));
            if (confirm != DialogResult.OK) { Log(Strings.Get("log.cancelled.user")); return; }

            var pipe = new ExportPipeline(NullIfEmpty(TextOf(_txtP12))) { Log = Log, Cancel = cancel };
            ExportPipelineResult result;
            if (selected?.Apdu != null)
                result = pipe.ExportDirectAndMakeExportable(
                    selected.Apdu.Token, selected.Apdu.Container, dest,
                    userPin: NullIfEmpty(TextOf(_txtPin)));
            else if (selected?.Direct != null)
                result = pipe.ExportAndMakeExportable(selected.Direct, dest);
            else
                result = pipe.ExportAndMakeExportable(dest, userPin: NullIfEmpty(TextOf(_txtPin)));
            if (result.AllSucceeded) Log(Strings.Get("log.full.done"));
            else Log(Strings.Format("log.exported", result.Exported));
            RefreshList(cancel);   // из рабочего потока: внутри всё, что трогает UI, идёт через Invoke
        }

        private void DoViewContainer()
        {
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }
            var (ex, sg) = CheckExportability(container);
            Log(Strings.Format("log.check.container", container));
            Log("  " + Strings.Get("col.location") + ": " + selected.Location);
            Log("  " + Strings.Get("col.details") + ": " + selected.Details);
            Log("  " + Strings.Format("log.check.exchange", ex));
            Log("  " + Strings.Format("log.check.sign", sg));

            string text = Strings.Format("log.check.container", container) + Environment.NewLine
                        + Strings.Get("col.location") + ": " + selected.Location + Environment.NewLine
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

        private void DoInstall()
        {
            string folder = AskFolder(Strings.Get("dlg.folder.container"), TextOf(_txtDest).Trim());
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                Log(Strings.Get("log.install.notcontainer"));
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
                Log(Strings.Get("log.install.invisible"));
            else if (installed.VisibleToCsp)
            {
                string certMgrPath = CertMgr.Locate();
                if (certMgrPath != null)
                {
                    var cm = new CertMgr(certMgrPath) { Log = Log };
                    var linked = cm.InstallContainerCertificates(
                        folder, CertMgr.HdImageContainer(installed.Name));
                    foreach (ToolResult failure in linked.Results)
                        if (!failure.Success)
                            Log(Strings.Format("tool.certmgr.installwarn", failure.Explain()));
                }
            }
            RefreshList();
        }

        private void DoExportPfx(CancellationToken cancel)
        {
            if (!RequireLicense()) return;
            ContainerSelection selected = SelectedContainer();
            string container = selected?.Target;
            if (container == null) { Log(Strings.Get("log.need.container")); return; }

            string exe = CertMgr.Locate();
            if (exe == null) { Log(Strings.Get("log.pfx.nocertmgr")); return; }

            string dest = AskSaveFile(Strings.Get("dlg.pfx.save"),
                                      "PKCS#12 (*.pfx)|*.pfx|" + Strings.Get("files.all") + "|*.*",
                                      TextOf(_txtDest).Trim(), Sanitize(selected.Name) + ".pfx");
            if (dest == null) { Log(Strings.Get("log.cancelled")); return; }

            string pass = AskText(Strings.Get("dlg.pfx.pass.title"), Strings.Get("dlg.pfx.pass.prompt"),
                                  "", password: true);
            if (pass == null) { Log(Strings.Get("log.cancelled")); return; }

            var cm = new CertMgr(exe) { Log = Log, Cancel = cancel };
            var r = cm.ExportContainerToPfx(container, dest, pass);
            Log(r.Success ? Strings.Format("log.pfx.done", dest) : Strings.Format("log.pfx.fail", r.Output));
        }

        /// <summary>
        /// Извлечь закрытый ключ из файлового контейнера без CSP и сохранить в PKCS#8/PEM.
        /// В журнал пишутся только путь и открытый ключ: тело закрытого ключа — секрет.
        /// </summary>
        private void DoExtractKey()
        {
            if (!RequireLicense()) return;
            string folder = AskFolder(Strings.Get("dlg.folder.container"), TextOf(_txtDest).Trim());
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                Log(Strings.Get("log.install.notcontainer"));
                return;
            }

            string pass = AskText(Strings.Get("dlg.extractkey.pass.title"),
                                  Strings.Get("dlg.extractkey.pass.prompt"), "", password: true);
            if (pass == null) { Log(Strings.Get("log.cancelled")); return; }

            string dest = AskSaveFile(Strings.Get("dlg.extractkey.save"),
                                      "PEM (*.pem)|*.pem|" + Strings.Get("files.all") + "|*.*",
                                      TextOf(_txtDest).Trim(), "privatekey.pem", "pem");
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
                Log(Strings.Format("log.extractkey.fail", e.Message));
            }
        }

        /// <summary>
        /// Собрать .pfx из файлового контейнера без CSP: ключ из *.key, сертификат из header.key.
        /// Если сертификата в контейнере нет, спрашиваем файл .cer — остальное не меняется.
        /// </summary>
        private void DoExtractPfx()
        {
            if (!RequireLicense()) return;
            string folder = AskFolder(Strings.Get("dlg.folder.container"), TextOf(_txtDest).Trim());
            if (folder == null) { Log(Strings.Get("log.cancelled")); return; }
            if (!ContainerStore.LooksLikeContainer(folder))
            {
                Log(Strings.Get("log.install.notcontainer"));
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
                                      TextOf(_txtDest).Trim(), Sanitize(name) + ".pfx");
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
                // Ограничение говорим сразу и на месте: иначе владелец решит, что это
                // резервная копия, из которой ключ вернётся в КриптоПро (замечание Codex).
                Log("  " + Strings.Get("log.extractpfx.note"));
            }
            catch (ContainerKeyException e)
            {
                Log(Strings.Format("log.extractpfx.fail", e.Message));
            }
        }

        private void OpenLogFolder()
        {
            try
            {
                Directory.CreateDirectory(SessionLog.Dir);
                Process.Start(new ProcessStartInfo(SessionLog.Dir) { UseShellExecute = true });
            }
            catch (Exception ex) { Log(Strings.Format("log.logs.fail", ex.Message)); }
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
                catch (Exception ex) { Log(Strings.Format("log.error", ex.Message)); }
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
            _btnCancel.Enabled = busy;
            _cmbLang.Enabled = !busy;
            _progress.Visible = busy;
            _status.Text = busy ? title : Strings.Get("status.ready");
            Cursor = busy ? Cursors.WaitCursor : Cursors.Default;
        }

        private void SetStatus(string text)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => SetStatus(text))); return; }
            _status.Text = text;
        }

        private void AddRow(string where, string name, string details, object tag = null)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddRow(where, name, details, tag))); return; }
            _lv.Items.Add(new ListViewItem(new[] { where, name, details }) { Tag = tag });
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
                Name = deviceOnly ? null : item.SubItems[1].Text,
                Target = deviceOnly ? null : csp?.Target ?? item.SubItems[1].Text,
                Location = item.SubItems[0].Text,
                Details = item.SubItems[2].Text,
                IsCsp = item.Tag is CspContainerSelection,
                Token = item.Tag as TokenCertificateSelection,
                Apdu = item.Tag as ApduContainerSelection,
                Direct = item.Tag as RutokenContainer,
            };
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
