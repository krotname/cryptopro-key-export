using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    /// <summary>
    /// Модальный выбор одного из нескольких способов сделать одно и то же. Нужен там, где
    /// действие одно, а файлы получаются разные: две кнопки в ленте объясняли разницу только
    /// подсказкой, и владелец узнавал о ней уже после экспорта (ROADMAP, P2, п. 4).
    ///
    /// У каждого варианта своя кнопка, под ней — то же пояснение, что было в подсказке кнопки.
    /// Недоступный сейчас вариант гасится, а причина пишется на его месте: как и в главном окне,
    /// отказ виден до нажатия, а не сообщением в журнале после (AGENTS п. 45 — то же правило).
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class ChoiceDialog
    {
        /// <summary>Вариант выбора: надпись кнопки, пояснение и причина отказа (null — вариант доступен).</summary>
        internal readonly struct Option
        {
            public Option(string title, string details, string reason = null)
            {
                Title = title;
                Details = details;
                Reason = reason;
            }

            public string Title { get; }
            public string Details { get; }
            public string Reason { get; }
        }

        /// <summary>
        /// Показать диалог. Возвращает индекс выбранного варианта или −1, если пользователь
        /// отказался (кнопка «Отмена», Esc или закрытие окна).
        /// </summary>
        public static int Ask(IWin32Window owner, string title, string prompt, params Option[] options)
        {
            if (options == null || options.Length == 0) return -1;

            bool rtl = Strings.CurrentIsRightToLeft;
            using var form = new Form
            {
                Text = title,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Font = new Font("Segoe UI", 9f),
                RightToLeft = rtl ? RightToLeft.Yes : RightToLeft.No,
                RightToLeftLayout = rtl,
            };

            // Ширина задаётся один раз здесь: пояснения многострочные, и без общей ширины
            // каждая строка тянула бы окно на свою длину.
            const int TextWidth = 460;

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, ColumnCount = 1,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12, 12, 12, 8),
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

            layout.Controls.Add(new Label
            {
                Text = prompt, AutoSize = true, MaximumSize = new Size(TextWidth, 0),
                Margin = new Padding(3, 3, 3, 12),
            });

            int chosen = -1;
            var buttons = new List<Button>();
            for (int i = 0; i < options.Length; i++)
            {
                Option option = options[i];
                var button = new Button
                {
                    Text = option.Title, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                    MinimumSize = new Size(180, 34), Padding = new Padding(12, 0, 12, 0),
                    Margin = new Padding(3, 0, 3, 2),
                    Enabled = option.Reason == null,
                };
                int index = i;
                button.Click += (_, __) =>
                {
                    chosen = index;
                    form.DialogResult = DialogResult.OK;
                };
                buttons.Add(button);
                layout.Controls.Add(button);

                string details = option.Reason ?? option.Details;
                layout.Controls.Add(new Label
                {
                    Text = details, AutoSize = true, MaximumSize = new Size(TextWidth, 0),
                    // Причина серым не пишется: она объясняет отказ, и её нужно заметить.
                    ForeColor = option.Reason == null ? SystemColors.GrayText : SystemColors.ControlText,
                    Margin = new Padding(3, 0, 3, 14),
                });
            }

            var cancel = new Button
            {
                Text = Strings.Get("common.cancel"), DialogResult = DialogResult.Cancel,
                AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                MinimumSize = new Size(96, 30), Padding = new Padding(10, 0, 10, 0),
                Anchor = AnchorStyles.Right, Margin = new Padding(3, 6, 3, 3),
            };
            layout.Controls.Add(cancel);

            form.Controls.Add(layout);
            form.CancelButton = cancel;
            // Первый доступный вариант — под Enter: обычно он же и нужен.
            form.AcceptButton = buttons.Find(b => b.Enabled);

            return form.ShowDialog(owner) == DialogResult.OK ? chosen : -1;
        }
    }
}
