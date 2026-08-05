using System;
using System.Drawing;
using System.IO;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    /// <summary>
    /// Встроенное руководство: лежит в сборке ресурсом, поэтому доступно и у портативного
    /// exe без единого соседнего файла. Показывается кнопкой «Справка» и командой <c>help</c>.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class Guide
    {
        /// <summary>Окно со справкой: моноширинный текст, копируется, закрывается по Esc.</summary>
        public static void Show(IWin32Window owner)
        {
            string text = GuideText.Value;
            if (string.IsNullOrWhiteSpace(text))
            {
                MessageBox.Show(owner, "Руководство не вшито в эту сборку.", "Справка",
                                MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            using var form = new Form
            {
                Text = "Справка — Экспорт ключей КриптоПро с Рутокена",
                StartPosition = FormStartPosition.CenterParent,
                ClientSize = new Size(720, 620),
                MinimumSize = new Size(520, 400),
                ShowInTaskbar = false,
                Font = new Font("Segoe UI", 9f),
            };
            form.Icon = (owner as Form)?.Icon;

            var box = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                WordWrap = true,
                Font = new Font("Consolas", 9.5f),
                BackColor = Color.White,
                Text = text.Replace("\r\n", "\n").Replace("\n", Environment.NewLine),
            };

            var bottom = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft,
                Height = 46, Padding = new Padding(10, 8, 10, 8),
            };
            var close = new Button { Text = "Закрыть", Width = 100, Height = 30, DialogResult = DialogResult.OK };
            bottom.Controls.Add(close);

            form.Controls.Add(box);
            form.Controls.Add(bottom);
            form.AcceptButton = close;
            form.CancelButton = close;

            box.SelectionStart = 0;
            box.SelectionLength = 0;
            form.ShowDialog(owner);
        }
    }
}
