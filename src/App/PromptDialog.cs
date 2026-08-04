using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    /// <summary>Модальный ввод одной строки (имя контейнера, пароль PFX) — в WinForms своего InputBox нет.</summary>
    [SupportedOSPlatform("windows")]
    internal static class PromptDialog
    {
        /// <summary>Показать диалог. Возвращает введённое значение или null, если пользователь отменил.</summary>
        public static string Ask(IWin32Window owner, string title, string prompt,
                                 string initialValue = "", bool password = false)
        {
            using var form = new Form
            {
                Text = title,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false,
                ClientSize = new Size(460, 130),
                Font = new Font("Segoe UI", 9f),
            };

            var label = new Label
            {
                Text = prompt, AutoSize = false,
                Bounds = new Rectangle(12, 12, 436, 36),
            };
            var input = new TextBox
            {
                Text = initialValue ?? "",
                UseSystemPasswordChar = password,
                Bounds = new Rectangle(12, 52, 436, 24),
            };
            var ok = new Button
            {
                Text = "OK", DialogResult = DialogResult.OK,
                Bounds = new Rectangle(272, 88, 84, 30),
            };
            var cancel = new Button
            {
                Text = "Отмена", DialogResult = DialogResult.Cancel,
                Bounds = new Rectangle(364, 88, 84, 30),
            };

            form.Controls.AddRange(new Control[] { label, input, ok, cancel });
            form.AcceptButton = ok;
            form.CancelButton = cancel;

            return form.ShowDialog(owner) == DialogResult.OK ? input.Text : null;
        }
    }
}
