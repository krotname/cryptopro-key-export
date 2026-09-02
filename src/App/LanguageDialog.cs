using System;
using System.Drawing;
using System.Runtime.Versioning;
using System.Windows.Forms;

namespace CryptoProExport.App
{
    /// <summary>
    /// Выбор языка интерфейса. Раньше список языков стоял отдельной строкой в постоянной панели
    /// окна, хотя выбирают его один раз (ROADMAP, P2, п. 8): место он занимал всегда, а нужен
    /// был однажды. Теперь это модальный диалог за кнопкой «Язык…» в служебной группе.
    ///
    /// Окно собирается отдельно от показа (<see cref="Build"/>): так его строит и проверяет
    /// <c>--selftest</c> — иначе подсказки и переводы этого окна не проверялись бы ничем,
    /// потому что в дерево главной формы оно не входит (замечание Codex на PR #86).
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class LanguageDialog
    {
        /// <summary>
        /// Собрать окно на действующем языке. Список языков лежит в <see cref="Form.Tag"/>:
        /// по нему <see cref="Ask"/> читает выбор, а самопроверка — подсказки и надписи.
        /// Подсказки живут в возвращённом <see cref="ToolTip"/>: он должен пережить окно.
        /// </summary>
        internal static Form Build(out ToolTip tips)
        {
            bool rtl = Strings.CurrentIsRightToLeft;
            var form = new Form
            {
                Text = Strings.Get("dlg.lang.title"),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false,
                ClientSize = new Size(380, 440),
                Font = new Font("Segoe UI", 9f),
                RightToLeft = rtl ? RightToLeft.Yes : RightToLeft.No,
                RightToLeftLayout = rtl,
            };

            var label = new Label
            {
                Text = Strings.Get("dlg.lang.prompt"), AutoSize = false,
                Bounds = new Rectangle(12, 12, 356, 52),
            };

            // ListBox, а не выпадающий список: языков двадцать, и видеть их сразу удобнее, чем
            // разворачивать. Двойной клик по строке равносилен «ОК» — так же, как в главном окне.
            var list = new ListBox
            {
                Bounds = new Rectangle(12, 70, 356, 318),
                IntegralHeight = false,
            };
            int current = 0;
            for (int i = 0; i < Strings.Available.Count; i++)
            {
                string code = Strings.Available[i];
                list.Items.Add(Strings.NativeName(code) + " (" + code + ")");
                if (string.Equals(code, Strings.Current, StringComparison.OrdinalIgnoreCase)) current = i;
            }
            list.SelectedIndex = current;

            var ok = new Button
            {
                Text = Strings.Get("common.ok"), DialogResult = DialogResult.OK,
                Bounds = new Rectangle(192, 398, 84, 30),
            };
            var cancel = new Button
            {
                Text = Strings.Get("common.cancel"), DialogResult = DialogResult.Cancel,
                Bounds = new Rectangle(284, 398, 84, 30),
            };
            list.DoubleClick += (_, __) =>
            {
                form.DialogResult = DialogResult.OK;
                form.Close();
            };

            tips = new ToolTip
            {
                AutoPopDelay = 30000, InitialDelay = 300, ReshowDelay = 100,
                ShowAlways = true, UseAnimation = false, UseFading = false,
            };
            tips.SetToolTip(list, Strings.Get("tip.lang"));
            tips.SetToolTip(ok, Strings.Get("tip.lang.ok"));
            tips.SetToolTip(cancel, Strings.Get("tip.lang.cancel"));

            form.Controls.AddRange(new Control[] { label, list, ok, cancel });
            form.AcceptButton = ok;
            form.CancelButton = cancel;
            form.Tag = list;
            return form;
        }

        /// <summary>
        /// Показать диалог. Возвращает выбранный код языка или <c>null</c>, если пользователь
        /// отказался (Esc, «Отмена», закрытие окна) либо выбрал тот же язык.
        /// </summary>
        public static string Ask(IWin32Window owner)
        {
            using var form = Build(out ToolTip tips);
            using (tips)
            {
                if (form.ShowDialog(owner) != DialogResult.OK) return null;
                if (form.Tag is not ListBox list) return null;
                int picked = list.SelectedIndex;
                if (picked < 0 || picked >= Strings.Available.Count) return null;
                string chosen = Strings.Available[picked];
                return string.Equals(chosen, Strings.Current, StringComparison.OrdinalIgnoreCase)
                    ? null
                    : chosen;
            }
        }
    }
}
