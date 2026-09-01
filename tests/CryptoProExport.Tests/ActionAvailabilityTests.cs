using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Доступность кнопок по выделенной строке. Таблица маленькая, но именно она решает,
    /// увидит ли владелец погашенную кнопку вместо сообщения в журнале после нажатия,
    /// поэтому проверяется целиком: и разрешения, и запреты, и причины.
    /// </summary>
    public class ActionAvailabilityTests
    {
        private static readonly RowAction[] AllActions =
            Enum.GetValues<RowAction>();

        private static readonly SelectedRow[] AllRows =
            Enum.GetValues<SelectedRow>();

        [Theory]
        // Снятие с носителя: без выделения обходятся все токены, иначе нужна строка
        // прямого чтения — APDU или legacy rtCOMLite.
        [InlineData(RowAction.Export, SelectedRow.None)]
        [InlineData(RowAction.Export, SelectedRow.Apdu)]
        [InlineData(RowAction.Export, SelectedRow.Direct)]
        [InlineData(RowAction.MakeExportable, SelectedRow.None)]
        [InlineData(RowAction.MakeExportable, SelectedRow.Apdu)]
        [InlineData(RowAction.MakeExportable, SelectedRow.Direct)]
        // Действиям по одному контейнеру годится строка любого источника, кроме устройства.
        [InlineData(RowAction.ExtractCert, SelectedRow.Csp)]
        [InlineData(RowAction.ExtractCert, SelectedRow.TokenWithCert)]
        [InlineData(RowAction.ExtractCert, SelectedRow.Apdu)]
        [InlineData(RowAction.ExtractCert, SelectedRow.Direct)]
        [InlineData(RowAction.ViewContainer, SelectedRow.Csp)]
        [InlineData(RowAction.ViewContainer, SelectedRow.TokenWithCert)]
        [InlineData(RowAction.ViewContainer, SelectedRow.TokenWithoutCert)]
        [InlineData(RowAction.ViewContainer, SelectedRow.Apdu)]
        [InlineData(RowAction.ViewContainer, SelectedRow.Direct)]
        [InlineData(RowAction.ExportPfx, SelectedRow.Csp)]
        [InlineData(RowAction.ExportPfx, SelectedRow.TokenWithCert)]
        [InlineData(RowAction.ExportPfx, SelectedRow.TokenWithoutCert)]
        [InlineData(RowAction.ExportPfx, SelectedRow.Apdu)]
        [InlineData(RowAction.ExportPfx, SelectedRow.Direct)]
        public void Allowed_HasNoReason(RowAction action, SelectedRow row)
        {
            Assert.Null(ActionAvailability.ReasonKey(action, row));
            Assert.True(ActionAvailability.IsAllowed(action, row));
        }

        [Theory]
        // Строка КриптоПро и строка PKCS#11 не дают доступа к файлам контейнера на носителе,
        // и причины у них разные: одна про CSP, вторая про публичные объекты PKCS#11.
        [InlineData(RowAction.Export, SelectedRow.Csp, "hint.row.csp")]
        [InlineData(RowAction.MakeExportable, SelectedRow.Csp, "hint.row.csp")]
        [InlineData(RowAction.Export, SelectedRow.TokenWithCert, "hint.row.pkcs11")]
        [InlineData(RowAction.Export, SelectedRow.TokenWithoutCert, "hint.row.pkcs11")]
        [InlineData(RowAction.MakeExportable, SelectedRow.TokenWithCert, "hint.row.pkcs11")]
        [InlineData(RowAction.MakeExportable, SelectedRow.TokenWithoutCert, "hint.row.pkcs11")]
        // Действию по одному контейнеру нужна выделенная строка.
        [InlineData(RowAction.ExtractCert, SelectedRow.None, "hint.need.row")]
        [InlineData(RowAction.ViewContainer, SelectedRow.None, "hint.need.row")]
        [InlineData(RowAction.ExportPfx, SelectedRow.None, "hint.need.row")]
        // Сертификата в строке нет — извлекать нечего, и это известно до нажатия.
        [InlineData(RowAction.ExtractCert, SelectedRow.TokenWithoutCert, "hint.cert.none")]
        public void Denied_NamesTheReason(RowAction action, SelectedRow row, string reason)
        {
            Assert.Equal(reason, ActionAvailability.ReasonKey(action, row));
            Assert.False(ActionAvailability.IsAllowed(action, row));
        }

        [Fact]
        public void DeviceRow_BlocksEveryAction()
        {
            // Строка «только устройство» есть у пустого слота PKCS#11 и у считывателя без
            // библиотеки: контейнера в ней нет ни для одного действия.
            foreach (RowAction action in AllActions)
                Assert.Equal("hint.row.device", ActionAvailability.ReasonKey(action, SelectedRow.Device));
        }

        [Fact]
        public void EveryReason_IsTranslatedInAllTwentyLanguages()
        {
            foreach (string key in Reasons())
                foreach (string language in Strings.Available)
                {
                    Assert.True(Strings.Table(language).TryGetValue(key, out string value),
                                $"{language}: нет ключа {key}");
                    Assert.False(string.IsNullOrWhiteSpace(value), $"{language}: пустое значение {key}");
                }
        }

        [Fact]
        public void EveryReason_ExplainsWhatToDo()
        {
            // Причина без выхода бесполезна: владелец должен понять, какую строку выбрать.
            foreach (string key in Reasons())
            {
                string text = Strings.Table("ru")[key];
                Assert.Contains("Сейчас недоступно", text, StringComparison.Ordinal);
                Assert.Contains("Выберите", text, StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void RowSensitiveButtons_AreWiredInTheWindow()
        {
            // Таблица бесполезна, если окно её не спрашивает: сверяем, что каждая
            // зависящая от строки кнопка объявлена в MainForm со своим действием.
            string gui = File.ReadAllText(RepoFile("src", "App", "MainForm.cs"));
            foreach (string wiring in new[]
                     {
                         "(_btnExport, RowAction.Export)",
                         "(_btnFull, RowAction.MakeExportable)",
                         "(_btnExtract, RowAction.ExtractCert)",
                         "(_btnView, RowAction.ViewContainer)",
                         "(_btnPfx, RowAction.ExportPfx)",
                     })
                Assert.Contains(wiring, gui, StringComparison.Ordinal);

            // Доступность пересчитывается и по смене выделения, и по смене занятости.
            Assert.Contains("_lv.SelectedIndexChanged += (_, __) => UpdateRowActions();", gui, StringComparison.Ordinal);
        }

        [Fact]
        public void WindowKeepsItsOwnChecks_SoASelectionRaceCannotSlipThrough()
        {
            // Строку читает фоновая задача уже после нажатия: выделение успевает смениться,
            // поэтому проверки внутри Do* остаются даже при погашенной кнопке.
            string gui = File.ReadAllText(RepoFile("src", "App", "MainForm.cs"));
            Assert.Contains("Log(Strings.Get(\"log.export.directonly\"));", gui, StringComparison.Ordinal);
            Assert.Contains("Log(Strings.Get(\"log.need.container\"));", gui, StringComparison.Ordinal);
        }

        /// <summary>Все причины отказа, которые умеет назвать таблица.</summary>
        private static IEnumerable<string> Reasons()
        {
            var keys = new SortedSet<string>(StringComparer.Ordinal);
            foreach (RowAction action in AllActions)
                foreach (SelectedRow row in AllRows)
                {
                    string reason = ActionAvailability.ReasonKey(action, row);
                    if (reason != null) keys.Add(reason);
                }
            Assert.Equal(
                new[] { "hint.cert.none", "hint.need.row", "hint.row.csp", "hint.row.device", "hint.row.pkcs11" },
                keys.ToArray());
            return keys;
        }

        private static string RepoFile(params string[] parts)
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "CryptoProExport.slnx")))
                dir = dir.Parent;
            Assert.NotNull(dir);

            string path = dir!.FullName;
            foreach (string part in parts) path = Path.Combine(path, part);
            Assert.True(File.Exists(path), "Не найден файл " + path);
            return path;
        }
    }
}
