using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Объяснение списка без контейнеров (ROADMAP, P2, п. 7). Правило простое, но ошибиться
    /// в нём дорого: «вставьте носитель» на машине с воткнутым токеном отправляет владельца
    /// искать не там, а «поставьте драйверы» при работающей библиотеке — тем более.
    /// </summary>
    public class ListEmptyHintTests
    {
        [Fact]
        public void ListWithContainers_IsNotExplained()
        {
            Assert.Null(ListEmptyHint.KeyFor(containerRows: 1, carriers: 0, pkcs11Tokens: 0));
            Assert.Null(ListEmptyHint.KeyFor(containerRows: 13, carriers: 8, pkcs11Tokens: 8));
        }

        [Fact]
        public void WithoutCarriers_AsksToInsertOne()
        {
            Assert.Equal(ListEmptyHint.NoReaderKey,
                         ListEmptyHint.KeyFor(containerRows: 0, carriers: 0, pkcs11Tokens: 0));
        }

        /// <summary>
        /// Пустой считыватель — это «вставьте носитель», а не «нет библиотеки»: считыватель
        /// виден системе всегда, но строки в списке не даёт, потому что PcscReaders.Uncovered
        /// пропускает считыватель без карты (замечание Codex на PR #83). Поэтому на вход идёт
        /// число носителей, а не считывателей.
        /// </summary>
        [Fact]
        public void EmptySlot_IsNotBlamedOnTheLibrary()
        {
            var readers = new[]
            {
                new PcscReader { Name = "Aktiv Rutoken ECP 0", CardPresent = false },
                new PcscReader { Name = "BIFIT ANGARA 0", CardPresent = false },
            };
            var rows = PcscReaders.Uncovered(readers, new string[0]);
            Assert.Empty(rows);

            int carriers = 0;
            foreach (var r in readers) if (r.CardPresent) carriers++;
            Assert.Equal(ListEmptyHint.NoReaderKey,
                         ListEmptyHint.KeyFor(rows.Count, carriers, pkcs11Tokens: 0));
        }

        /// <summary>
        /// Носитель вставлен, ни одна библиотека его не показала. Строка `[PC/SC]` в списке
        /// при этом есть — но она не контейнерная, и объяснение должно показаться. Считать
        /// все строки подряд нельзя: тогда это сообщение недостижимо (второе замечание Codex
        /// на PR #83).
        /// </summary>
        [Fact]
        public void CarrierWithoutLibrary_BlamesTheMissingLibrary()
        {
            var readers = new[] { new PcscReader { Name = "BIFIT ANGARA 0", CardPresent = true, Atr = "3B ..." } };
            var deviceRows = PcscReaders.Uncovered(readers, new string[0]);
            Assert.Single(deviceRows);

            Assert.Equal(ListEmptyHint.NoLibraryKey,
                         ListEmptyHint.KeyFor(containerRows: 0, carriers: 1, pkcs11Tokens: 0));
        }

        /// <summary>
        /// Библиотека носитель показала, а контейнеров на нём нет — «поставьте драйверы» здесь
        /// было бы неправдой: драйверы как раз работают.
        /// </summary>
        [Fact]
        public void ReadCarrierWithoutContainers_SaysSo()
        {
            Assert.Equal(ListEmptyHint.NoContainerKey,
                         ListEmptyHint.KeyFor(containerRows: 0, carriers: 1, pkcs11Tokens: 1));
        }

        /// <summary>
        /// Токен, который PC/SC не считает картой (USB-носитель через свою библиотеку), всё
        /// равно прочитан: «вставьте носитель» тут неуместно.
        /// </summary>
        [Fact]
        public void TokenWithoutPcscCard_IsStillRead()
        {
            Assert.Equal(ListEmptyHint.NoContainerKey,
                         ListEmptyHint.KeyFor(containerRows: 0, carriers: 0, pkcs11Tokens: 1));
        }

        /// <summary>
        /// Сорвавшийся обход — это «неизвестно», а не «пусто». У Рутокен Lite и JaCarta LT
        /// контейнеры КриптоПро видны только прямым APDU, и его ошибка не доказывает, что
        /// контейнеров нет (замечание Codex на PR #83). Ошибка перекрывает остальные причины.
        /// </summary>
        [Theory]
        [InlineData(0, 0)]
        [InlineData(1, 0)]
        [InlineData(1, 1)]
        public void FailedScan_IsNotAnEmptyCarrier(int carriers, int pkcs11Tokens)
        {
            Assert.Equal(ListEmptyHint.ScanFailedKey,
                         ListEmptyHint.KeyFor(0, carriers, pkcs11Tokens, scanFailed: true));
        }

        /// <summary>Найденный контейнер объяснять не нужно даже после сорвавшегося обхода.</summary>
        [Fact]
        public void FailedScan_DoesNotExplainAListWithContainers()
        {
            Assert.Null(ListEmptyHint.KeyFor(1, 1, 1, scanFailed: true));
        }

        /// <summary>
        /// Что считать строкой с контейнером. Устройство без контейнера и сертификат-сирота
        /// (AGENTS п. 30) список наполняют, но показывать по-прежнему нечего — иначе объяснение
        /// подавлялось бы как раз там, где оно и нужно (замечание Codex на PR #83).
        /// </summary>
        [Theory]
        [InlineData(SelectedRow.Csp, true)]
        [InlineData(SelectedRow.Apdu, true)]
        [InlineData(SelectedRow.Direct, true)]
        [InlineData(SelectedRow.TokenWithCert, true)]
        [InlineData(SelectedRow.TokenWithoutCert, true)]
        [InlineData(SelectedRow.TokenCertificateOnly, false)]
        [InlineData(SelectedRow.Device, false)]
        [InlineData(SelectedRow.None, false)]
        public void OnlyRealContainers_Count(SelectedRow row, bool counts)
        {
            Assert.Equal(counts, ListEmptyHint.IsContainerRow(row));
        }

        /// <summary>
        /// Все объяснения должны быть на каждом языке интерфейса: строка показывается вместо
        /// списка, и маркер пропавшего перевода занял бы всё окно.
        /// </summary>
        [Fact]
        public void EveryExplanation_ExistsInEveryLanguage()
        {
            foreach (string language in Strings.Available)
            {
                using var scope = Strings.Scope(language);
                foreach (string key in new[]
                         {
                             ListEmptyHint.NoReaderKey,
                             ListEmptyHint.NoLibraryKey,
                             ListEmptyHint.NoContainerKey,
                             ListEmptyHint.ScanFailedKey,
                         })
                {
                    string text = Strings.Get(key);
                    Assert.False(string.IsNullOrWhiteSpace(text), $"{language}: пустой {key}");
                    Assert.DoesNotContain(Strings.MissingMarkerStart, text);
                }
            }
        }
    }
}
