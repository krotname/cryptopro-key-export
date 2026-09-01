using Xunit;

namespace CryptoProExport.Tests
{
    /// <summary>
    /// Объяснение пустого списка (ROADMAP, P2, п. 7). Правило простое, но ошибиться в нём
    /// дорого: «вставьте носитель» на машине с воткнутым токеном отправляет владельца искать
    /// не там, а «поставьте драйверы» без единого считывателя — тем более.
    /// </summary>
    public class ListEmptyHintTests
    {
        [Fact]
        public void NonEmptyList_IsNotExplained()
        {
            Assert.Null(ListEmptyHint.KeyFor(rows: 1, carriers: 0));
            Assert.Null(ListEmptyHint.KeyFor(rows: 13, carriers: 8));
        }

        [Fact]
        public void EmptyListWithoutCarriers_AsksToInsertOne()
        {
            Assert.Equal(ListEmptyHint.NoReaderKey, ListEmptyHint.KeyFor(rows: 0, carriers: 0));
        }

        /// <summary>
        /// Пустой считыватель — это «вставьте носитель», а не «нет библиотеки»: считыватель
        /// виден системе всегда, но строки в списке не даёт, потому что PcscReaders.Uncovered
        /// пропускает считыватель без карты (замечание Codex на PR #83). Поэтому на вход и
        /// идёт число носителей, а не считывателей.
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
            Assert.Equal(ListEmptyHint.NoReaderKey, ListEmptyHint.KeyFor(rows.Count, carriers));
        }

        [Fact]
        public void EmptyListWithCarriers_BlamesTheMissingLibrary()
        {
            Assert.Equal(ListEmptyHint.NoLibraryKey, ListEmptyHint.KeyFor(rows: 0, carriers: 1));
            Assert.Equal(ListEmptyHint.NoLibraryKey, ListEmptyHint.KeyFor(rows: 0, carriers: 8));
        }

        /// <summary>
        /// Оба объяснения должны быть на каждом языке интерфейса: строка показывается вместо
        /// списка, и маркер пропавшего перевода занял бы всё окно.
        /// </summary>
        [Fact]
        public void BothExplanations_ExistInEveryLanguage()
        {
            foreach (string language in Strings.Available)
            {
                using var scope = Strings.Scope(language);
                foreach (string key in new[] { ListEmptyHint.NoReaderKey, ListEmptyHint.NoLibraryKey })
                {
                    string text = Strings.Get(key);
                    Assert.False(string.IsNullOrWhiteSpace(text), $"{language}: пустой {key}");
                    Assert.DoesNotContain(Strings.MissingMarkerStart, text);
                }
            }
        }
    }
}
