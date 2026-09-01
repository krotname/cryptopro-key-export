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
            Assert.Null(ListEmptyHint.KeyFor(rows: 1, readers: 0));
            Assert.Null(ListEmptyHint.KeyFor(rows: 13, readers: 8));
        }

        [Fact]
        public void EmptyListWithoutReaders_AsksToInsertCarrier()
        {
            Assert.Equal(ListEmptyHint.NoReaderKey, ListEmptyHint.KeyFor(rows: 0, readers: 0));
        }

        [Fact]
        public void EmptyListWithReaders_BlamesTheMissingLibrary()
        {
            Assert.Equal(ListEmptyHint.NoLibraryKey, ListEmptyHint.KeyFor(rows: 0, readers: 1));
            Assert.Equal(ListEmptyHint.NoLibraryKey, ListEmptyHint.KeyFor(rows: 0, readers: 8));
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
