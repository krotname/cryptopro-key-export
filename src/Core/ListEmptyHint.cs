namespace CryptoProExport
{
    /// <summary>
    /// Чем объяснить пустой список носителей — прямо в самом списке, а не только в журнале
    /// (ROADMAP, P2, п. 7). Причин ровно две, и действия у них разные: считывателей нет вовсе
    /// — носитель надо вставить; считыватель есть, но библиотеки PKCS#11 для него не нашлось
    /// — нужны драйверы вендора. Раньше и то и другое было видно только в журнале, а он
    /// теперь свёрнут по умолчанию.
    ///
    /// Правило вынесено из окна в Core сознательно: так его проверяют тесты, как и таблицу
    /// <see cref="ActionAvailability"/>.
    /// </summary>
    public static class ListEmptyHint
    {
        /// <summary>Ни одного считывателя: носитель не вставлен или PC/SC его не видит.</summary>
        public const string NoReaderKey = "list.empty.noreader";

        /// <summary>Считыватель есть, но читать его нечем: библиотеки PKCS#11 не нашлось.</summary>
        public const string NoLibraryKey = "list.empty.nolibrary";

        /// <summary>
        /// Ключ объяснения или <c>null</c>, если объяснять нечего — в списке есть строки.
        /// Отрицательные значения на вход не приходят, но и на них ответ осмысленный:
        /// строк нет и считывателей нет.
        /// </summary>
        public static string KeyFor(int rows, int readers) =>
            rows > 0 ? null : readers > 0 ? NoLibraryKey : NoReaderKey;
    }
}
