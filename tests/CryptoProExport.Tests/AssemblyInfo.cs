using Xunit;

// Действующий язык интерфейса — глобальное состояние процесса (Strings.Current), и тесты
// переключают его через Strings.Scope. Параллельный прогон коллекций сделал бы такие
// проверки недетерминированными, а весь набор укладывается в пару секунд.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
