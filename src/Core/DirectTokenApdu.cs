using System;
using System.Collections.Generic;
using System.Threading;

namespace CryptoProExport
{
    /// <summary>
    /// Ссылка на один файловый контейнер, найденный безопасным APDU-backend'ом без PIN.
    /// В путь результата попадает только технический <see cref="OutputName"/>, а не имя,
    /// которое может содержать ФИО.
    /// </summary>
    public sealed class DirectTokenContainerRef
    {
        public RutokenKind Kind { get; internal set; }
        public string Reader { get; internal set; }
        public string Name { get; internal set; }
        public string OutputName { get; internal set; }

        internal int Index { get; set; }
        internal ushort[] Path { get; set; }
        internal LiteContainerRef Lite { get; set; }
    }

    /// <summary>
    /// Единая маршрутизация доказанных пассивных носителей: Rutoken S, Rutoken Lite,
    /// JaCarta LT/PRO и ESMART. Тип сначала подтверждается метаданными токена; APDU чужого
    /// семейства к reader никогда не отправляется.
    /// </summary>
    public sealed class DirectTokenApdu
    {
        public Action<string> Log { get; set; }
        public CancellationToken Cancel { get; set; } = CancellationToken.None;

        private void Say(string message) => Log?.Invoke(message);

        public static bool Supports(RutokenKind kind) => kind == RutokenKind.RutokenS
            || kind == RutokenKind.RutokenLite || kind == RutokenKind.JaCartaLt
            || kind == RutokenKind.JaCartaPro || kind == RutokenKind.Esmart;

        public List<DirectTokenContainerRef> ListContainers(Pkcs11TokenInfo token)
        {
            ValidateToken(token);
            Cancel.ThrowIfCancellationRequested();
            if (token.Kind == RutokenKind.RutokenLite)
            {
                var lite = new RutokenLiteApdu { Log = Say };
                var result = new List<DirectTokenContainerRef>();
                foreach (LiteContainerRef item in lite.ListContainers(token.Reader))
                {
                    Cancel.ThrowIfCancellationRequested();
                    result.Add(new DirectTokenContainerRef
                    {
                        Kind = token.Kind,
                        Reader = token.Reader,
                        Name = item.Name,
                        OutputName = $"lite_{item.DfIndex:X2}",
                        Index = item.DfIndex,
                        Lite = item,
                    });
                }
                return result;
            }
            if (token.Kind == RutokenKind.RutokenS)
                return new RutokenSApdu { Log = Say, Cancel = Cancel }.ListContainers(token.Reader);
            if (token.Kind == RutokenKind.Esmart)
                return new EsmartApdu { Log = Say, Cancel = Cancel }.ListContainers(token.Reader);
            if (token.Kind == RutokenKind.JaCartaPro)
                return new JaCartaProApdu { Log = Say, Cancel = Cancel }.ListContainers(token.Reader);
            return new JaCartaLtApdu { Log = Say, Cancel = Cancel }.ListContainers(token.Reader);
        }

        /// <summary>
        /// Отобрать контейнер по полному техническому <see cref="DirectTokenContainerRef.OutputName"/>.
        /// Для eToken PRO с профилем PRO селектор обязателен: публичный список может содержать несколько
        /// контейнеров, а защищённые файлы разрешено читать только у явно выбранного индекса.
        /// Имена из <c>name.key</c> намеренно не участвуют в выборе.
        /// </summary>
        public static List<DirectTokenContainerRef> SelectContainers(
            Pkcs11TokenInfo token, IEnumerable<DirectTokenContainerRef> containers,
            string outputName)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            var candidates = new List<DirectTokenContainerRef>();
            foreach (DirectTokenContainerRef candidate in
                containers ?? Array.Empty<DirectTokenContainerRef>())
            {
                if (candidate == null || candidate.Kind != token.Kind
                    || !string.Equals(candidate.Reader, token.Reader,
                        StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(candidate.OutputName))
                    throw ContainerSelectionError(outputName);
                if (token.Kind == RutokenKind.JaCartaPro
                    && !IsJaCartaProOutputName(candidate.OutputName, candidate.Index))
                    throw ContainerSelectionError(outputName);
                candidates.Add(candidate);
            }

            if (string.IsNullOrWhiteSpace(outputName))
            {
                if (token.Kind == RutokenKind.JaCartaPro)
                    throw ContainerSelectionError("--container <technical OutputName>");
                return candidates;
            }

            if (token.Kind == RutokenKind.JaCartaPro
                && !IsJaCartaProOutputName(outputName, index: null))
                throw ContainerSelectionError(outputName);

            var matches = candidates.FindAll(candidate => string.Equals(
                candidate.OutputName, outputName, StringComparison.OrdinalIgnoreCase));
            if (matches.Count != 1) throw ContainerSelectionError(outputName);
            return matches;
        }

        public RutokenContainer ReadContainer(Pkcs11TokenInfo token,
                                               DirectTokenContainerRef selected,
                                               string userPin)
        {
            ValidateToken(token);
            if (selected == null) throw new ArgumentNullException(nameof(selected));
            if (selected.Kind != token.Kind ||
                !string.Equals(selected.Reader, token.Reader, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException(Pkcs11Token.KindName(selected.Kind), nameof(selected));

            string pin = ResolvePin(token, userPin);
            Cancel.ThrowIfCancellationRequested();
            if (token.Kind == RutokenKind.RutokenLite)
            {
                if (selected.Lite == null) throw new ArgumentException(nameof(selected));
                string temporary = RutokenLiteApdu.ReserveOutputDirectory(
                    System.IO.Path.GetTempPath(), "cpx-lite-read");
                try
                {
                    var lite = new RutokenLiteApdu { Log = Say };
                    string name = lite.ReadContainer(token.Reader, selected.Lite.DfIndex,
                        pin, temporary);
                    var container = new RutokenContainer
                    {
                        TokenName = token.Reader,
                        TokenDir = $"APDU/{selected.Lite.DfIndex:X2}",
                        ContainerName = name ?? selected.Name,
                    };
                    foreach (string file in ContainerStore.ContainerFiles)
                    {
                        string path = System.IO.Path.Combine(temporary, file);
                        if (System.IO.File.Exists(path))
                            container.Files[file] = System.IO.File.ReadAllBytes(path);
                    }
                    return container;
                }
                finally
                {
                    if (System.IO.Directory.Exists(temporary))
                        try { System.IO.Directory.Delete(temporary, recursive: true); } catch (System.IO.IOException) { }
                }
            }
            if (token.Kind == RutokenKind.RutokenS)
                return new RutokenSApdu { Log = Say, Cancel = Cancel }
                    .ReadContainer(token.Reader, selected, pin);
            if (token.Kind == RutokenKind.Esmart)
                return new EsmartApdu { Log = Say, Cancel = Cancel }
                    .ReadContainer(token.Reader, selected, pin);
            if (token.Kind == RutokenKind.JaCartaPro)
            {
                if (token.PinCountLow || token.PinFinalTry || token.PinLocked)
                    throw new LiteApduException(Strings.Format(
                        "err.lite.pin", Pkcs11Token.PinState(token)));
                if (!IsJaCartaProOutputName(selected.OutputName, selected.Index))
                    throw ContainerSelectionError(selected.OutputName);
                return new JaCartaProApdu { Log = Say, Cancel = Cancel }
                    .ReadContainer(token.Reader, selected, pin);
            }
            return new JaCartaLtApdu { Log = Say, Cancel = Cancel }
                .ReadContainer(token.Reader, selected, pin);
        }

        internal static string ResolvePin(Pkcs11TokenInfo token, string userPin)
        {
            if (!string.IsNullOrEmpty(userPin)) return userPin;
            if (token != null && token.PinDefault && !token.PinCountLow &&
                !token.PinFinalTry && !token.PinLocked)
            {
                if (token.Kind == RutokenKind.JaCartaLt) return "1234567890";
                if (token.Kind == RutokenKind.RutokenS || token.Kind == RutokenKind.RutokenLite
                    || token.Kind == RutokenKind.Esmart)
                    return "12345678";
            }
            throw new LiteApduException(Strings.Format("err.lite.pin", "—"));
        }

        /// <summary>
        /// Один явно введённый PIN нельзя молча отправлять нескольким reader: даже у двух
        /// одинаковых моделей значения могут различаться, а ошибка расходует счётчик карты.
        /// Для пакетного режима без PIN безопасные заводские значения выбираются отдельно
        /// для каждого токена только по подтверждённым PKCS#11-флагам.
        /// </summary>
        internal static void EnsureSingleReaderForExplicitPin(
            IEnumerable<Pkcs11TokenInfo> tokens, string userPin)
        {
            if (string.IsNullOrEmpty(userPin)) return;
            var readers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Pkcs11TokenInfo token in tokens ?? Array.Empty<Pkcs11TokenInfo>())
            {
                if (token != null && Supports(token.Kind) && !string.IsNullOrWhiteSpace(token.Reader))
                    readers.Add(token.Reader);
            }
            if (readers.Count > 1)
                throw new LiteApduException(Strings.Get("err.direct.pin.scope"));
        }

        /// <summary>
        /// Глобальный batch-путь не имеет technical selector. При подключённом eToken PRO/PRO
        /// он обязан остановиться до первого защищённого чтения; пользователь выбирает
        /// точную APDU-строку в GUI либо задаёт <c>--container</c> адресной CLI-команде.
        /// </summary>
        internal static void EnsureBatchSelectionSafe(IEnumerable<Pkcs11TokenInfo> tokens)
        {
            foreach (Pkcs11TokenInfo token in
                tokens ?? Array.Empty<Pkcs11TokenInfo>())
            {
                if (token?.Kind == RutokenKind.JaCartaPro)
                    throw ContainerSelectionError("--container <technical OutputName>");
            }
        }

        private static bool IsJaCartaProOutputName(string value, int? index)
        {
            const string prefix = "jacartapro_";
            string candidate = (value ?? string.Empty).Trim();
            if (candidate.Length != prefix.Length + 2
                || !candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                || candidate[prefix.Length] != '0')
                return false;
            char suffix = char.ToUpperInvariant(candidate[prefix.Length + 1]);
            if (!(suffix is >= '0' and <= '9' or >= 'A' and <= 'F')) return false;
            if (!index.HasValue) return true;
            return index.Value is >= 0 and <= 15
                && string.Equals(candidate, $"{prefix}{index.Value:X2}",
                    StringComparison.OrdinalIgnoreCase);
        }

        private static ArgumentException ContainerSelectionError(string outputName)
            => new ArgumentException(Strings.Format("err.container.nokey",
                string.IsNullOrWhiteSpace(outputName) ? "--container" : outputName),
                nameof(outputName));

        private static void ValidateToken(Pkcs11TokenInfo token)
        {
            if (token == null) throw new ArgumentNullException(nameof(token));
            if (!Supports(token.Kind))
                throw new ArgumentException(Pkcs11Token.KindName(token.Kind), nameof(token));
            if (token.Kind == RutokenKind.Esmart && !Pkcs11Token.IsConfirmedEsmart(token))
                throw new ArgumentException(Pkcs11Token.KindName(token.Kind), nameof(token));
            if (token.Kind == RutokenKind.JaCartaPro)
            {
                if (!Pkcs11Token.IsConfirmedJaCartaPro(token)
                    || !JaCartaProApdu.IsExactLiveReader(token, PcscReaders.List()))
                    throw new ArgumentException(Pkcs11Token.KindName(token.Kind), nameof(token));
            }
            RutokenKind resolved = Pkcs11Token.ResolveReaderKind(token.Reader, token);
            if (resolved != token.Kind)
                throw new ArgumentException(Pkcs11Token.KindName(resolved), nameof(token));
        }
    }
}
