using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoProExport
{
    internal enum RtComWorkerFailure
    {
        Start,
        Crashed,
        Timeout,
        Malformed,
        Failed,
    }

    internal sealed class RtComWorkerException : InvalidOperationException
    {
        public RtComWorkerFailure Failure { get; }
        public int? WorkerExitCode { get; }

        public RtComWorkerException(RtComWorkerFailure failure, string message,
                                    int? workerExitCode = null, Exception inner = null)
            : base(message, inner)
        {
            Failure = failure;
            WorkerExitCode = workerExitCode;
        }
    }

    internal sealed class RtComWorkerLaunch
    {
        public string FileName { get; }
        public IReadOnlyList<string> ArgumentPrefix { get; }

        public RtComWorkerLaunch(string fileName, params string[] argumentPrefix)
        {
            FileName = fileName ?? throw new ArgumentNullException(nameof(fileName));
            ArgumentPrefix = argumentPrefix ?? Array.Empty<string>();
        }

        public static RtComWorkerLaunch CurrentApplication()
        {
            string executable = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executable))
                throw new InvalidOperationException(Strings.Get("err.rtcom.worker.noexe"));

            string entry = Assembly.GetEntryAssembly()?.Location;
            string name = Path.GetFileNameWithoutExtension(executable);
            if (string.Equals(name, "dotnet", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(entry))
                return new RtComWorkerLaunch(executable, entry, RtComWorkerServer.Command);

            return new RtComWorkerLaunch(executable, RtComWorkerServer.Command);
        }
    }

    internal sealed class RtComWorkerRequest
    {
        public int Version { get; set; }
        public string Language { get; set; }
        public string UserPin { get; set; }
        public List<string> SkipReaders { get; set; }
    }

    internal sealed class RtComWorkerMessage
    {
        public int Version { get; set; }
        public string Type { get; set; }
        public string Text { get; set; }
        public List<RtComWorkerContainer> Containers { get; set; }
    }

    internal sealed class RtComWorkerContainer
    {
        public string TokenName { get; set; }
        public string TokenDir { get; set; }
        public string ContainerName { get; set; }
        public Dictionary<string, byte[]> Files { get; set; }
    }

    /// <summary>
    /// Машинный канал parent/worker. Он намеренно отделён от stdout/stderr процесса:
    /// сообщения имеют length-prefix, версию и строгий предел размера, поэтому случайный
    /// текст нативной библиотеки нельзя принять за контейнер или событие журнала.
    /// </summary>
    internal static class RtComWorkerProtocol
    {
        public const int Version = 1;
        public const int MaxFrameBytes = 32 * 1024 * 1024;

        private static readonly JsonSerializerOptions Json = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        public static void Write<T>(Stream stream, T value)
        {
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value, Json);
            if (payload.Length == 0 || payload.Length > MaxFrameBytes)
                throw new InvalidDataException("Invalid rtCOMLite worker frame length.");
            Span<byte> header = stackalloc byte[4];
            header[0] = (byte)payload.Length;
            header[1] = (byte)(payload.Length >> 8);
            header[2] = (byte)(payload.Length >> 16);
            header[3] = (byte)(payload.Length >> 24);
            stream.Write(header);
            stream.Write(payload, 0, payload.Length);
            stream.Flush();
        }

        public static T Read<T>(Stream stream) where T : class
        {
            byte[] header = new byte[4];
            int first = stream.Read(header, 0, header.Length);
            if (first == 0) return null;
            ReadExactly(stream, header, first, header.Length - first);
            int length = header[0] | header[1] << 8 | header[2] << 16 | header[3] << 24;
            if (length <= 0 || length > MaxFrameBytes)
                throw new InvalidDataException("Invalid rtCOMLite worker frame length.");
            byte[] payload = new byte[length];
            ReadExactly(stream, payload, 0, length);
            try
            {
                return JsonSerializer.Deserialize<T>(payload, Json)
                       ?? throw new InvalidDataException("Empty rtCOMLite worker message.");
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("Invalid rtCOMLite worker JSON.", error);
            }
        }

        private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
                int read = stream.Read(buffer, offset, count);
                if (read == 0) throw new EndOfStreamException("Incomplete rtCOMLite worker frame.");
                offset += read;
                count -= read;
            }
        }
    }

    internal sealed class RtComWorkerReadOutcome
    {
        public List<RutokenContainer> Containers { get; set; }
        public string Error { get; set; }
        public bool HasFinalMessage { get; set; }
    }

    internal static class RtComWorkerClient
    {
        private const int MaxContainers = 512;
        private const int MaxMessages = 10000;
        private const int MaxTextLength = 65536;
        private const int MaxTotalTextLength = 1024 * 1024;
        private const int MaxSingleFileBytes = 8 * 1024 * 1024;
        private const long MaxTotalFileBytes = 64L * 1024 * 1024;

        public static List<RutokenContainer> Run(
            RtComWorkerLaunch launch, int timeoutMs, string userPin,
            ISet<string> skipReaders, Action<string> log, Action started,
            CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            if (launch == null) throw new ArgumentNullException(nameof(launch));
            if (timeoutMs <= 0) throw new ArgumentOutOfRangeException(nameof(timeoutMs));

            using var requestPipe = new AnonymousPipeServerStream(
                PipeDirection.Out, HandleInheritability.Inheritable);
            using var responsePipe = new AnonymousPipeServerStream(
                PipeDirection.In, HandleInheritability.Inheritable);

            var psi = new ProcessStartInfo
            {
                FileName = launch.FileName,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = AppContext.BaseDirectory,
            };
            foreach (string argument in launch.ArgumentPrefix) psi.ArgumentList.Add(argument);
            psi.ArgumentList.Add(requestPipe.GetClientHandleAsString());
            psi.ArgumentList.Add(responsePipe.GetClientHandleAsString());
            // Отладочный канал CLR дочернему процессу не нужен и расширяет поверхность IPC.
            psi.Environment["DOTNET_EnableDiagnostics"] = "0";

            Process process;
            try
            {
                process = Process.Start(psi);
            }
            catch (Exception error) when (error is InvalidOperationException
                                           or System.ComponentModel.Win32Exception)
            {
                throw new RtComWorkerException(RtComWorkerFailure.Start,
                    Strings.Format("err.rtcom.worker.start", Path.GetFileName(launch.FileName), error.Message),
                    inner: error);
            }
            if (process == null)
                throw new RtComWorkerException(RtComWorkerFailure.Start,
                    Strings.Format("err.rtcom.worker.start", Path.GetFileName(launch.FileName), "—"));

            using (process)
            {
                requestPipe.DisposeLocalCopyOfClientHandle();
                responsePipe.DisposeLocalCopyOfClientHandle();

                Task drainOut = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
                Task drainErr = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
                Task<RtComWorkerReadOutcome> read = Task.Run(
                    () => ReadMessages(responsePipe, log ?? (_ => { }), started ?? (() => { })));
                Task exit = process.WaitForExitAsync();

                Exception writeError = null;
                try
                {
                    var request = new RtComWorkerRequest
                    {
                        Version = RtComWorkerProtocol.Version,
                        Language = Strings.Current,
                        UserPin = userPin,
                        SkipReaders = skipReaders == null
                            ? new List<string>()
                            : new List<string>(skipReaders),
                    };
                    RtComWorkerProtocol.Write(requestPipe, request);
                }
                catch (Exception error) when (error is IOException or ObjectDisposedException)
                {
                    writeError = error;
                }
                finally
                {
                    requestPipe.Close();
                }

                var timer = Stopwatch.StartNew();
                bool timedOut = false;
                try
                {
                    while (!read.IsCompleted || !exit.IsCompleted)
                    {
                        cancel.ThrowIfCancellationRequested();
                        if (read.IsFaulted) break;
                        int remaining = timeoutMs - checked((int)Math.Min(timer.ElapsedMilliseconds, int.MaxValue));
                        if (remaining <= 0)
                        {
                            timedOut = true;
                            break;
                        }
                        Task[] pending = read.IsCompleted
                            ? new[] { exit }
                            : exit.IsCompleted ? new Task[] { read } : new Task[] { read, exit };
                        Task.WaitAny(pending, Math.Min(remaining, 250), cancel);
                    }
                }
                catch (OperationCanceledException)
                {
                    KillAndWait(process);
                    throw new OperationCanceledException(Strings.Get("err.rtcom.worker.cancelled"), cancel);
                }

                if (read.IsFaulted)
                {
                    KillAndWait(process);
                    Exception cause = read.Exception?.GetBaseException();
                    throw new RtComWorkerException(RtComWorkerFailure.Malformed,
                        Strings.Get("err.rtcom.worker.malformed"), inner: cause);
                }
                if (timedOut)
                {
                    KillAndWait(process);
                    throw new RtComWorkerException(RtComWorkerFailure.Timeout,
                        Strings.Format("err.rtcom.worker.timeout", timeoutMs));
                }

                // Оба задания завершены. GetResult здесь не блокирует, а разворачивает исключение
                // чтения без AggregateException, если поток закрылся повреждённым кадром.
                RtComWorkerReadOutcome outcome;
                try { outcome = read.GetAwaiter().GetResult(); }
                catch (Exception error)
                {
                    throw new RtComWorkerException(RtComWorkerFailure.Malformed,
                        Strings.Get("err.rtcom.worker.malformed"), inner: error);
                }
                exit.GetAwaiter().GetResult();
                _ = Task.WaitAll(new[] { drainOut, drainErr }, 1000);

                int exitCode = process.ExitCode;
                if (!string.IsNullOrEmpty(outcome.Error))
                    throw new RtComWorkerException(RtComWorkerFailure.Failed,
                        Strings.Format("err.rtcom.worker.failed", outcome.Error), exitCode);
                if (exitCode != 0)
                    throw new RtComWorkerException(RtComWorkerFailure.Crashed,
                        Strings.Format("err.rtcom.worker.crashed", ExitCodeText(exitCode)), exitCode,
                        writeError);
                if (!outcome.HasFinalMessage || outcome.Containers == null || writeError != null)
                    throw new RtComWorkerException(RtComWorkerFailure.Malformed,
                        Strings.Get("err.rtcom.worker.incomplete"), inner: writeError);
                return outcome.Containers;
            }
        }

        private static RtComWorkerReadOutcome ReadMessages(
            Stream stream, Action<string> log, Action started)
        {
            var outcome = new RtComWorkerReadOutcome();
            bool startedSeen = false;
            int count = 0;
            int totalTextLength = 0;
            while (true)
            {
                RtComWorkerMessage message = RtComWorkerProtocol.Read<RtComWorkerMessage>(stream);
                if (message == null) return outcome;
                if (++count > MaxMessages || message.Version != RtComWorkerProtocol.Version
                    || outcome.HasFinalMessage || string.IsNullOrEmpty(message.Type))
                    throw new InvalidDataException("Invalid rtCOMLite worker message sequence.");

                switch (message.Type)
                {
                    case "started":
                        if (startedSeen) throw new InvalidDataException("Duplicate worker start event.");
                        startedSeen = true;
                        started();
                        break;
                    case "log":
                        if (message.Text == null || message.Text.Length > MaxTextLength)
                            throw new InvalidDataException("Invalid worker log event.");
                        totalTextLength = checked(totalTextLength + message.Text.Length);
                        if (totalTextLength > MaxTotalTextLength)
                            throw new InvalidDataException("Worker log output is too large.");
                        log(message.Text);
                        break;
                    case "result":
                        if (!startedSeen)
                            throw new InvalidDataException("Worker result precedes start event.");
                        outcome.Containers = ConvertContainers(message.Containers);
                        outcome.HasFinalMessage = true;
                        break;
                    case "error":
                        if (string.IsNullOrWhiteSpace(message.Text) || message.Text.Length > MaxTextLength)
                            throw new InvalidDataException("Invalid worker error event.");
                        outcome.Error = message.Text;
                        outcome.HasFinalMessage = true;
                        break;
                    default:
                        throw new InvalidDataException("Unknown rtCOMLite worker message.");
                }
            }
        }

        private static List<RutokenContainer> ConvertContainers(List<RtComWorkerContainer> wire)
        {
            wire ??= new List<RtComWorkerContainer>();
            if (wire.Count > MaxContainers)
                throw new InvalidDataException("Too many rtCOMLite worker containers.");
            long total = 0;
            var result = new List<RutokenContainer>(wire.Count);
            var allowed = new HashSet<string>(ContainerStore.ContainerFiles,
                                              StringComparer.OrdinalIgnoreCase);
            foreach (RtComWorkerContainer source in wire)
            {
                if (source == null || source.Files == null || source.Files.Count > allowed.Count
                    || TooLong(source.TokenName) || TooLong(source.TokenDir)
                    || TooLong(source.ContainerName))
                    throw new InvalidDataException("Invalid rtCOMLite worker container.");
                var target = new RutokenContainer
                {
                    TokenName = source.TokenName,
                    TokenDir = source.TokenDir,
                    ContainerName = source.ContainerName,
                };
                foreach (var file in source.Files)
                {
                    if (!allowed.Contains(file.Key) || file.Value == null
                        || file.Value.Length > MaxSingleFileBytes)
                        throw new InvalidDataException("Invalid rtCOMLite worker file.");
                    total += file.Value.Length;
                    if (total > MaxTotalFileBytes)
                        throw new InvalidDataException("rtCOMLite worker response is too large.");
                    target.Files.Add(file.Key, file.Value);
                }
                result.Add(target);
            }
            return result;
        }

        private static bool TooLong(string value) => value != null && value.Length > 4096;

        private static string ExitCodeText(int exitCode) => $"0x{unchecked((uint)exitCode):X8}";

        private static void KillAndWait(Process process)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (Exception) { }
            try { process.WaitForExit(5000); }
            catch (Exception) { }
        }
    }

    /// <summary>Точка входа дочернего процесса. Вызывается до GUI, CLI и SessionLog.</summary>
    internal static class RtComWorkerServer
    {
        public const string Command = "--rtcom-worker";
        private const int InvalidInvocationExitCode = 64;
        private const int ManagedFailureExitCode = 65;

        public static int Run(string[] pipeHandles)
        {
            SuppressCrashUi();
            if (pipeHandles == null || pipeHandles.Length != 2)
                return InvalidInvocationExitCode;

            try
            {
                using var request = new AnonymousPipeClientStream(PipeDirection.In, pipeHandles[0]);
                using var response = new AnonymousPipeClientStream(PipeDirection.Out, pipeHandles[1]);
                try
                {
                    RtComWorkerRequest command = RtComWorkerProtocol.Read<RtComWorkerRequest>(request);
                    Validate(command);
                    if (!Strings.Use(command.Language))
                        throw new InvalidDataException("Unknown worker language.");

                    void Send(RtComWorkerMessage message)
                    {
                        message.Version = RtComWorkerProtocol.Version;
                        RtComWorkerProtocol.Write(response, message);
                    }

                    var worker = new RutokenExporter
                    {
                        UserPin = command.UserPin,
                        SkipReaders = new HashSet<string>(command.SkipReaders,
                                                          StringComparer.OrdinalIgnoreCase),
                        Log = text => Send(new RtComWorkerMessage { Type = "log", Text = text }),
                    };
                    try
                    {
                        List<RutokenContainer> containers = worker.ReadAllContainersInCurrentProcess(
                            () => Send(new RtComWorkerMessage { Type = "started" }));
                        Send(new RtComWorkerMessage
                        {
                            Type = "result",
                            Containers = ToWire(containers),
                        });
                        return 0;
                    }
                    finally
                    {
                        worker.UserPin = null;
                        command.UserPin = null;
                    }
                }
                catch (Exception error)
                {
                    try
                    {
                        RtComWorkerProtocol.Write(response, new RtComWorkerMessage
                        {
                            Version = RtComWorkerProtocol.Version,
                            Type = "error",
                            Text = error.Message,
                        });
                    }
                    catch (Exception) { }
                    return ManagedFailureExitCode;
                }
            }
            catch (Exception)
            {
                return ManagedFailureExitCode;
            }
        }

        private static void Validate(RtComWorkerRequest request)
        {
            if (request == null || request.Version != RtComWorkerProtocol.Version
                || string.IsNullOrWhiteSpace(request.Language)
                || request.UserPin?.Length > 4096
                || request.SkipReaders == null || request.SkipReaders.Count > 512)
                throw new InvalidDataException("Invalid rtCOMLite worker request.");
            foreach (string reader in request.SkipReaders)
                if (string.IsNullOrEmpty(reader) || reader.Length > 4096)
                    throw new InvalidDataException("Invalid rtCOMLite worker reader.");
        }

        private static List<RtComWorkerContainer> ToWire(List<RutokenContainer> containers)
        {
            var result = new List<RtComWorkerContainer>(containers?.Count ?? 0);
            if (containers == null) return result;
            foreach (RutokenContainer container in containers)
                result.Add(new RtComWorkerContainer
                {
                    TokenName = container.TokenName,
                    TokenDir = container.TokenDir,
                    ContainerName = container.ContainerName,
                    Files = container.Files,
                });
            return result;
        }

        private static void SuppressCrashUi()
        {
            const uint SemFailCriticalErrors = 0x0001;
            const uint SemNoGpFaultErrorBox = 0x0002;
            _ = SetErrorMode(SemFailCriticalErrors | SemNoGpFaultErrorBox);
            try { _ = WerSetFlags(0x0020); } // WER_FAULT_REPORTING_NO_UI
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        [DllImport("kernel32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint SetErrorMode(uint mode);

        [DllImport("wer.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern int WerSetFlags(uint flags);
    }
}
