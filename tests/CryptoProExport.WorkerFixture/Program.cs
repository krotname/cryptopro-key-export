using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using CryptoProExport;

namespace CryptoProExport.WorkerFixture
{
    /// <summary>Маркер для поиска сборки fixture из интеграционных тестов.</summary>
    public sealed class WorkerFixtureMarker { }

    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length != 3) return 64;
            string mode = args[0];
            using var request = new AnonymousPipeClientStream(PipeDirection.In, args[1]);
            using var response = new AnonymousPipeClientStream(PipeDirection.Out, args[2]);
            RtComWorkerRequest command = RtComWorkerProtocol.Read<RtComWorkerRequest>(request);
            if (command == null || command.Version != RtComWorkerProtocol.Version) return 65;

            switch (mode)
            {
                case "success":
                    if (command.UserPin != "test-pin") return 66;
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    Send(response, new RtComWorkerMessage { Type = "log", Text = "fixture-progress" });
                    Send(response, new RtComWorkerMessage
                    {
                        Type = "result",
                        Containers = new List<RtComWorkerContainer>
                        {
                            new RtComWorkerContainer
                            {
                                TokenName = "fixture-reader",
                                TokenDir = "/1/",
                                ContainerName = "fixture-container",
                                Files = new Dictionary<string, byte[]>
                                {
                                    ["primary.key"] = new byte[] { 1, 2, 3 },
                                },
                            },
                        },
                    });
                    return 0;

                case "managed-error":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    Send(response, new RtComWorkerMessage
                        { Type = "error", Text = "synthetic worker failure" });
                    return 65;

                case "nonzero":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    return 17;

                case "crash":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    Process.GetCurrentProcess().Kill();
                    return 18;

                case "timeout":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    Send(response, new RtComWorkerMessage
                        { Type = "log", Text = "fixture-pid:" + Environment.ProcessId });
                    Thread.Sleep(Timeout.Infinite);
                    return 19;

                case "malformed":
                    response.Write(new byte[] { 9, 0, 0, 0, (byte)'{' }, 0, 5);
                    response.Flush();
                    return 0;

                case "incomplete":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    return 0;

                case "log-flood":
                    Send(response, new RtComWorkerMessage { Type = "started" });
                    string chunk = new string('x', 65536);
                    for (int i = 0; i < 17; i++)
                        Send(response, new RtComWorkerMessage { Type = "log", Text = chunk });
                    return 0;

                default:
                    return 67;
            }
        }

        private static void Send(Stream response, RtComWorkerMessage message)
        {
            message.Version = RtComWorkerProtocol.Version;
            RtComWorkerProtocol.Write(response, message);
        }
    }
}
