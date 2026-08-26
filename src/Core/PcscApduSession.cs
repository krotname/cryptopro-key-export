using System;
using System.Runtime.InteropServices;

namespace CryptoProExport
{
    /// <summary>
    /// Узкая PC/SC-сессия для проверенных APDU-backend'ов. Не выбирает протокол карты сама:
    /// конкретный исполнитель обязан сначала доказать тип носителя по PKCS#11/имени reader,
    /// а затем послать только команды своего профиля.
    /// </summary>
    internal sealed class PcscApduSession : IDisposable
    {
        private const uint ScopeUser = 0;
        private const uint ShareShared = 2;
        private const uint ProtocolT0 = 1;
        private const uint ProtocolT1 = 2;
        private const uint LeaveCard = 0;

        private IntPtr _context;
        private IntPtr _card;
        private bool _transaction;
        private IoRequest _pci;

        public static PcscApduSession Open(string reader)
        {
            if (string.IsNullOrWhiteSpace(reader))
                throw new LiteApduException(CryptoErrors.Describe(unchecked((int)0x80100009)));

            var session = new PcscApduSession();
            int rc;
            try
            {
                rc = SCardEstablishContext(ScopeUser, IntPtr.Zero, IntPtr.Zero, out session._context);
            }
            catch (DllNotFoundException e)
            {
                throw new LiteApduException(e.Message);
            }
            if (rc != 0) throw new LiteApduException(CryptoErrors.Describe(rc));

            rc = SCardConnect(session._context, reader, ShareShared, ProtocolT0 | ProtocolT1,
                out session._card, out uint activeProtocol);
            if (rc != 0)
            {
                SCardReleaseContext(session._context);
                session._context = IntPtr.Zero;
                throw new LiteApduException(CryptoErrors.Describe(rc));
            }
            session._pci = new IoRequest { Protocol = activeProtocol, PciLength = 8 };

            rc = SCardBeginTransaction(session._card);
            if (rc != 0)
            {
                session.Dispose();
                throw new LiteApduException(CryptoErrors.Describe(rc));
            }
            session._transaction = true;
            return session;
        }

        public byte[] Transmit(byte[] command)
        {
            if (command == null) throw new ArgumentNullException(nameof(command));
            var response = new byte[65538];
            int length = response.Length;
            int rc = SCardTransmit(_card, ref _pci, command, command.Length,
                IntPtr.Zero, response, ref length);
            if (rc != 0) throw new LiteApduException(CryptoErrors.Describe(rc));
            var result = new byte[length];
            Array.Copy(response, result, length);
            return result;
        }

        /// <summary>Для T=0: если карта вернула 61xx, забрать тело отдельным GET RESPONSE.</summary>
        public byte[] TransmitWithGetResponse(byte[] command)
        {
            byte[] response = Transmit(command);
            if (response.Length >= 2 && response[response.Length - 2] == 0x61)
                return Transmit(new byte[] { 0x00, 0xC0, 0x00, 0x00, response[response.Length - 1] });
            return response;
        }

        public static bool IsOk(byte[] response) => Status(response) == 0x9000;

        public static int Status(byte[] response) => response == null || response.Length < 2
            ? 0 : (response[response.Length - 2] << 8) | response[response.Length - 1];

        public static byte[] Data(byte[] response)
        {
            if (response == null || response.Length <= 2) return Array.Empty<byte>();
            var data = new byte[response.Length - 2];
            Array.Copy(response, data, data.Length);
            return data;
        }

        public static void RequireOk(byte[] response, string operation)
        {
            int status = Status(response);
            if (status != 0x9000)
                throw new LiteApduException(Strings.Format(
                    "err.com.call", operation, "0x" + status.ToString("X4")));
        }

        public void Dispose()
        {
            if (_card != IntPtr.Zero && _transaction)
            {
                try { SCardEndTransaction(_card, LeaveCard); } catch { }
                _transaction = false;
            }
            if (_card != IntPtr.Zero)
            {
                try { SCardDisconnect(_card, LeaveCard); } catch { }
                _card = IntPtr.Zero;
            }
            if (_context != IntPtr.Zero)
            {
                try { SCardReleaseContext(_context); } catch { }
                _context = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IoRequest
        {
            public uint Protocol;
            public uint PciLength;
        }

        [DllImport("winscard.dll")]
        private static extern int SCardEstablishContext(uint scope, IntPtr r1, IntPtr r2,
            out IntPtr context);
        [DllImport("winscard.dll")]
        private static extern int SCardReleaseContext(IntPtr context);
        [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardConnectW")]
        private static extern int SCardConnect(IntPtr context, string reader, uint share,
            uint protocols, out IntPtr card, out uint activeProtocol);
        [DllImport("winscard.dll")]
        private static extern int SCardDisconnect(IntPtr card, uint disposition);
        [DllImport("winscard.dll")]
        private static extern int SCardBeginTransaction(IntPtr card);
        [DllImport("winscard.dll")]
        private static extern int SCardEndTransaction(IntPtr card, uint disposition);
        [DllImport("winscard.dll")]
        private static extern int SCardTransmit(IntPtr card, ref IoRequest sendPci,
            byte[] sendBuffer, int sendLength, IntPtr receivePci,
            byte[] receiveBuffer, ref int receiveLength);
    }
}
