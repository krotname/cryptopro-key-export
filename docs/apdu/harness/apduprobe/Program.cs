using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// Direct PC/SC APDU probe: keeps ONE session open so SELECT -> auth -> read state persists.
// Usage: apduprobe "<reader>" <apdu-file> [--t0]
//   apdu-file: one command APDU per line, hex (spaces optional). '#' starts a comment.
static class P
{
    const int SCOPE_SYSTEM = 2, SHARE_SHARED = 2, PROTO_T0 = 1, PROTO_T1 = 2, LEAVE = 0;

    [StructLayout(LayoutKind.Sequential)] struct IO_REQUEST { public int dwProtocol; public int cbPciLength; }

    [DllImport("winscard.dll")] static extern int SCardEstablishContext(int scope, IntPtr r1, IntPtr r2, out IntPtr ctx);
    [DllImport("winscard.dll")] static extern int SCardReleaseContext(IntPtr ctx);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardConnectW")]
    static extern int SCardConnect(IntPtr ctx, string reader, int share, int prefProto, out IntPtr card, out int activeProto);
    [DllImport("winscard.dll")] static extern int SCardTransmit(IntPtr card, ref IO_REQUEST send, byte[] sbuf, int slen, IntPtr rpci, byte[] rbuf, ref int rlen);
    [DllImport("winscard.dll")] static extern int SCardDisconnect(IntPtr card, int disp);
    [DllImport("winscard.dll", CharSet = CharSet.Unicode, EntryPoint = "SCardStatusW")]
    static extern int SCardStatus(IntPtr card, byte[] reader, ref int readerLen, out int state, out int proto, byte[] atr, ref int atrLen);

    static string Hex(byte[] b, int n) { var sb = new StringBuilder(); for (int i = 0; i < n; i++) sb.Append(b[i].ToString("X2")).Append(' '); return sb.ToString().Trim(); }
    static byte[] Parse(string s)
    {
        int h = s.IndexOf('#'); if (h >= 0) s = s.Substring(0, h);
        var t = new StringBuilder(); foreach (var c in s) if (Uri.IsHexDigit(c)) t.Append(c);
        var hx = t.ToString(); var o = new byte[hx.Length / 2];
        for (int i = 0; i < o.Length; i++) o[i] = Convert.ToByte(hx.Substring(i * 2, 2), 16);
        return o;
    }

    static int Main(string[] a)
    {
        if (a.Length < 2) { Console.Error.WriteLine("usage: apduprobe \"<reader>\" <apdu-file> [--t0]"); return 2; }
        string reader = a[0]; string file = a[1];
        int pref = PROTO_T0 | PROTO_T1; for (int i = 2; i < a.Length; i++) if (a[i] == "--t0") pref = PROTO_T0;

        var lines = new List<string>();
        foreach (var ln in File.ReadAllLines(file)) { var p = ln.Trim(); if (p.Length == 0 || p.StartsWith("#")) continue; lines.Add(ln); }

        int rv = SCardEstablishContext(SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out var ctx);
        if (rv != 0) { Console.Error.WriteLine($"EstablishContext=0x{rv:X8}"); return 1; }
        rv = SCardConnect(ctx, reader, SHARE_SHARED, pref, out var card, out var active);
        if (rv != 0) { Console.Error.WriteLine($"Connect=0x{rv:X8}"); SCardReleaseContext(ctx); return 1; }

        var atr = new byte[64]; int atrLen = atr.Length; var rn = new byte[256]; int rnLen = rn.Length;
        SCardStatus(card, rn, ref rnLen, out _, out _, atr, ref atrLen);
        Console.WriteLine($"# reader   : {reader}");
        Console.WriteLine($"# protocol : T={(active == PROTO_T1 ? 1 : 0)}");
        Console.WriteLine($"# ATR      : {Hex(atr, atrLen)}");
        Console.WriteLine();

        var pci = new IO_REQUEST { dwProtocol = active, cbPciLength = 8 };
        foreach (var ln in lines)
        {
            byte[] apdu; try { apdu = Parse(ln); } catch { Console.WriteLine($"# skip (bad hex): {ln}"); continue; }
            if (apdu.Length < 4) { Console.WriteLine($"# skip (too short): {ln}"); continue; }
            var rbuf = new byte[65538]; int rlen = rbuf.Length;
            rv = SCardTransmit(card, ref pci, apdu, apdu.Length, IntPtr.Zero, rbuf, ref rlen);
            string tag = ln.Contains("#") ? ln.Substring(ln.IndexOf('#')) : "";
            if (rv != 0) { Console.WriteLine($">> {Hex(apdu, apdu.Length)}   {tag}"); Console.WriteLine($"!! SCardTransmit=0x{rv:X8}"); Console.WriteLine(); continue; }
            string sw = rlen >= 2 ? $"{rbuf[rlen - 2]:X2}{rbuf[rlen - 1]:X2}" : "----";
            int dlen = rlen >= 2 ? rlen - 2 : 0;
            Console.WriteLine($">> {Hex(apdu, apdu.Length)}   {tag}");
            Console.WriteLine($"<< SW={sw}  data({dlen}): {Hex(rbuf, dlen)}");
            Console.WriteLine();
        }
        SCardDisconnect(card, LEAVE);
        SCardReleaseContext(ctx);
        return 0;
    }
}
