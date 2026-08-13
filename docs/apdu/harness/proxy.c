/* proxy winscard.dll (x64): forwards every export to winscard_real.dll,
   hooks the PC/SC data-path calls and logs full APDUs to a file.
   Injection: place next to the process EXE so the loader resolves
   WinSCard.dll (imported by CryptoPro cpscard.dll/pcsc.dll) to this proxy. */
#include <windows.h>
#include <winscard.h>
#include <stdio.h>
#include "forwarders.h"   /* generated: /EXPORT pragmas (forwarders + hooked aliases + DATA) */

static CRITICAL_SECTION g_cs;
static FILE *g_log = NULL;
static HMODULE g_real = NULL;

/* ---- real function pointers (only the ones we hook) ---- */
typedef LONG (WINAPI *pConnectA)(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
typedef LONG (WINAPI *pConnectW)(SCARDCONTEXT, LPCWSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
typedef LONG (WINAPI *pTransmit)(SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE, DWORD, LPSCARD_IO_REQUEST, LPBYTE, LPDWORD);
typedef LONG (WINAPI *pControl)(SCARDHANDLE, DWORD, LPCVOID, DWORD, LPVOID, DWORD, LPDWORD);
typedef LONG (WINAPI *pBegin)(SCARDHANDLE);
typedef LONG (WINAPI *pEnd)(SCARDHANDLE, DWORD);
typedef LONG (WINAPI *pReconnect)(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD);
typedef LONG (WINAPI *pDisconnect)(SCARDHANDLE, DWORD);
typedef LONG (WINAPI *pStatusA)(SCARDHANDLE, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG (WINAPI *pStatusW)(SCARDHANDLE, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

static pConnectA   r_ConnectA;
static pConnectW   r_ConnectW;
static pTransmit   r_Transmit;
static pControl    r_Control;
static pBegin      r_Begin;
static pEnd        r_End;
static pReconnect  r_Reconnect;
static pDisconnect r_Disconnect;
static pStatusA    r_StatusA;
static pStatusW    r_StatusW;

/* ---- handle -> reader-name table (for labelling transmits) ---- */
#define MAXH 64
static struct { SCARDHANDLE h; wchar_t name[96]; } g_tab[MAXH];

static void tab_put(SCARDHANDLE h, const wchar_t *nm) {
    int i;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < MAXH; i++) if (g_tab[i].h == 0) { g_tab[i].h = h; if (nm) { wcsncpy(g_tab[i].name, nm, 95); g_tab[i].name[95] = 0; } break; }
    LeaveCriticalSection(&g_cs);
}
static const wchar_t *tab_get(SCARDHANDLE h) {
    int i;
    for (i = 0; i < MAXH; i++) if (g_tab[i].h == h) return g_tab[i].name;
    return L"?";
}

static void ensure(void) {
    if (g_real) return;
    EnterCriticalSection(&g_cs);
    if (!g_real) {
        g_real = LoadLibraryW(L"winscard_real.dll");
        if (g_real) {
            r_ConnectA   = (pConnectA)  GetProcAddress(g_real, "SCardConnectA");
            r_ConnectW   = (pConnectW)  GetProcAddress(g_real, "SCardConnectW");
            r_Transmit   = (pTransmit)  GetProcAddress(g_real, "SCardTransmit");
            r_Control    = (pControl)   GetProcAddress(g_real, "SCardControl");
            r_Begin      = (pBegin)     GetProcAddress(g_real, "SCardBeginTransaction");
            r_End        = (pEnd)       GetProcAddress(g_real, "SCardEndTransaction");
            r_Reconnect  = (pReconnect) GetProcAddress(g_real, "SCardReconnect");
            r_Disconnect = (pDisconnect)GetProcAddress(g_real, "SCardDisconnect");
            r_StatusA    = (pStatusA)   GetProcAddress(g_real, "SCardStatusA");
            r_StatusW    = (pStatusW)   GetProcAddress(g_real, "SCardStatusW");
        }
        if (!g_log) {
            char path[MAX_PATH];
            DWORD n = GetEnvironmentVariableA("WINSCARD_TRACE_LOG", path, MAX_PATH);
            if (n == 0 || n >= MAX_PATH) strcpy(path, "winscard-trace.log");
            g_log = fopen(path, "a");
        }
    }
    LeaveCriticalSection(&g_cs);
}

static void logline(const char *fmt, ...) {
    va_list ap;
    SYSTEMTIME st;
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    GetLocalTime(&st);
    fprintf(g_log, "%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

static void hexcat(char *dst, size_t cap, const BYTE *p, DWORD n) {
    size_t len = strlen(dst); DWORD i;
    for (i = 0; i < n && len + 3 < cap; i++) { sprintf(dst + len, "%02X ", p[i]); len += 3; }
}

/* ================= hooked exports ================= */
LONG WINAPI MyConnectA(SCARDCONTEXT ctx, LPCSTR reader, DWORD share, DWORD pref, LPSCARDHANDLE ph, LPDWORD proto) {
    LONG rv; ensure(); rv = r_ConnectA(ctx, reader, share, pref, ph, proto);
    if (rv == 0 && ph) { wchar_t w[96]; MultiByteToWideChar(CP_ACP, 0, reader ? reader : "", -1, w, 96); tab_put(*ph, w); }
    logline("CONNECT-A \"%s\" share=%lu pref=%lu -> hCard=%p proto=%lu rv=0x%08lX",
            reader ? reader : "", share, pref, ph ? (void*)*ph : 0, proto ? *proto : 0, rv);
    return rv;
}
LONG WINAPI MyConnectW(SCARDCONTEXT ctx, LPCWSTR reader, DWORD share, DWORD pref, LPSCARDHANDLE ph, LPDWORD proto) {
    LONG rv; char rn[96]; ensure(); rv = r_ConnectW(ctx, reader, share, pref, ph, proto);
    WideCharToMultiByte(CP_UTF8, 0, reader ? reader : L"", -1, rn, 96, 0, 0);
    if (rv == 0 && ph) tab_put(*ph, reader);
    logline("CONNECT-W \"%s\" share=%lu pref=%lu -> hCard=%p proto=%lu rv=0x%08lX",
            rn, share, pref, ph ? (void*)*ph : 0, proto ? *proto : 0, rv);
    return rv;
}
LONG WINAPI MyTransmit(SCARDHANDLE h, LPCSCARD_IO_REQUEST sPci, LPCBYTE sBuf, DWORD sLen,
                       LPSCARD_IO_REQUEST rPci, LPBYTE rBuf, LPDWORD rLen) {
    LONG rv; char rn[96]; DWORD got; char line[8192];
    ensure();
    WideCharToMultiByte(CP_UTF8, 0, tab_get(h), -1, rn, 96, 0, 0);
    /* Mask the data field of authentication commands so the PIN never lands in the log:
       VERIFY (INS 20) and CHANGE REFERENCE DATA (INS 24) carry the credential in cleartext. */
    if (sLen >= 4 && sBuf[0] == 0x00 && (sBuf[1] == 0x20 || sBuf[1] == 0x24)) {
        logline("[%s] hCard=%p >> APDU (%lu): %02X %02X %02X %02X Lc=%02X <PIN data masked>",
                rn, (void*)h, sLen, sBuf[0], sBuf[1], sBuf[2], sBuf[3], (sLen > 4 ? sBuf[4] : 0));
    } else {
        line[0] = 0; hexcat(line, sizeof(line), sBuf, sLen);
        logline("[%s] hCard=%p >> APDU (%lu): %s", rn, (void*)h, sLen, line);
    }
    rv = r_Transmit(h, sPci, sBuf, sLen, rPci, rBuf, rLen);
    got = (rLen ? *rLen : 0);
    line[0] = 0; hexcat(line, sizeof(line), rBuf, got);
    logline("[%s] hCard=%p << RESP (%lu): %s  rv=0x%08lX", rn, (void*)h, got, line, rv);
    return rv;
}
LONG WINAPI MyControl(SCARDHANDLE h, DWORD code, LPCVOID inB, DWORD inL, LPVOID outB, DWORD outL, LPDWORD ret) {
    LONG rv; char line[8192]; ensure();
    line[0] = 0; hexcat(line, sizeof(line), (const BYTE*)inB, inL);
    logline("hCard=%p CONTROL code=0x%08lX in(%lu): %s", (void*)h, code, inL, line);
    rv = r_Control(h, code, inB, inL, outB, outL, ret);
    { DWORD g = ret ? *ret : 0; line[0] = 0; hexcat(line, sizeof(line), (const BYTE*)outB, g);
      logline("hCard=%p CONTROL out(%lu): %s  rv=0x%08lX", (void*)h, g, line, rv); }
    return rv;
}
LONG WINAPI MyBegin(SCARDHANDLE h) { ensure(); return r_Begin(h); }
LONG WINAPI MyEnd(SCARDHANDLE h, DWORD d) { ensure(); return r_End(h, d); }
LONG WINAPI MyReconnect(SCARDHANDLE h, DWORD sh, DWORD pr, DWORD init, LPDWORD ap) {
    LONG rv; ensure(); rv = r_Reconnect(h, sh, pr, init, ap);
    logline("hCard=%p RECONNECT share=%lu pref=%lu init=%lu -> proto=%lu rv=0x%08lX",
            (void*)h, sh, pr, init, ap ? *ap : 0, rv);
    return rv;
}
LONG WINAPI MyDisconnect(SCARDHANDLE h, DWORD d) {
    LONG rv; ensure(); rv = r_Disconnect(h, d);
    logline("hCard=%p DISCONNECT disp=%lu rv=0x%08lX", (void*)h, d, rv);
    return rv;
}
LONG WINAPI MyStatusA(SCARDHANDLE h, LPSTR rn, LPDWORD rnl, LPDWORD st, LPDWORD pr, LPBYTE atr, LPDWORD atrl) {
    ensure(); return r_StatusA(h, rn, rnl, st, pr, atr, atrl);
}
LONG WINAPI MyStatusW(SCARDHANDLE h, LPWSTR rn, LPDWORD rnl, LPDWORD st, LPDWORD pr, LPBYTE atr, LPDWORD atrl) {
    ensure(); return r_StatusW(h, rn, rnl, st, pr, atr, atrl);
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID res) {
    (void)inst; (void)res;
    /* Keep DllMain minimal: no LoadLibrary/file IO here (loader lock).
       Real init happens lazily in ensure() from the first hooked call. */
    if (reason == DLL_PROCESS_ATTACH) { InitializeCriticalSection(&g_cs); DisableThreadLibraryCalls(inst); }
    return TRUE;
}
