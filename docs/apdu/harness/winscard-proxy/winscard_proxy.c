/* Нативный x64 proxy для winscard.dll — перехват APDU между CryptoPro CSP и картой.
 *
 * Все экспорты (кроме SCardTransmit) форвардятся в winscard_orig.dll через winscard.def
 * (см. gen-def.py). SCardTransmit логирует APDU (команду и ответ) в файл и вызывает настоящий.
 * Лог: путь из переменной окружения WINSCARD_APDU_LOG, иначе winscard_apdu.log рядом.
 *
 * Сборка (MinGW-w64):
 *   python gen-def.py                 # winscard.def из экспортов системного winscard.dll
 *   cp C:/Windows/System32/winscard.dll ./winscard_orig.dll
 *   gcc -O2 -shared -o winscard.dll winscard_proxy.c winscard.def -lkernel32
 *
 * Использование: положить winscard.dll + winscard_orig.dll рядом с копией csptest.exe и
 * запускать её оттуда (loader берёт winscard.dll из каталога exe первым). Для .NET-хостов
 * apphost жёстко ищет DLL — там прокси грузят явным NativeLibrary.Load(путь).
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG (WINAPI *PFN_Transmit)(SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE, DWORD,
                                    LPSCARD_IO_REQUEST, LPBYTE, LPDWORD);

static PFN_Transmit g_real = NULL;
static CRITICAL_SECTION g_cs;
static int g_init = 0;
static FILE *g_log = NULL;

static void ensure(void)
{
    if (!g_real) {
        HMODULE h = LoadLibraryA("winscard_orig.dll");
        if (h) g_real = (PFN_Transmit)GetProcAddress(h, "SCardTransmit");
    }
    if (!g_log) {
        char *p = getenv("WINSCARD_APDU_LOG");
        g_log = fopen(p ? p : "winscard_apdu.log", "a");
    }
}

static void dump(const char *pfx, const BYTE *b, DWORD n, LONG rv)
{
    if (!g_log) return;
    fputs(pfx, g_log);
    for (DWORD i = 0; i < n; i++) fprintf(g_log, "%02X", b[i]);
    if (rv != 0x7fffffff) fprintf(g_log, " rv=0x%08lX", (unsigned long)rv);
    fputc('\n', g_log);
    fflush(g_log);
}

LONG WINAPI SCardTransmit(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSend, LPCBYTE pbSend,
                          DWORD cbSend, LPSCARD_IO_REQUEST pioRecv, LPBYTE pbRecv, LPDWORD pcbRecv)
{
    EnterCriticalSection(&g_cs);
    ensure();
    dump("> ", pbSend, cbSend, 0x7fffffff);
    LONG rv = -1;
    if (g_real) {
        rv = g_real(hCard, pioSend, pbSend, cbSend, pioRecv, pbRecv, pcbRecv);
        DWORD n = (pcbRecv && pbRecv) ? *pcbRecv : 0;
        dump("< ", pbRecv, n, rv);
    } else if (g_log) {
        fputs("! winscard_orig SCardTransmit not resolved\n", g_log);
        fflush(g_log);
    }
    LeaveCriticalSection(&g_cs);
    return rv;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        if (!g_init) { InitializeCriticalSection(&g_cs); g_init = 1; }
    }
    return TRUE;
}
