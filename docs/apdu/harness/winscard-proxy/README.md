# winscard-proxy — нативный перехват APDU CSP↔карта

x64 proxy-DLL для `winscard.dll`. Форвардит все 80 экспортов системного `winscard.dll` в его
копию `winscard_orig.dll`, кроме `SCardTransmit` — тот логирует APDU (команду и ответ) и вызывает
настоящий. CryptoPro CSP ходит к карте через системный PC/SC (`cpscard.dll` → `pcsc.dll` →
`winscard.dll`), поэтому перехват на `winscard.dll` видит **все** APDU.

Альтернатива без сборки — frida-хук того же `SCardTransmit` (см. `docs/apdu/jacarta-pro.md`,
раздел «Как снята трасса»). Оба дают одинаковый результат; нативный прокси не требует Python-рантайма
в целевом процессе и удобен для .NET-хостов.

## Сборка (MinGW-w64)

```bash
pip install pefile
python gen-def.py                                   # winscard.def из экспортов системной DLL
cp /c/Windows/System32/winscard.dll ./winscard_orig.dll
gcc -O2 -shared -o winscard.dll winscard_proxy.c winscard.def -lkernel32
```

`winscard_orig.dll` (копия системной DLL) и собранный `winscard.dll` — **локальные артефакты, не
коммитятся**: перераспространять системную библиотеку Windows нельзя, а прокси легко пересобрать.

## Использование

Нативный exe (csptest и т.п.) — loader берёт `winscard.dll` из каталога самого exe первым:

```powershell
$dir = "путь-к-прокси"
Copy-Item "C:\Program Files\Crypto Pro\CSP\csptest.exe" "$dir\csptest.exe"
$env:WINSCARD_APDU_LOG = "$dir\apdu.log"
# путь контейнера с пробелами обязательно в кавычках внутри одной строки аргументов:
Start-Process "$dir\csptest.exe" -WorkingDirectory $dir -Wait `
  -ArgumentList '-keycopy -contsrc "\\.\Aladdin Token JC 0\<контейнер>" -contdest "\\.\HDIMAGE\x" -pinsrc <PIN> -silent'
```

.NET-хост (apphost жёстко ищет DLL, app-local не срабатывает) — загрузить прокси явно первым:
`System.Runtime.InteropServices.NativeLibrary.Load(@"...\winscard.dll")` до первого обращения к PC/SC.

## Формат лога

```
> 00A408040C66665000E00E0B00CC02F002FE        (команда APDU)
< 30440420…9000 rv=0x00000000                 (ответ; хвост SW и код winscard)
```
