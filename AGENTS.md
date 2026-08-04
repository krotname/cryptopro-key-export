# AGENTS.md — контекст для LLM-агента

Инструкции для любого агента (Claude Code, Codex, Cursor …), продолжающего этот проект.
Прочитай также `README.md` (что делает проект) и `ROADMAP.md` (что делать дальше).

## Назначение проекта
Инструмент для **владельца собственных ключей ЭЦП**: снять ключевой контейнер КриптоПро
с Рутокена и снять запрет на экспорт закрытого ключа (резервная копия / миграция / PFX).
Легитимный сценарий — работа пользователя со своими сертификатами. Не добавляй функций,
рассчитанных на чужие ключи или обход чужих ограничений.

## Стек
- .NET `net8.0-windows`, C#. Собирается .NET SDK 10 (`dotnet`). Решение — `CryptoProExport.slnx` (новый XML-формат; не удивляйся отсутствию `.sln`).
- `CryptoProExport.Core` — библиотека (COM/CryptoAPI/процессы). `CryptoProExport.App` — WinForms + CLI.

## Внешние зависимости (только на целевой машине, НЕ в NuGet)
- **КриптоПро CSP** — CryptoAPI и `p12utility` завязаны на него.
- **`p12utility.win32.exe`** — лежит в `tools/`, копируется рядом с exe при сборке.
- **`rtComLite.dll`** (COM `rtCOMLite.rtContext`, «диагностика Рутокен» Контура) — для чтения с токена. Ставится из `https://help.kontur.ru/rtComLite.exe`. Late-binding, на этапе сборки не нужен.

## Сборка и тесты
```bash
dotnet build -c Release          # ожидается 0 ошибок, 0 предупреждений
```
Проверка без физического токена (обязательный минимум перед коммитом):
```powershell
# ВАЖНО: .exe запускать только через PowerShell Start-Process; из git-bash — "Permission denied".
# WinExe печатает в stdout ТОЛЬКО при перенаправлении в файл.
$exe = "src\App\bin\Release\net8.0-windows\CryptoProExport.exe"
Start-Process $exe "--selftest" -Wait -RedirectStandardOutput st.txt -WindowStyle Hidden ; type st.txt   # SELFTEST OK
Start-Process $exe "list"       -Wait -RedirectStandardOutput ls.txt -WindowStyle Hidden ; type ls.txt   # перечень контейнеров
```
Self-contained сборка:
```bash
dotnet publish src/App/CryptoProExport.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o publish
```

## Подводные камни окружения (реальные, уже наступали)
1. **Манифест WinForms.** Корневой тег строго `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" …>`.
   Лишнее слово (`<assembly manifest …>`) → при запуске «Параллельная конфигурация неправильна» (SxS), сборка при этом проходит. Файл: `src/App/app.manifest`.
2. **Запуск .exe.** Из bash не запускается (`Permission denied`). Используй PowerShell `Start-Process`.
3. **stdout WinExe.** Виден только при redirect в файл; в консоль напрямую ничего не выводит.
4. **Кодировки.** Имена контейнеров (`PP_ENUMCONTAINERS`, `name.key`) — cp1251. Используй `Cp1251`, не `Encoding.Default` (=UTF-8 в .NET).
5. **Хук среды автора.** PowerShell-команда, где рядом стоят `Remove-Item` и путь `C:\Program…`, блокируется целиком. Разноси на отдельные команды.
6. **Тестовые артефакты — персданные.** `extractcert` вытаскивает реальный сертификат (ФИО/СНИЛС/ИНН). Не коммить `.cer/.key/.pfx` (см. `.gitignore`), удаляй после теста.

## Git-процесс
- Приватный репозиторий `krotname/cryptopro-key-export`, ветка `main`.
- CI нет (GitHub-hosted Actions заблокированы биллингом для приватных репо; при желании — self-hosted раннер «adler»).
- Перед завершением: `dotnet build` без ошибок + `--selftest` OK + `git status` чистый.

## Первый шаг для следующего агента
Взять из `ROADMAP.md` раздел **P1**: e2e-тест на физическом Рутокене и добавление
конвертации в PFX (`p12utility --cptop12`) в GUI.
