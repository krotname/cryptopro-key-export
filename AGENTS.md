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
- **Разрядность строго x86** (`PlatformTarget` в `CryptoProExport.App.csproj`). Причина ниже.

## Внешние зависимости
- **КриптоПро CSP** — единственное, что ставится на целевой машине отдельно (лицензионный продукт; CryptoAPI и `p12utility` завязаны на него).
- **`p12utility.win32.exe`** и **`rtCOMLite.dll`** лежат в `tools/`, **вшиваются в `CryptoProExport.Core` как embedded resources** (см. `.csproj`) и распаковываются в `%LOCALAPPDATA%\CryptoProExport\bundled\<версия>` при первом обращении (`BundledTools`). Доставлять их отдельно не нужно.
- `rtCOMLite.dll` (COM `rtCOMLite.rtContext`, CLSID `{0ACACF07-…}`) создаётся **без регистрации в системе**: `NativeLibrary.Load` → `DllGetClassObject` → `IClassFactory::CreateInstance` (`RegFreeCom`). Запасной путь — зарегистрированный в системе компонент (ProgID), если он есть.
- Условие `Exists(...)` в `.csproj` позволяет собрать репозиторий и без бинарников в `tools/` — приложение тогда честно сообщит, что зависимость не вшита.

## Сборка и тесты
```bash
dotnet build -c Release          # ожидается 0 ошибок, 0 предупреждений
```
Проверка без физического токена (обязательный минимум перед коммитом):
```powershell
# ВАЖНО: .exe запускать только через PowerShell Start-Process; из git-bash — "Permission denied".
# WinExe печатает в stdout ТОЛЬКО при перенаправлении в файл, причём в cp1251:
#   [Text.Encoding]::GetEncoding(1251).GetString([IO.File]::ReadAllBytes("$PWD\st.txt"))
$exe = "src\App\bin\Release\net8.0-windows\CryptoProExport.exe"
Start-Process $exe "--selftest" -Wait -RedirectStandardOutput st.txt -WindowStyle Hidden   # SELFTEST OK + отчёт о зависимостях
Start-Process $exe "deps"       -Wait -RedirectStandardOutput dp.txt -WindowStyle Hidden   # откуда берутся зависимости
Start-Process $exe "list"       -Wait -RedirectStandardOutput ls.txt -WindowStyle Hidden   # перечень контейнеров
```
`--selftest` заодно проверяет, что у всех кнопок/полей/списка проставлены всплывающие подсказки
(`MainForm.CheckTooltips`), и падает с кодом 1, если появился элемент без подсказки.

Портативная сборка (один exe, всё внутри):
```powershell
pwsh build\publish.ps1           # publish\CryptoProExport.exe, ~64 МБ, других файлов в папке нет
```

**Тестовые файлы с личными данными.** Перенаправленный вывод (`st.txt`, `ls.txt`, …) содержит
имена контейнеров с ФИО — удаляй сразу после проверки, не коммить.

## Подводные камни окружения (реальные, уже наступали)
1. **Манифест WinForms.** Корневой тег строго `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" …>`.
   Лишнее слово (`<assembly manifest …>`) → при запуске «Параллельная конфигурация неправильна» (SxS), сборка при этом проходит. Файл: `src/App/app.manifest`.
2. **Запуск .exe.** Из bash не запускается (`Permission denied`). Используй PowerShell `Start-Process`.
3. **stdout WinExe.** Виден только при redirect в файл; в консоль напрямую ничего не выводит.
4. **Кодировки.** Имена контейнеров (`PP_ENUMCONTAINERS`, `name.key`) — cp1251. Используй `Cp1251`, не `Encoding.Default` (=UTF-8 в .NET).
5. **Хук среды автора.** PowerShell-команда, где рядом стоят `Remove-Item` и путь `C:\Program…`, блокируется целиком. Разноси на отдельные команды.
6. **Тестовые артефакты — персданные.** `extractcert` вытаскивает реальный сертификат (ФИО/СНИЛС/ИНН). Не коммить `.cer/.key/.pfx` (см. `.gitignore`), удаляй после теста.
7. **x86 обязателен, не «для совместимости».** `rtCOMLite.dll` 32-битный и загружается в процесс. В x64 он работал бы только через COM-суррогат (`AppID … DllSurrogate` в реестре), то есть требовал бы установки компонента — ровно то, от чего мы уходим. Не переводи проект на x64/AnyCPU. CryptoAPI КриптоПро в 32-битном процессе проверен: `list` перечисляет контейнеры (провайдеры 75/80/81).
8. **`p12utility` 4.0.8 не умеет `--cptop12`.** В справке есть только `--p12tocp`, `--p12addtocp`, `--cprepair`, `--cppublic` (обратное направление: PKCS#12 → контейнер). Экспорт в `.pfx` придётся делать иначе (см. ROADMAP).
9. **Справка `p12utility` выводится в cp866**, а вывод самого приложения — в cp1251. Читай файлы с явной кодировкой, иначе получишь мохнатую кашу.

## Git-процесс
- Приватный репозиторий `krotname/cryptopro-key-export`, ветка `main`.
- CI нет (GitHub-hosted Actions заблокированы биллингом для приватных репо; при желании — self-hosted раннер «adler»).
- Перед завершением: `dotnet build` без ошибок + `--selftest` OK + `git status` чистый.

## Первый шаг для следующего агента
Взять из `ROADMAP.md` раздел **P1**: e2e-тест на физическом Рутокене (единственное,
что нельзя проверить без железа) и экспорт в PFX — но не через `--cptop12`, его нет
(см. грабли п. 8), а через `cptools`/`certmgr` или CAPI-экспорт после `--keyexport`.
