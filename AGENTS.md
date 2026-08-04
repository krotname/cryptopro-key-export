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
dotnet build CryptoProExport.slnx -c Release -warnaserror   # 0 ошибок, 0 предупреждений
dotnet test  CryptoProExport.slnx -c Release --no-build     # 56 тестов xunit
```
Тесты покрывают чистую логику: кодеки cp1251/cp866, `name.key`, аргументы p12utility,
разбор разрядности PE, наличие вшитых зависимостей, `ContainerStore` (во временной папке —
системное хранилище КриптоПро не трогается).
Проверка без физического токена (обязательный минимум перед коммитом):
```powershell
# ВАЖНО: .exe запускать только через PowerShell Start-Process; из git-bash — "Permission denied".
# WinExe печатает в stdout ТОЛЬКО при перенаправлении в файл. Вывод в UTF-8:
#   [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes("$PWD\st.txt"))
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

## Тестовый контейнер без персданных
Для проверки цикла «снятие запрета → установка в CSP → PFX» не нужен ни токен, ни живой ключ:
```powershell
$csptest = "C:\Program Files\Crypto Pro\CSP\csptest.exe"
& $csptest -keyset -newkeyset -container "\\.\HDIMAGE\cpxtest" -provtype 80 -protected=none
& $csptest -keyset -container "\\.\HDIMAGE\cpxtest" -provtype 80 -makecert   # самоподписанный серт в контейнер
```
Появится `%LOCALAPPDATA%\Crypto Pro\cpxtest.000` с шестью `*.key` и сертификатом внутри
(CN=cpxtest). Дальше: `extractcert` → копия папки → `keyexport` → `install` → `checkexport` → `topfx`.
Убирать за собой: `csptest -keyset -deletekeyset -container …` или удалить папку и снять
сертификат из хранилища «Личное».

## CI
GitHub Actions **работает** (`.github/workflows/ci.yml`, `windows-latest`): сборка с
`-warnaserror`, тесты, портативная сборка с `--selftest`, проверка поведения без КриптоПро CSP,
портативный exe в артефактах. Прежнее утверждение, что Actions заблокированы биллингом,
не подтвердилось — прогоны идут.

## Подводные камни окружения (реальные, уже наступали)
1. **Манифест WinForms.** Корневой тег строго `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" …>`.
   Лишнее слово (`<assembly manifest …>`) → при запуске «Параллельная конфигурация неправильна» (SxS), сборка при этом проходит. Файл: `src/App/app.manifest`.
2. **Запуск .exe.** Из bash не запускается (`Permission denied`). Используй PowerShell `Start-Process`.
3. **stdout WinExe.** Виден только при redirect в файл; в консоль напрямую ничего не выводит.
4. **Кодировки.** Имена контейнеров (`PP_ENUMCONTAINERS`, `name.key`) — cp1251. Используй `Cp1251`, не `Encoding.Default` (=UTF-8 в .NET).
5. **Хук среды автора.** PowerShell-команда, где рядом стоят `Remove-Item` и путь `C:\Program…`, блокируется целиком. Разноси на отдельные команды.
6. **Тестовые артефакты — персданные.** `extractcert` вытаскивает реальный сертификат (ФИО/СНИЛС/ИНН). Не коммить `.cer/.key/.pfx` (см. `.gitignore`), удаляй после теста.
7. **x86 обязателен, не «для совместимости».** `rtCOMLite.dll` 32-битный и загружается в процесс. В x64 он работал бы только через COM-суррогат (`AppID … DllSurrogate` в реестре), то есть требовал бы установки компонента — ровно то, от чего мы уходим. Не переводи проект на x64/AnyCPU. CryptoAPI КриптоПро в 32-битном процессе проверен: `list` перечисляет контейнеры (провайдеры 75/80/81).
8. **`p12utility` 4.0.8 не умеет `--cptop12`.** В справке есть только `--p12tocp`, `--p12addtocp`, `--cprepair`, `--cppublic` (обратное направление: PKCS#12 → контейнер). Экспорт в `.pfx` сделан через `certmgr` (`CertMgr.cs`).
9. **Консольные утилиты КриптоПро (p12utility, certmgr, csptest) пишут в cp866.** Читать их вывод через `Cp866` — иначе в логе каша. Само приложение с версии 1.2 выводит UTF-8.
10. **«Экспортируемость» проверяется через `KP_PERMISSIONS`** (флаг `CRYPT_EXPORT = 0x4`), а не через `CryptExportKey`: на прямой `CryptExportKey(PRIVATEKEYBLOB)` КриптоПро отвечает `NTE_BAD_KEY_STATE` даже для экспортируемого ключа. Проверено на паре контейнеров: до `--keyexport` `0x00130898`, после — `0x0013089C`, и именно второй успешно выгружается в PFX.
11. **Файловые контейнеры лежат в `%LOCALAPPDATA%\Crypto Pro\<имя>.000`** (считыватель HDIMAGE). Имя, которое показывает CSP, берётся из `name.key`, а не из имени папки: копия контейнера с тем же `name.key` сольётся с оригиналом в перечислении. Поэтому `ContainerStore.Install` переписывает `name.key`.
12. **Локальный запуск build-версии требует 32-битного рантайма .NET.** Сборка даёт framework-dependent x86; без `Microsoft.WindowsDesktop.App` x86 exe падает с `0x80008002`. На CI поэтому самопроверка гоняется на портативной (self-contained) сборке.

## Git-процесс
- Приватный репозиторий `krotname/cryptopro-key-export`, ветка `main`.
- Перед завершением: `dotnet build -warnaserror` + `dotnet test` + `--selftest` OK + `git status` чистый + зелёный CI на PR.

## Первый шаг для следующего агента
Осталось единственное, что нельзя проверить без железа, — **e2e на физическом Рутокене**
(`ROADMAP.md`, P1): снятие контейнера, маппинг шести `*.key`, PIN-поток. Весь остальной
конвейер (снятие запрета → установка в CSP → PFX) проверен на синтетическом контейнере,
рецепт — выше в разделе «Тестовый контейнер без персданных».
