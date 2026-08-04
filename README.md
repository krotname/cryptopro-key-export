# CryptoPro Key Export

Утилита для экспорта **собственных** ключевых контейнеров КриптоПро с Рутокена и снятия
запрета на экспорт закрытого ключа. Предназначена для владельца ключей: резервное
копирование, миграция контейнера, конвертация в PKCS#12.

Собрана из двух механизмов:

1. **Снятие контейнера с Рутокена** — через COM-компонент `rtCOMLite.rtContext`
   (порт логики утилиты Контура «Проверка Рутокенов» / `tokens.hta`). Читает файловую
   память токена напрямую, минуя КриптоПро CSP, поэтому запрет на экспорт ключа
   на уровне CSP не мешает снять 6 файлов контейнера (`*.key`).
2. **Снятие запрета на экспорт** — вызов КриптоПро `p12utility --cprepair --keyexport`
   (перезаписывает `header.key`, помечая ключ экспортируемым). Сертификат для операции
   извлекается из контейнера автоматически через CryptoAPI
   (`CryptGetKeyParam(KP_CERTIFICATE)`), пока токен вставлен.

## Полный конвейер

```
Рутокен (неэкспортируемый ключ)
   │  rtCOMLite: SelectMF → EnumFiles → ReadBinary
   ▼
папка с контейнером (name/header/primary/masks/primary2/masks2 .key)
   │  CryptoAPI: CryptAcquireContext → CryptGetUserKey → CryptGetKeyParam(KP_CERTIFICATE)
   ▼
cert_exchange.cer / cert_signature.cer
   │  p12utility --cprepair --container_folder . --cert … --keyexport
   ▼
экспортируемый файловый контейнер (header.key вырастает до ~3 КБ)
   │  установка в CSP: копия папки в хранилище HDIMAGE + имя в name.key
   ▼
контейнер виден КриптоПро и работает без токена
   │  certmgr -install … && certmgr -export -pfx
   ▼
PKCS#12 (.pfx) — сертификат вместе с закрытым ключом
```

Проверить, что запрет действительно снят, можно в любой момент: программа читает
права ключа (`KP_PERMISSIONS`) и показывает, взведён ли флаг `CRYPT_EXPORT`.

## Требования (на целевой машине)

- **Windows** + **КриптоПро CSP** (проверено на CSP 5.0 R2, build 15873) — единственное,
  что нужно установить отдельно: это лицензионный продукт, его CryptoAPI-провайдер вшить нельзя.
- **Больше ничего скачивать и доставлять не нужно.** `p12utility.win32.exe` и `rtCOMLite.dll`
  вшиты в приложение и распаковываются в `%LOCALAPPDATA%\CryptoProExport\bundled\<версия>`
  при первом обращении. `rtCOMLite` загружается **без регистрации в системе и без прав
  администратора** (`DllGetClassObject` → `IClassFactory`), устанавливать
  «компонент диагностики Рутокен» не требуется.
- Приложение **32-битное** — так вшитый 32-битный `rtCOMLite.dll` грузится прямо в процесс.
- Поддерживаются Рутокен S / Lite (файловый контейнер в памяти токена).
  Рутокен ЭЦП 2.0 с аппаратным неизвлекаемым ключом так не выгрузить.

Проверить готовность окружения одной командой:

```
CryptoProExport.exe deps
```

## Структура

```
src/Core/           библиотека (net8.0-windows)
  RutokenExporter.cs   экспорт контейнера с токена (rtCOMLite, late-binding COM)
  CertFromContainer.cs извлечение .cer и проверка прав ключа (CryptoAPI P/Invoke)
  P12Utility.cs        обёртка p12utility (--cprepair/--keyexport/--cppublic)
  CertMgr.cs           обёртка certmgr: сертификат в хранилище + экспорт в .pfx
  ContainerStore.cs    установка контейнера в хранилище CSP (HDIMAGE)
  ExportPipeline.cs    оркестратор полного цикла
  BundledTools.cs      вшитые зависимости и их распаковка в кэш
  RegFreeCom.cs        создание COM-объекта из DLL без регистрации в системе
  ProcessRunner.cs     запуск утилит КриптоПро с чтением вывода в cp866
  CryptoErrors.cs      расшифровка кодов CryptoAPI и смарт-карт
  NameKey.cs           разбор и сборка name.key (имя контейнера)
  SessionLog.cs        журнал сеанса в %LOCALAPPDATA%
  Cp1251.cs / Cp866.cs кодеки для имён контейнеров и вывода утилит
  Diagnostics.cs       отчёт о зависимостях (команда deps, лог GUI)
src/App/            приложение (WinForms + CLI)
  MainForm.cs          графический интерфейс со всплывающими подсказками
  PromptDialog.cs      ввод имени контейнера и пароля PFX
  Cli.cs               консольный режим
tests/              юнит-тесты (xunit)
build/publish.ps1   портативная сборка одним exe
tools/              вшиваемые зависимости (p12utility.win32.exe, rtCOMLite.dll)
.github/workflows/  CI: сборка, тесты, самопроверка, артефакт
```

## Сборка

```bash
dotnet build -c Release
```

Портативная сборка — один `.exe`, внутри и .NET, и обе нативные зависимости:

```powershell
pwsh build\publish.ps1
```

На выходе `publish\CryptoProExport.exe` (~64 МБ), в папке больше ничего нет.

## Использование

**Графический интерфейс** — запустить `CryptoProExport.exe` без аргументов.
У каждой кнопки и поля есть всплывающая подсказка: что делает, что для этого нужно
и что получится. Порядок работы:

1. *Обновить список* — показать контейнеры (видимые CSP + на подключённых Рутокенах).
2. *Экспорт с токена* — снять контейнеры в папку назначения.
3. *Извлечь сертификат* — сохранить `.cer` выбранного контейнера.
4. *Сделать экспортируемым* — полный цикл в один клик.
5. *Проверить ключ* — убедиться, что запрет на экспорт снят.
6. *Установить в КриптоПро* — чтобы снятый контейнер работал без токена.
7. *Экспорт в PFX* — выгрузить контейнер в `.pfx` вместе с закрытым ключом.
8. *Журнал* — открыть папку с журналами работы.

В лог при запуске выводится, откуда берутся зависимости и виден ли КриптоПро CSP.

**Консоль:**

```
CryptoProExport.exe deps
CryptoProExport.exe list
CryptoProExport.exe extractcert <containerName> <outDir>
CryptoProExport.exe checkexport <containerName>
CryptoProExport.exe export <destDir> [pin]
CryptoProExport.exe keyexport <folder> <cert.cer> [pass]
CryptoProExport.exe install <folder> [name]
CryptoProExport.exe installed
CryptoProExport.exe uninstall <folder>
CryptoProExport.exe topfx <containerName> <out.pfx> [password]
CryptoProExport.exe full <destDir> [cert.cer] [pin]
```

Типичный сценарий без токена под рукой — контейнер уже снят в папку:

```
CryptoProExport.exe keyexport C:\backup\mykey C:\backup\mykey\cert_exchange.cer
CryptoProExport.exe install   C:\backup\mykey "Мой ключ (копия)"
CryptoProExport.exe checkexport "Мой ключ (копия)"
CryptoProExport.exe topfx     "Мой ключ (копия)" C:\backup\mykey.pfx пароль
```

Журналы каждого запуска — в `%LOCALAPPDATA%\CryptoProExport\logs`. Пароли в них не пишутся.

## Развитие

План дальнейшей разработки и приоритеты — [ROADMAP.md](ROADMAP.md).
Контекст и рабочие процессы для разработчика/LLM-агента — [AGENTS.md](AGENTS.md).

## Происхождение

Логика снятия с токена восстановлена из открытого `tokens.hta` (JScript внутри
NSIS-обёртки `Tokens.exe`, СКБ Контур). `p12utility` — штатная утилита КриптоПро.
`rtCOMLite.dll` — «Библиотека Rutoken COM Lite» компании «Актив» (v1.0.3.1),
распространяемый компонент диагностики Рутокен; вшит в приложение, чтобы его
не приходилось устанавливать отдельно.
Проект переиспользует эти механизмы для законной работы владельца со своими ключами.
