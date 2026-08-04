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
экспортируемый файловый контейнер  →  PKCS#12 (p12utility --cptop12 / cptools / openssl)
```

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
  CertFromContainer.cs извлечение .cer из контейнера (CryptoAPI P/Invoke)
  P12Utility.cs        обёртка p12utility (--cprepair/--keyexport/--cppublic)
  ExportPipeline.cs    оркестратор полного цикла
  BundledTools.cs      вшитые зависимости и их распаковка в кэш
  RegFreeCom.cs        создание COM-объекта из DLL без регистрации в системе
  Diagnostics.cs       отчёт о зависимостях (команда deps, лог GUI)
  Cp1251.cs            декодер имён контейнеров
src/App/            приложение (WinForms + CLI)
  MainForm.cs          графический интерфейс со всплывающими подсказками
  Cli.cs               консольный режим
build/publish.ps1   портативная сборка одним exe
tools/              вшиваемые зависимости (p12utility.win32.exe, rtCOMLite.dll)
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

В лог при запуске выводится, откуда берутся зависимости и виден ли КриптоПро CSP.

**Консоль:**

```
CryptoProExport.exe deps
CryptoProExport.exe list
CryptoProExport.exe extractcert <containerName> <outDir>
CryptoProExport.exe export <destDir> [pin]
CryptoProExport.exe keyexport <folder> <cert.cer> [pass]
CryptoProExport.exe full <destDir> [cert.cer] [pin]
```

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
