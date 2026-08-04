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

- **Windows** + **КриптоПро CSP** (проверено на CSP 5.0 R2, build 15873).
- **`p12utility.win32.exe`** — рядом с приложением (лежит в `tools/`, копируется при сборке).
- **`rtComLite.dll`** — «компонент диагностики Рутокен» Контура
  (устанавливается из `https://help.kontur.ru/rtComLite.exe`), нужен только для чтения с токена.
- Поддерживаются Рутокен S / Lite (файловый контейнер в памяти токена).
  Рутокен ЭЦП 2.0 с аппаратным неизвлекаемым ключом так не выгрузить.

## Структура

```
src/Core/           библиотека (net8.0-windows)
  RutokenExporter.cs   экспорт контейнера с токена (rtCOMLite, late-binding COM)
  CertFromContainer.cs извлечение .cer из контейнера (CryptoAPI P/Invoke)
  P12Utility.cs        обёртка p12utility (--cprepair/--keyexport/--cppublic)
  ExportPipeline.cs    оркестратор полного цикла
  Cp1251.cs            декодер имён контейнеров
src/App/            приложение (WinForms + CLI)
  MainForm.cs          графический интерфейс
  Cli.cs               консольный режим
tools/p12utility.win32.exe   зависимость КриптоПро
```

## Сборка

```bash
dotnet build -c Release
```

Автономная сборка со всеми зависимостями .NET:

```bash
dotnet publish src/App -c Release -r win-x64 --self-contained ^
  -p:PublishSingleFile=false -o publish
```

## Использование

**Графический интерфейс** — запустить `CryptoProExport.exe` без аргументов:

1. *Обновить список* — показать контейнеры (видимые CSP + на подключённых Рутокенах).
2. *Экспорт с токена* — снять контейнеры в папку назначения.
3. *Извлечь сертификат* — сохранить `.cer` выбранного контейнера.
4. *Сделать экспортируемым* — полный цикл в один клик.

**Консоль:**

```
CryptoProExport.exe list
CryptoProExport.exe extractcert <containerName> <outDir>
CryptoProExport.exe export <destDir> [pin]
CryptoProExport.exe keyexport <folder> <cert.cer> [pass]
CryptoProExport.exe full <destDir> [cert.cer] [pin]
```

## Происхождение

Логика снятия с токена восстановлена из открытого `tokens.hta` (JScript внутри
NSIS-обёртки `Tokens.exe`, СКБ Контур). `p12utility` — штатная утилита КриптоПро.
Проект переиспользует эти механизмы для законной работы владельца со своими ключами.
