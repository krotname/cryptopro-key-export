# JaCarta на платформе Athena IDProtect — минидрайверный носитель (обезличенно)

Сеанс на живом экземпляре 23.08.2026. Все данные обезличены: серийники, метки и персональные
контейнеры не приводятся.

## Точная идентификация носителя

| Признак | Значение |
|---------|----------|
| Считыватель (PC/SC) | `Aladdin R.D. JaCarta 0` |
| Модель карты (certutil `-scinfo`) | `IDProtect (X)` — платформа Athena IDProtect / Laser |
| Криптопровайдер | Microsoft Base Smart Card Crypto Provider (минидрайвер), контейнер по умолчанию — пуст |
| USB | `VID_24DC&PID_0402`, статус `OK` |
| ATR | `3B DC 18 FF 81 91 FE 1F C3 80 73 C8 21 13 66 01 06 11 59 00 01 28` |
| Тип чипа | JavaCard / GlobalPlatform (CPLC читается) |

**Не путать** с уже описанными носителями:
- JaCarta PRO (`docs/apdu/jacarta-pro.md`) — считыватель `Aladdin Token JC 0`, модель `PRO`, ГОСТ,
  закрытый ключ снимается по APDU. Другая карта и другой апплет.
- JaCarta LT (PR #44) — USB `24DC:0102`, PKCS#11-модель `JaCarta DS` / Datastore. Другой USB ID и
  другой протокол; здесь модель по семейству **не угадывается**.

Exact-target закреплён по совокупности `reader + VID/PID + ATR + модель`, а не по slot index.

## Что показали прямые опыты

### PKCS#11 — токена нет ни в одной установленной библиотеке
Пробник только на чтение (`token-session/slotprobe`, `GetSlotList` по всем слотам):

| Библиотека | Что вернула |
|------------|-------------|
| `asepkcs.dll` («JaCarta PKCS#11 module» 2.09) | 0 слотов вообще |
| `jcPKCS11-2.dll` | 32 фантомных слота, `tokenPresent=False` во всех |
| `jcPKCS11ds.dll` | 0 слотов |
| `isbc_pkcs11_main.dll` (ISBC/ESMART) | 1 слот `Aladdin R.D. JaCarta 0`, `tokenPresent=False` |

Значит `Pkcs11Token.Enumerate` корректно отдаёт 0 токенов, а команда `token` — код 2. Это **не** сбой:
установленный PKCS#11-стек не поддерживает апплет этой карты (её ATR нет в их списках), она
обслуживается только минидрайвером Microsoft.

### CryptoPro CSP — контейнер на этой карте не создаётся
- `csptest -card -enum` — карта видна как считыватель `Aladdin R.D. JaCarta 0`;
- `csptest -keyset -enum_cont -fqcn` — на карте **нет** ни одного контейнера КриптоПро (только HDIMAGE);
- `csptest -keyset -newkeyset -silent` на этой карте — **`AcquireContext` падает 0x80090016
  (`NTE_KEYSET_NOT_DEF`)**, то есть носитель не может держать keyset;
- контроль на HDIMAGE тем же `-silent` — `AcquireContext` проходит, а падение позже, на `GenKey`,
  с `0x80090022` (`NTE_SILENT_CONTEXT`, «нужен диалог»). Разница кодов доказывает: на JaCarta
  IDProtect отказ именно на уровне носителя, а не из-за тихого контекста.

### APDU — JavaCard/GlobalPlatform
Прямой пробник (`docs/apdu/harness/apduprobe`, только чтение):
- `SELECT` (A4) по MF и по AID → `6D00` (нет ISO-файловой системы, апплет не выбирается без прав);
- `GET DATA` CPLC (`00 CA 9F 7F`) → `9000`, 42 байта Card Production Life Cycle — карта отвечает как
  JavaCard/GP.

## Граница (доказана построением, а не выведена из флага)

Эта JaCarta IDProtect — минидрайверная JavaCard. Она **не несёт контейнера КриптоПро**, **не является
PKCS#11-токеном**, и **CryptoPro не может создать на ней контейнер** (`NTE_KEYSET_NOT_DEF`).
Экспортировать этим инструментом с такого носителя **нечего** — не потому, что путь не найден, а
потому, что на нём нет ни ключа КриптоПро, ни доступного PKCS#11-объекта.

Разрешение владельца на разрушительные тесты на этом экземпляре имелось; менять тип носителя
(инициализировать как PKI-токен через JaCarta Unified Client) смысла нет: полученные так ключи были бы
CNG/PKCS#11-ключами PKI, а не контейнерами КриптоПро, и всё равно вне задачи инструмента.

## Что сделано в коде

Правильная поддержка такого носителя = **честная диагностика**, а не ложный экспорт:
- `PcscReaders` (Core) — пассивное перечисление считывателей PC/SC поверх `winscard`
  (`SCardGetStatusChange` с нулевым тайм-аутом, **без подключения** к карте — не мешает ни CSP, ни
  соседнему токену);
- `PcscReaders.Uncovered` — карты, физически стоящие в PC/SC, но не показанные ни одной библиотекой
  PKCS#11; `CarrierHintKey` — подсказка о вендоре по имени считывателя;
- `deps`, `list`, `token` теперь показывают такую карту с именем считывателя, вендором и ATR, вместо
  того чтобы молча свести всё к «токенов нет (проверьте драйверы Рутокен)». `token` остаётся
  fail-closed (код 2 — экспортировать нечего).

## Как воспроизвести за минуту

```powershell
# 1) точная идентификация (ATR + модель)
certutil -scinfo                                   # reader, IDProtect (X), ATR, провайдер минидрайвера
# 2) PKCS#11 — токена нет
dotnet token-session/slotprobe/bin/Release/net10.0/slotprobe.dll C:\Windows\System32\asepkcs.dll
# 3) CSP не создаёт контейнер (0x80090016), в отличие от HDIMAGE (0x80090022)
& 'C:\Program Files\Crypto Pro\CSP\csptest.exe' -keyset -newkeyset -container "\\.\Aladdin R.D. JaCarta 0\probe" -provtype 80 -silent
# 4) диагностика приложения
publish\CryptoProExport.exe deps --lang ru         # секция «Карты в считывателях PC/SC без PKCS#11-токена»
```
