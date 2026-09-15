# SafeNet Token JC (профиль PRO) — попытка физического E2E и точный блокер

Дата: 6 сентября 2026. Носитель расходный, тестовый; PIN/серийные приведены как
технические идентификаторы стенда, ключевого материала здесь нет.

> **РЕШЕНО 15.09.2026 — блокер снят, E2E воспроизведён.** Разбор ниже описывает состояние
> окружения на 6–7 сентября. Его центральный вывод («keyset-путь eToken PRO в КриптоПро мёртв,
> `0x8009001F` воспроизводится и на PROFELTORG») **опровергнут**: на 15.09.2026 `csptest -newkeyset`
> на эталонном eToken PRO PROFELTORG (`Aladdin Token JC`, серийный `00A7A257`, заводской PIN
> `1234567890`) проходит `AcquireContext` и создаёт контейнер с обоими ГОСТ-ключами, а
> CSP-free `tokenexport` снимает контейнер по APDU (баг декодера соли устранён в PR #108). Полный
> create(CSP)→read(CSP-free) E2E на eToken PRO подтверждён вживую — см. итог. Сам SafeNet-юнит
> `023721CD` в этой сессии заново не прогонялся, но блокер окружения, который его останавливал,
> устранён.

## Носитель

| Признак | Значение |
|---|---|
| PC/SC reader | `SafeNet Token JC 0` |
| USB | `VID_0529/PID_0620` |
| ATR | `3B D5 18 00 81 31 FE 7D 80 73 C8 21 10 F4` |
| Applet (SELECT) | `A0 00 00 03 12 02 02` (SafeNet/eToken) |
| PKCS#11 | manufacturer `Aladdin R.D.`, model `PRO`, serial `023721CD` |

ATR **побайтно совпадает** с рабочим eToken PRO `PROFELTORG` (`Aladdin Token JC 0`,
serial `00A7A257`) — см. [jacarta-pro.md](../apdu/jacarta-pro.md). Оба носителя КриптоПро
матчит на один carrier `safenet_pro`
(`HKLM\SOFTWARE\WOW6432Node\Crypto Pro\Cryptography\CurrentVersion\KeyCarriers\safenet_pro`:
`Folders=CC00\..\CC09`, `Mask/ATR` по маске, поле `DLL` пустое → generic `pcsc.dll`).

## Блокер

Создание контейнера штатным путём КриптоПро не проходит:

```
csptest -keyset -newkeyset -container "\\.\SafeNet Token JC 0\cpxt_safenet" \
        -provtype 80 -password <user-pin> -protected=none
ctkey.c:1110:AcquireContext(...) -> 0x8009001F (NTE_BAD_KEYSET_PARAM)
```

Ошибка возникает **в `AcquireContext`, мгновенно и без единой APDU к карте**
(снято APDU-прокси `winscard.dll`, харнесс `docs/apdu/harness`: при работающей трассировке
`-keyset -enum_cont -verifycontext` даёт полный APDU-лог, а `-newkeyset`/`-check` — пустой лог).

## Что проверено (и что это опровергло)

1. **Не оболочка.** Тот же результат из PowerShell с настоящими `\\.\` (ложный `0x8009001F`
   от искажённых bash-бэкслешей исключён).
2. **Структура карты (apduprobe, `SELECT`).** SafeNet: `66665000` ✓, соль `66665000/000F` ✓,
   сервисные объекты `0002/0003/0006/000A` ✓, но `66665000/E00E0B00` ✗ (`6A82`).
   PROFELTORG: `66665000/E00E0B00` **✓** (`9000`).
3. **Инициализация носителя нативным middleware.** Установлен SafeNet Authentication Client
   10.8-R9 (официальный MSI, подпись Thales DIS CPL валидна). SafeNet переинициализирован
   `eTPKCS11.dll` — `C_InitToken` + `C_InitPIN` (SO и user PIN заданы, `TOKEN_INITIALIZED`).
   `-newkeyset` — по-прежнему `0x8009001F` без APDU.
4. **Не кэш SCardSvr.** Реальный PnP remove/insert ридера (`Disable/Enable-PnpDevice`,
   инвалидирует per-card кэш ресурс-менеджера) результат не изменил.
5. **Не конфиг ридеров.** КриптоПро авто-обрабатывает PC/SC (`KeyDevices\PCSC\PNP PCSC`),
   отдельного `Readers`-ключа нет; для ESMART/HDIMAGE создание/чтение контейнеров работает.

## Ключевое наблюдение: блокер глобален для eToken PRO, а не про персонализацию SafeNet

Тот же `0x8009001F` без APDU воспроизводится на **PROFELTORG** — рабочем eToken PRO с тем же ATR,
у которого `E00E0B00` **присутствует** и на котором E2E проходил 27.08.2026. При этом
`csptest -enum_cont` сейчас показывает **ноль** контейнеров на обоих eToken-носителях
(`Aladdin Token JC` и `SafeNet Token JC`), тогда как контейнеры ESMART и HDIMAGE видны.

Отсюда:
- Наличие/отсутствие `E00E0B00` **не является** решающим фактором (PROFELTORG его имеет и всё равно
  падает) — прежняя гипотеза «нужно создать `E00E0B00`» снята.
- Установка SafeNet Authentication Client **причиной не является**: SafeNet давал тот же
  `0x8009001F` ещё до установки SAC; после установки картина не изменилась ни к лучшему, ни к
  худшему, крипто-путь для не-eToken (ESMART) не пострадал.
- Отказ лежит в **eToken-керриере КриптоПро** (`safenet_pro` / `pcsc.dll` без media-DLL): в текущем
  окружении путь keyset для eToken PRO не работает ни на создание, ни на чтение. Это отдельная
  регрессия окружения КриптоПро↔eToken, а не проблема воспроизведения персонализации SafeNet.

## Итог (обновлён 15.09.2026)

На 6–7 сентября физический E2E на eToken PRO не давался: `-newkeyset` падал `0x8009001F` в
`AcquireContext` (и на SafeNet, и на PROFELTORG). **К 15.09.2026 блокер окружения устранён** —
`csptest -newkeyset` на пустом PROFELTORG (`00A7A257`, заводской PIN `1234567890`) проходит
`AcquireContext`, создаёт контейнер `cpxt_verify_20260915` и генерирует оба ГОСТ-2012-ключа
(`a signature key created` + `an exchange key created`, `exit=0`); проектный CSP-free `tokenexport`
снимает контейнер по APDU без CryptoPro (6 файлов), декодер соли исправлен в PR #108. Контейнер
после проверки удалён (`deletekeyset`, `enum_cont` чист). Таким образом прежний вывод «keyset-путь
eToken PRO в КриптоПро мёртв как регрессия окружения» **снят**: полный create(CSP)→read(CSP-free)
E2E на eToken PRO воспроизведён. Read-путь распознавания (`JaCartaProApdu` принимает reader
`SafeNet Token JC` и `Aladdin Token JC`) остаётся в силе. Открытым остаётся лишь прогон на самом
SafeNet-юните `023721CD` (в этой сессии не запускался) — но средство, которое его блокировало, уже
работает на эталонном PROFELTORG.
