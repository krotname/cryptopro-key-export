# SafeNet Token JC (профиль PRO) — попытка физического E2E и точный блокер

Дата: 6 сентября 2026. Носитель расходный, тестовый; PIN/серийные приведены как
технические идентификаторы стенда, ключевого материала здесь нет.

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

## Итог

Физический E2E на SafeNet не достигнут. Read-путь распознавания (`JaCartaProApdu` принимает reader
`SafeNet Token JC`) не затронут и остаётся в силе. Следующий шаг — разбираться не с картой, а с
eToken-керриером КриптоПро (почему `safenet_pro`/`jacarta.dll` не отдаёт keyset для eToken PRO в
этом окружении, включая ранее рабочий PROFELTORG); синтетический контейнер имеет смысл повторять
только после восстановления этого пути на эталонном PROFELTORG.
