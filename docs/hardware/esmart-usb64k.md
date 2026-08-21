# ESMART Token USB 64K: read-only исследование

Дата проверки: 21.08.2026. Целевое устройство идентифицировалось одновременно по всем
признакам ниже; индекс считывателя сам по себе не использовался:

- USB ID `VID_072F&PID_90DE`;
- точное имя PC/SC reader `ESMART Token USB 64K 0`;
- ATR `3B BE 96 00 00 42 06 21 00 00 00 00 00 00 00 00 00 90 00`;
- реестровый профиль `CP_ESMARTToken_64`.

Другой ESMART reader с `VID_2CE4&PID_7479` и состоянием Code 10 в исследование не входил.

## Границы безопасности

Исследование было строго read-only:

- `C_Login` не вызывался, попытки PIN не тратились;
- контейнеры, сертификаты и объекты не создавались, не менялись и не удалялись;
- прямой APDU-harness не использовался, из нашего кода `SCardTransmit` не вызывался,
  записывающие APDU не отправлялись; внутренний обмен vendor PKCS#11 не трассировался;
- ESMART PKI Client не устанавливался;
- серийные номера, метки объектов, сертификаты и иные персональные данные не сохранялись.

## USB, PC/SC и CSP

Windows определила устройство как `Microsoft Usbccid (WUDF)`, класс `SmartCardReader`,
состояние `OK`, `ConfigManagerErrorCode=0`. Используется inbox-драйвер Microsoft
`wudfusbcciddriver.inf` версии 10.0.26100.3323; служба `SCardSvr` работала в режиме
`Running/Automatic`.

Ограниченная проверка `SCardConnect(shared)` + `SCardStatus` по точному reader завершилась
успешно: активный протокол T=0, состояние `0x6`, ATR совпал с указанным выше. После чтения
статуса соединение закрыто с `SCARD_LEAVE_CARD`; прямого `SCardTransmit` не было.

В обеих ветках реестра (32 и 64 бит) профиль
`HKLM\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\CP_ESMARTToken_64` связывает этот
ATR с `Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider`. Профиль
`HKLM\SOFTWARE\ISBC CORP\PKCS11\EsmartToken64` содержит тот же ATR и указывает backend
`isbc_esmart_token_mod.dll`.

`csptest -keyset -enum_cont -fqcn` при четырёх подключённых считывателях не завершился в
ограниченное время; остановлен только запущенный для проверки процесс. Из этого нельзя делать
вывод ни о наличии, ни об отсутствии контейнеров ESMART.

## Подтверждённый PKCS#11-модуль

Официальное руководство ESMART документирует пару Windows DLL:

- `isbc_pkcs11_main.dll` — точка входа Cryptoki, которую передают как PKCS#11 module;
- `isbc_esmart_token_mod.dll` — backend ESMART Token, который должен лежать рядом.

Для ручной установки руководство предписывает копировать **обе** DLL в системный каталог
Windows соответствующей разрядности. Поэтому приложение ищет только подтверждённый entry
module `isbc_pkcs11_main.dll` в системных x86/x64 каталогах. Оно намеренно не ищет случайные
копии в `Program Files`.

На исследованной машине стандартная полная пара отсутствовала и в `System32`, и в
`SysWOW64`. В каталогах CryptoPro CSP присутствовала только `isbc_pkcs11_main.dll` версии
4.0.1.0, без `isbc_esmart_token_mod.dll`; такая неполная копия не добавлена как fallback.

Для read-only probe использована уже находившаяся в Saby x86-пара версии 4.0.1.0:

`C:\Program Files (x86)\Tensor\Saby\26.4200.583\service\modules\ClientCryptography\crypto-libs`

Обе DLL имеют валидную Authenticode-подпись. Контрольные суммы проверенных файлов:

| Файл | SHA-256 |
|---|---|
| `isbc_pkcs11_main.dll` | `2A76FBE00BB1B0553CA29C9C391F90616FCAFBFFFE916F44A409FBAF198BCD4F` |
| `isbc_esmart_token_mod.dll` | `A4ADC63D05936D9BD3E4F56FD43FB3CA186895DC9F6DC7C3299B54E3260DD92A` |

## Результат probe без PIN

Probe запускался в 32-битном процессе, companion загружался явно, затем выполнялись только
`C_Initialize`, `C_GetInfo`, `C_GetSlotList`, `C_GetSlotInfo` и, для точного reader,
`C_GetTokenInfo`.

- `CK_INFO`: Cryptoki 2.40, manufacturer `ISBC`, library version 1.0;
- `C_GetSlotList(CK_FALSE)` вернул три slot, включая точный
  `ESMART Token USB 64K 0` и виртуальный `ISBC ESMART Token 0`;
- `C_GetSlotList(CK_TRUE)` вернул 0 slot;
- `C_GetTokenInfo` для точного reader вернул `CKR_TOKEN_NOT_PRESENT`.

Поэтому `CK_TOKEN_INFO` и публичные объекты в этой конфигурации получить не удалось.
Это **не** означает, что на токене нет объектов: PC/SC одновременно видел карту и её ATR,
а использованная пара была прикладной копией без установленного полного системного стека.
Согласно руководству ESMART, сертификаты и открытые ключи относятся к публичным объектам и
читаются без PIN; повторять проверку после штатной установки полной пары можно по тому же
read-only сценарию, всё так же без `C_Login`.

В отдельном x86-процессе одновременно удерживались загруженными
`rtPKCS11ECP.dll`, `jcPKCS11-2.dll` и `isbc_pkcs11_main.dll`; все три библиотеки успешно
выполнили `C_GetSlotList`. Это подтверждает, что существующая модель приложения — загрузить
все доступные vendor libraries, мягко пережить сбой одной и дедуплицировать reader — применима
и после добавления ESMART.

## Что изменено в приложении

- `isbc_pkcs11_main.dll` добавлена третьей в `Pkcs11Token.KnownLibraries`;
- для ESMART используются только системные candidates правильной разрядности, а main-only
  путь, отсутствующий companion или несовпадающая PE-архитектура двух DLL отбрасываются до
  попытки загрузки;
- строки `ESMART` и `ISBC` классифицируются как сторонний smart-card token;
- отсутствие ESMART PKI Client отражено в диагностике на всех 20 языках.

Приложение не поставляет PKCS#11 DLL внутри portable exe. Для реальной диагностики ESMART
полная пара соответствующей разрядности должна быть установлена в системе отдельно.

## Проверенный пакет и официальные источники

Страница загрузок на дату проверки предлагала ESMART PKI Client 4.17 для Windows x86/x64.
Скачанный по этой ссылке ZIP имел SHA-256
`16527284529ED83744B4C4A0D156280518527D4610C32D9FEF513242CA2D62A8`, при этом вложенный
подписанный `setup.exe` сообщал file/product version 4.13.1.0. Пакет только исследован и не
запускался на установку.

- [ESMART Token — загрузки](https://token.esmart.ru/downloads)
- [ESMART Token — PKCS#11](https://cdn.esmart.ru/token/docs/manuals/ESMART%20-%20PKCS11.pdf)
- [ESMART PKI Client — руководство администратора](https://cdn.esmart.ru/token/docs/manuals/ESMART%20PKI%20Client%20-%20Administrative%20manual%20%282%29.pdf)
- [Описание ESMART Token](https://cdn.esmart.ru/token/docs/manuals/ESMART%20Token%20-%20Overview.pdf)
