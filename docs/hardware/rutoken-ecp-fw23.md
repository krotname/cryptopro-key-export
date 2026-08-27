# Рутокен ЭЦП fw 23.02: полный отрицательный E2E

Дата актуальной проверки: 27 августа 2026 года. Проверен собственный расходный
тестовый носитель. Серийный номер, PIN, случайные ID объектов и содержимое
сертификата намеренно не сохраняются.

## Точная идентификация

| Признак | Проверенное значение |
|---|---|
| PC/SC reader | `Aktiv Rutoken ECP 0` |
| USB | `VID_0A89/PID_0030` |
| ATR | `3B 8B 01 52 75 74 6F 6B 65 6E 20 44 53 20 C1` |
| PKCS#11 module | системная `rtPKCS11ECP.dll` |
| manufacturer / model | `Aktiv Co.` / `Rutoken ECP` |
| hardware / firmware | `20.05` / `23.02` |
| механизмы | 46 |

USB PID, ATR и model не доказывают поколение по отдельности. Вывод о профиле
ЭЦП 2.x основан на полном наборе механизмов и их `CK_MECHANISM_INFO`:

| Возможность | Актуальный readback |
|---|---|
| RSA key generation/sign/encrypt | аппаратно, 512–2048 бит |
| ГОСТ key generation/sign | аппаратно |
| `CKM_EC_KEY_PAIR_GEN`, ECDSA/ECDH | отсутствуют |
| PIN safety | `COUNT_LOW=false`, `FINAL_TRY=false`, `LOCKED=false` |

## Исходное состояние

До входа пять классов объектов дали общий счётчик 0. Заводской тестовый PIN
разрешено было использовать только после read-only-проверки флага
`CKF_USER_PIN_TO_BE_CHANGED` и безопасного счётчика. Выполнен один успешный
`C_Login`; после него authenticated baseline также остался нулевым.

Это отличает текущий расходный экземпляр от исторического пользовательского
снимка, где присутствовали публичные объекты и аппаратные ключи. Исторический
снимок подтверждал диагностику приложения, но не используется как источник
текущего состояния и не раскрывается в этом документе.

## Object и certificate CRUD

В одной read-write PKCS#11-сессии с уникальным техническим префиксом выполнены:

1. `CKO_DATA`: create → read `CKA_VALUE` → update → повторный read.
2. `CKO_CERTIFICATE`: create валидного короткоживущего тестового X.509 DER →
   read `CKA_VALUE` → update `CKA_LABEL` → повторный read.
3. Все созданные объекты зарегистрированы для обязательного удаления в
   `finally`; чужие объекты по пустому baseline отсутствовали.

## Аппаратный private key

На токене сгенерирована RSA-2048 пара через аппаратный
`CKM_RSA_PKCS_KEY_PAIR_GEN`. Для private key явно заданы
`CKA_SENSITIVE=true` и `CKA_EXTRACTABLE=false`. Readback объекта подтвердил:

| Атрибут | Значение |
|---|---|
| `CKA_EXTRACTABLE` | `false` |
| `CKA_SENSITIVE` | `true` |
| `CKA_ALWAYS_SENSITIVE` | `true` |
| `CKA_NEVER_EXTRACTABLE` | `true` |

Ключ использован по назначению, не извлекаясь из чипа:

- `C_Sign` с `CKM_SHA256_RSA_PKCS` создал 256-байтовую подпись;
- `C_Verify` на токене подтвердил подпись;
- независимая host-проверка по публичным modulus/exponent также успешна.

Обе попытки получить закрытый материал закончились отрицательно:

- `CKA_VALUE` вернулся как unreadable attribute;
- `C_WrapKey` вернул `CKR_KEY_NOT_WRAPPABLE`.

Обход аппаратной политики, смена `CKA_EXTRACTABLE` и импорт копии private key не
предпринимались.

## Уборка и независимый readback

В `finally` удалены пять созданных объектов: data, certificate, public key,
private key и session wrapping key. Authenticated final count — 0. После выхода
отдельная read-only-инвентаризация вновь подтвердила:

- точную identity и 46 механизмов;
- 0 объектов во всех пяти классах;
- заводской флаг остаётся установлен;
- `COUNT_LOW`, `FINAL_TRY` и `LOCKED` не установлены.

## Пользовательская граница

Для точного профиля ЭЦП 2.x результат закрыт как **полностью отрицательный**:
аппаратный private key можно генерировать и использовать для подписи, но нельзя
прочитать или обернуть. Это свойство чипа, а не недостающая команда
CryptoProExport. Приложение предоставляет read-only диагностику и выгрузку
публичного сертификата, если он существует, но не обещает резервную копию
аппаратного закрытого ключа.

## Первичные источники производителя

- [Официальный пакет драйверов и PKCS#11](https://www.rutoken.ru/support/download/pkcs/)
- [Матрица механизмов PKCS#11 для ЭЦП 2.0/3.0](https://dev.rutoken.ru/pages/viewpage.action?pageId=3178538)
- [Сценарии RSA/ECDSA для ЭЦП 2.0/3.0](https://dev.rutoken.ru/pages/viewpage.action?pageId=180715764)
- [PID 0030 используется ЭЦП 2.0 и 3.0](https://dev.rutoken.ru/display/KB/RU1013)
- [Спецификация и неоднозначность ATR/model](https://dev.rutoken.ru/pages/viewpage.action?pageId=81527047)
- [Аппаратная генерация неизвлекаемых ключей](https://dev.rutoken.ru/display/KB/RU1081)
