# Отчёт: настройка CryptoPro CSP и E2E подключённых токенов — 10.09.2026

## Результат

CryptoPro CSP 5.0.13800 на `ADLER-WHITE-W1` настроен на неинтерактивный ДСЧ CPSD.
Четыре подключённых пассивных носителя прошли полный цикл
`создание → …98 → tokenfull → HDIMAGE → …9C → два PFX`.
Активный JaCarta-2 GOST ожидаемо отклонён до запроса PIN и без записи. Два носителя
PRO распознаны, их пустые публичные слоты больше не ломают `list`. В локальной
консольной сессии создание контейнера дошло до штатной аутентификации; тестовый
процесс остановлен до ввода PIN, контейнеры `cpxt_probe_*` не появились.

## CSP и ДСЧ

- Провайдер: Crypto-Pro GOST R 34.10-2012, type 80; версия CSP 5.0.13800.
- Зарегистрирован `Random\CPSD\Default` с `Level=1`; `Bio\Default` оставлен с
  `Level=10`. Штатный `csptest PP_ENUMRANDOMS` видит оба источника и выбирает CPSD.
- Рабочая порция: `%LOCALAPPDATA%\CryptoProExport\cpsd-e2e\portion-300C4A3C`,
  после четырёх генераций осталось две порции (по 144 байта в `db1/db2`).
- Перед изменением ветка Random сохранена на домашнем сервере:
  `F:\backup\cryptopro-key-export\csp-random\20260910-013612\random.reg`,
  SHA-256 `4EC7662E0BFB34604E86366E3C8F95C2B80011BADEA566DEF2D4D1AEAA3A8023`.
- Схема `CPSD\Default`, значения `/db1/kis_1`, `/db2/kis_1` и приоритет `Level=1`
  соответствует [описанию КриптоПро](https://cryptopro.ru/forum2/default.aspx?g=posts&t=3809).

## Матрица подключённых носителей

| Reader | Профиль | Проверка | Результат |
|---|---|---|---|
| `ARDS ZAO JaCarta LT 0` | пассивный JaCarta LT | полный E2E `cpxt_0910_jclt1_a4e9` | обе пары `…98 → …9C`; PFX проверены |
| `Aladdin R.D. JaCarta LT 0` | пассивный JaCarta LT | полный E2E `cpxt_0910_jclt2_b5f0` | обе пары `…98 → …9C`; PFX проверены |
| `ESMART Token Nano 192K 0` | пассивный ESMART | полный E2E `cpxt_0910_esnano_c6a1` | обе пары `…98 → …9C`; PFX проверены |
| `Feitian SCR301 0` | ESMART Token ГОСТ MIK51 | полный E2E третьего слота `cpxt_0910_esgost_d7b2` | обе пары `…98 → …9C`; PFX проверены |
| `ARDS JaCarta 0` | активный JaCarta-2 GOST | отрицательный production-flow | код 3, точное сообщение «не подходит»; 0 файлов, PIN не запрашивался |
| `Aladdin Token JC 0` | eToken PRO | public APDU + проба создания | пустой `CC00` корректно пропущен; CSP дошёл до аутентификации, запись не начата |
| `SafeNet Token JC 0` | профиль PRO | public APDU + проба создания | пустой `CC00` корректно пропущен; CSP дошёл до аутентификации, запись не начата |

## PFX-квитанции

| Тег | Native PFX SHA-256 | CSP PFX SHA-256 |
|---|---|---|
| `cpxt_0910_jclt1_a4e9` | `7E1EA3605604A8474DA4567212AC8958AE436073D16BEA4525AD554620F39FDC` | `5B1CBD773D4693889377AEFF7DBEAF17E89299D0A219F2FB35F8C8505EB37D20` |
| `cpxt_0910_jclt2_b5f0` | `778862A291D9B301A5EA6A61A49DE4C22F88BD8670ABE7B16ED20E8BC68C1296` | `33A128C56D1C9C481C018DFD042C7233D18F240DD8D03D601B997CECE4020BC7` |
| `cpxt_0910_esnano_c6a1` | `3E8C0949FF512FAA794B5AEBEE7BA6885450A486D3A66A3315BC1AFE0C16CEAA` | `F9C4614F23A4D140C8DD2B80F78461CA36BD36B83BD487E1145D53907A50BB7F` |
| `cpxt_0910_esgost_d7b2` | `C9F86717ADC7B933FA187889341848D3CBE59CE4725013706414C1E41B6BBB32` | `D0CF932CF4673435F4175AB7A9DFBA1D708C004B400A72E21476C3920C33CEF2` |

Все native PFX приняты OpenSSL (MAC, key bag, certificate bag), CSP PFX —
`certutil` с ожидаемым CryptoPro provider и HDIMAGE container.

## Исправленные дефекты

1. В `make-token-container.ps1` структура Win32 `INPUT` была длиннее нативной из-за
   лишних полей, поэтому `SendInput` не кормил Био ДСЧ. Исправлены layout, чтение
   текста дочерних контролов и движение в указанном диалогом направлении.
2. Nano 192K отсутствовал в точном allowlist reader, а portable-комплект не содержал
   его backend DLL. Добавлен строгий индексированный профиль и полный набор
   подписанных backend-модулей из [ESMART PKI Client 4.17](https://token.esmart.ru/downloads).
3. `EsmartGostApdu` считал, что номер контейнера хранится в `7F0X`. Прямой read-only
   scan карты показал три группы `F01x/F02x/F03x` внутри общего `8F01/7F01`.
   Адресация исправлена; `list` теперь показывает все три контейнера, а третий прошёл E2E.
4. PRO-backend считал нулевой 256-байтовый `name` незанятого `CC00` повреждённым
   DER и обрывал диагностику. Такой точный пустой слот теперь пропускается; ненулевой
   повреждённый объект по-прежнему останавливает обход.

## Верификация кода

- `dotnet build CryptoProExport.slnx -c Release -warnaserror`: 0 ошибок,
  0 предупреждений.
- Целевые тесты APDU/PKCS#11/resources: 221/221.
- Portable x86: `SELFTEST OK`, форма и подсказки проверены на 20 языках,
  7 аппаратных reader, CSP и встроенный ESMART-комплект найдены.
- Финальный полный xUnit, очистка синтетики и CI фиксируются перед закрытием отчёта.

## Осталось для двух PRO

Предыдущий `0x8009001F` воспроизводился из неинтерактивной session 0. После перевода
рабочей сессии на локальную консоль и настройки CPSD обе пробы `-newkeyset` не
завершились этой ошибкой, а открыли штатную аутентификацию. Для продолжения нужен
сохранённый пользовательский PIN; Vaultwarden после мастер-пароля требует физический
security-key factor. До него PIN не подбирался и счётчик попыток не расходовался.
