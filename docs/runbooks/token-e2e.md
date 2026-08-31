# Полный E2E нового токена: от синтетического контейнера до PFX

Runbook проверенного цикла регрессии для нового физического носителя. Задача —
доказать, что утилита снимает неэкспортируемый закрытый ключ КриптоПро именно по
APDU (мимо CSP), не читая боевых ключей владельца. Метод: создать **свой**
синтетический неэкспортируемый двухключевой контейнер прямо на токене, прогнать
`tokenfull → install → checkexport → PFX`, затем удалить только своё.

Проверено 30.08.2026 разом на семи носителях: Рутокен S, Рутокен Lite, eToken
PRO, два ESMART, две JaCarta LT (AGENTS.md п.43).

## 0. Безопасность (обязательно)

- **Боевые контейнеры владельца не трогать.** Работать только со своими
  контейнерами с префиксом `cpxt_`. Читающие команды (`list`, `tokenexport`,
  `tokenfull`) сам токен не изменяют, но экспорт боевого ключа на диск запрещён.
- **До и после — снять baseline** и сверить, что состояние совпало:
  ```powershell
  & "C:\Program Files\Crypto Pro\CSP\csptest.exe" -keyset -enum_cont -verifycontext -fqcn | Select-String '\\\.\'
  ```
- **Идентифицировать целевой носитель по ATR/VID/PID, а не по имени считывателя.**
  Имена вводят в заблуждение: reader `Aladdin R.D. JaCarta LT 0` в одном сеансе —
  рабочая JaCarta LT, в п.40 карта с тем же ATR — мёртвая IDProtect. См.
  [../hardware/jacarta-idprotect.md](../hardware/jacarta-idprotect.md).

## 1. Подготовка

```powershell
# Портативная сборка (self-contained x86) — локальный build-exe без x86-рантайма не запустится
cd <repo>; pwsh build\publish.ps1        # publish\CryptoProExport.exe
$exe = 'publish\CryptoProExport.exe'
$csptest = 'C:\Program Files\Crypto Pro\CSP\csptest.exe'
```

Экспортные команды закрыты лицензией (`LicenseGate`) — на тестовой машине лицензия
уже установлена, `tokenfull` проходит. Если нет — `license`/`fingerprint`, выпуск
через `keytool issue-license` в `krotname/license-server`.

### PIN известных носителей (см. `secrets.txt`, вне гита)

| Носитель | PIN |
|---|---|
| Рутокен S / Lite / ЭЦП | `12345678` (заводской) |
| eToken PRO «PROFELTORG» | `1122` |
| ESMART (ISBC/64K) | `12345678` (заводской) |
| JaCarta LT / DS | `1234567890` (заводской) |

`-password` у `csptest` на смарт-карте **служит PIN'ом носителя** (контейнер при
`-protected=none` остаётся беспарольным). Поэтому в командах ниже `-password <PIN>`.

## 2. Идентификация токенов

```powershell
& $csptest -card -enum -v          # считыватели + ATR
& $exe list --lang ru              # модель, APDU-бэкенд, контейнеры (redirect в файл для stdout)
```
`list` для каждого контейнера печатает `[APDU <технический-id>] <имя>`, например
`[APDU rutokens_0B00] cpxt_s`. **Технический id и есть селектор `--container`.**

## 3. Создать синтетический неэкспортируемый контейнер на токене

```powershell
# Ключи генерируются на носителе, обе пары неэкспортируемы. Скрипт закрывает
# модальные окна (Био ДСЧ — движением мыши SendInput, прочие — WM_COMMAND IDOK).
pwsh token-session\make-token-container.ps1 -ContainerPath "\.\<reader>\cpxt_<tag>" -Password <PIN> -TimeoutSec 200

# Самоподписанный сертификат в контейнер. -password ОБЯЗАТЕЛЕН, иначе makecert
# зависнет на диалоге «Аутентификация — КриптоПро CSP» (наблюдалось на ESMART).
& $csptest -keyset -container "\.\<reader>\cpxt_<tag>" -provtype 80 -makecert -password <PIN>
```
Проверить, что baseline действительно неэкспортируемый (флага `CRYPT_EXPORT` нет):
```powershell
& $exe checkexport cpxt_<tag> --lang ru    # ждём 0x00130098 / 0x00122898 (…98, НЕ …9C)
```
Если ключ уже `…9C` — это **экспортируемый** образец, он ничего не доказывает
(CSP штатно копирует такой ключ с любого носителя). Годен только `…98`.

## 4. Снять контейнер по APDU и снять запрет (ядро теста)

```powershell
$out = "<scratch>\<tag>"; New-Item -ItemType Directory -Force $out | Out-Null
# технический id берётся из вывода list (шаг 2)
& $exe tokenfull "<reader>" "$out" <PIN> --container <технический-id> --lang ru
```
Ожидаемо: `[APDU]` читает шесть `*.key`, извлекается сертификат, `p12utility
--cprepair --keyexport` помечает ключ(и) экспортируемыми, `header.key` растёт
~1.3 КБ → ~3 КБ. Токен при этом **только читается**.

## 5. Установка в CSP и доказательство экспортируемости

```powershell
& $exe install "$out\<технический-id>" --lang ru     # HDIMAGE-копия, видна CSP
& $exe checkexport cpxt_<tag> --lang ru              # ждём 0x0013089C / 0x0012289C (…9C)
```
`…9C` на обоих ключах — главное доказательство: запрет на экспорт снят.

## 6. PFX (обе ветки)

```powershell
& $exe extractpfx "$out\<технический-id>" "$out\<tag>.pfx" <pfx-pass> "" --lang ru   # для OpenSSL
& $exe topfx cpxt_<tag> "$out\<tag>_cp.pfx" <pfx-pass> --lang ru                     # для КриптоПро (certmgr)
certutil -p <pfx-pass> -dump "$out\<tag>_cp.pfx" | Select-String 'Provider|Container'
```

## 7. Уборка (удалять ТОЛЬКО своё `cpxt_*`)

```powershell
# a) контейнер с токена. На смарт-картах требует интерактивный PIN даже с -password:
& $csptest -keyset -deletekeyset -container "\.\<reader>\cpxt_<tag>" -provtype 80 -password <PIN>
#    Рутокен S/Lite и одна JaCarta так удаляются; ESMART и вторая JaCarta показывают
#    диалог «Аутентификация — КриптоПро CSP» — PIN в него вводится только SendInput
#    (WM_SETTEXT не работает), затем Enter. CryptAcquireContext(CRYPT_DELETEKEYSET)
#    на этих контейнерах даёт 0x8009001F — не годится, чистить через csptest.

# b) HDIMAGE-копии (без PIN):
& $csptest -keyset -deletekeyset -container "\.\HDIMAGE\cpxt_<tag>" -provtype 80

# c) сертификаты из «Личное»:
Get-ChildItem Cert:\CurrentUser\My | ? { $_.Subject -like '*CN=cpxt_*' } |
  % { Remove-Item ("Cert:\CurrentUser\My\" + $_.Thumbprint) -Force }
```
Затем сверить `enum_cont` с baseline из шага 0 — расхождений быть не должно.

## Особенности по семействам (грабли, уже наступавшие)

| Носитель | Бэкенд | Раскладка результата | Заметки |
|---|---|---|---|
| Рутокен S | `RutokenSApdu` | одна папка, оба ключа | `rtCOMLite` не использовать |
| Рутокен Lite | `RutokenLiteApdu` | **две** папки `_exchange`/`_signature` | контейнеры = DF-индексы `lite_XX` |
| eToken PRO | `JaCartaProApdu` | **две** папки | `--container` обязателен, только технический `jacartapro_XX` |
| JaCarta LT | `JaCartaLtApdu` | одна папка, оба ключа | несколько контейнеров различаются байтом Type в таблице объектов (0x03, 0x0E…) — см. AGENTS п.43 |
| ESMART (оба) | `EsmartApdu` | одна папка | `makecert`/`deletekeyset` показывают PIN-диалог; нужен `-password`/SendInput |

- **Селектор `--container` матчит технический `OutputName`** (`rutokens_0B00`,
  `jacartalt_0F`), а не видимое имя. При вводе имени — «Контейнер «…» не найден».
- **stdout WinExe виден только при redirect в файл**; читать в UTF-8. `.exe` из
  git-bash не запускается — только `Start-Process`.
- Ветки Lite/PRO дают контейнеры `<имя> [exchange]`/`[signature]` — `checkexport`
  каждой отдельно.
