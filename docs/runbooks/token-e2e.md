# Полный E2E нового токена: от синтетического контейнера до PFX

Runbook проверенного цикла регрессии для нового физического носителя. Задача —
доказать, что утилита снимает неэкспортируемый закрытый ключ КриптоПро именно по
APDU (мимо CSP), не читая боевых ключей владельца. Метод: создать **свой**
синтетический неэкспортируемый двухключевой контейнер прямо на токене, прогнать
`tokenfull → install → checkexport`, затем удалить только своё.

Проверено 30.08.2026 разом на семи носителях: Рутокен S, Рутокен Lite, eToken
PRO, два ESMART, две JaCarta LT (AGENTS.md п.43).

## 0. Безопасность (обязательно)

- **Боевые контейнеры владельца не трогать.** Работать только со своими
  контейнерами с префиксом `cpxt_`. Читающие команды (`list`, `tokenexport`,
  `tokenfull`) сам токен не изменяют, но экспорт боевого ключа на диск запрещён.
- **До и после — снять baseline** и сверить, что состояние совпало
  (`-SimpleMatch`, иначе шаблон `\\.\` — невалидное регулярное выражение):
  ```powershell
  & "C:\Program Files\Crypto Pro\CSP\csptest.exe" -keyset -enum_cont -verifycontext -fqcn |
    Select-String -SimpleMatch '\\.\'
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

### Как читать вывод WinExe

`.exe` — WinExe: в консоль он ничего не печатает, stdout виден **только** при
перенаправлении в файл, и запускать его надо через `Start-Process` (из git-bash —
`Permission denied`). Дальше по тексту используется помощник:

```powershell
function Run($a){                        # $a — аргументы CryptoProExport.exe
  $o = [IO.Path]::GetTempFileName()
  $p = Start-Process $exe $a -Wait -PassThru -RedirectStandardOutput $o -WindowStyle Hidden
  Write-Host "EXIT=$($p.ExitCode)"
  [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($o))   # приложение печатает UTF-8
  Remove-Item $o -ErrorAction SilentlyContinue
}
```

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
& $csptest -card -enum -v     # считыватели + ATR (csptest — консольный, печатает сразу)
Run 'list --lang ru'          # модель, APDU-бэкенд, контейнеры (через Run — из-за WinExe)
```
`list` для каждого контейнера печатает `[APDU <технический-id>] <имя>`, например
`[APDU rutokens_0B00] cpxt_s`. **Технический id и есть селектор `--container`**
(матч по нему, а не по видимому имени).

**Обязательно (AGENTS §19–21): до любой записи сопоставить выбранный reader с
VID/PID и, где есть, серийником — имена считывателей вводят в заблуждение.**

```powershell
# reader ↔ USB VID/PID (+ серийник в хвосте InstanceId, напр. Rutoken S) и карта ↔
# CID. Перечисляем ПО КЛАССУ, без allowlist вендоров — иначе новый VID (например
# eToken PRO — VID_0529) выпал бы из инвентаря ровно на новом носителе.
Get-PnpDevice -PresentOnly -Class SmartCardReader, SmartCard |
  Select-Object Class, FriendlyName, InstanceId | Sort-Object Class | Format-Table -Wrap
# reader ↔ ATR — из вывода `csptest -card -enum -v` выше; серийник токена также
# виден в дампе PKCS#11 (`token`/`list`) у моделей, которые его отдают.
```
Зафиксировать точную строку reader (например `Aktiv Co. ruToken 0`), её ATR и
VID/PID — и подставлять именно её во все команды §3–§7. Если рядом два похожих
носителя (две JaCarta LT!), различать по ATR/VID/PID, а не по имени.

## 3. Создать синтетический неэкспортируемый контейнер на токене

```powershell
# Тег обязан быть свободен ВО ВСЕХ пространствах имён HDIMAGE. Иначе install (§5)
# создаст вторую физическую папку с тем же логическим именем, и уборка (§7) не
# отличит твою копию от чужой — снесёт чужой контейнер с закрытым ключом. HDIMAGE
# в enum_cont не «немеет» (в отличие от токен-ридеров, см. §7), проверка надёжна.
$csp = & $csptest -keyset -enum_cont -verifycontext -fqcn 2>&1
foreach ($n in @("cpxt_<tag>", "cpxt_<tag> [exchange]", "cpxt_<tag> [signature]")) {
  if ($csp -match [regex]::Escape("\HDIMAGE\$n")) { throw "HDIMAGE уже содержит '$n' — выбери другой тег" }
}
# И сертификат: прерванный прогон мог оставить cert CN=cpxt_<tag> без контейнера,
# тогда чистка по subject (§7c) снесла бы чужой. Резервируем и это пространство имён.
if (Get-ChildItem Cert:\CurrentUser\My | ? { $_.Subject -match 'CN=cpxt_<tag>(,|$)' }) {
  throw "в «Личное» уже есть сертификат CN=cpxt_<tag> — выбери другой тег или убери его"
}

# Ключи генерируются на носителе, обе пары неэкспортируемы. Скрипт закрывает
# модальные окна (Био ДСЧ — движением мыши SendInput, прочие — WM_COMMAND IDOK).
# Если cpxt_<tag> уже есть на самом токене — newkeyset упадёт с NTE_EXISTS (тег занят).
pwsh token-session\make-token-container.ps1 -ContainerPath "\\.\<reader>\cpxt_<tag>" -Password <PIN> -TimeoutSec 200

# Самоподписанный сертификат в контейнер. -password ОБЯЗАТЕЛЕН, иначе makecert
# зависнет на диалоге «Аутентификация — КриптоПро CSP» (наблюдалось на ESMART).
& $csptest -keyset -container "\\.\<reader>\cpxt_<tag>" -provtype 80 -makecert -password <PIN>
```
Проверить, что baseline действительно неэкспортируемый (флага `CRYPT_EXPORT` нет):
```powershell
Run 'checkexport "\\.\<reader>\cpxt_<tag>" --lang ru'    # FQCN reader — иначе одноимённый контейнер соседнего токена; ждём …98, НЕ …9C
```
Если ключ уже `…9C` — это **экспортируемый** образец, он ничего не доказывает
(CSP штатно копирует такой ключ с любого носителя). Годен только `…98`.

**Перечитать `list` после создания — технический id появляется только сейчас.**
`list` из §2 снимался до §3, нового контейнера в нём ещё нет. Прогнать заново и
взять `[APDU <технический-id>]` строки `cpxt_<tag>` — этот id пойдёт в `--container`
на шаге 4 (у eToken PRO селектор обязателен и строго технический):
```powershell
Run 'list --lang ru'    # найти строку "[APDU <технический-id>] cpxt_<tag>"
```

## 4. Снять контейнер по APDU и снять запрет (ядро теста)

```powershell
# $out должен быть СВЕЖИМ и принадлежать только этому прогону: §7 в конце делает
# Remove-Item $out -Recurse -Force, поэтому переиспользование занятого пути стёрло
# бы чужие файлы. Падаем, если путь уже существует.
$out = "<scratch>\<tag>"
if (Test-Path $out) { throw "$out уже существует — выбери свежий путь для прогона" }
New-Item -ItemType Directory $out | Out-Null
# технический id берётся из вывода list (шаг 2)
Run "tokenfull `"<reader>`" `"$out`" <PIN> --container <технический-id> --lang ru"
```
Ожидаемо: `[APDU]` читает шесть `*.key`, извлекается сертификат, `p12utility
--cprepair --keyexport` помечает ключ(и) экспортируемыми, `header.key` растёт
~1.3 КБ → ~3 КБ. Токен при этом **только читается**.

**Раскладка результата зависит от семейства (важно для шагов 5–7):**
- Рутокен S, JaCarta LT, ESMART — **одна** папка `<технический-id>`, оба ключа в
  одном контейнере;
- Рутокен Lite и eToken PRO — **две** папки: `<технический-id>` (обмен) и
  `<технический-id>_signature` (подпись). `ExportPipeline.MakeLiteSavedContainerExportable`
  раскладывает двухключевой контейнер на две одноключевые HDIMAGE-копии, обходя
  дефект `p12utility 4.0.8`.

## 5. Установка в CSP и доказательство экспортируемости

Обработать **каждую** полученную папку из шага 4 (для Lite/PRO — обе).

**Проверять именно HDIMAGE-копию по полному FQCN `\\.\HDIMAGE\<имя>`.** Токен в
этот момент ещё подключён, а его контейнер носит **то же логическое имя**, что и
установленная копия; голое имя `cpxt_<tag>` неоднозначно и CSP может проверить
неэкспортируемый контейнер на токене вместо снятого на диск. `checkexport`
принимает FQCN (проверено на HDIMAGE-контейнере).

```powershell
# одноключевой случай (S/LT/ESMART):
Run "install `"$out\<технический-id>`" --lang ru"                       # HDIMAGE-копия, видна CSP
Run 'checkexport "\\.\HDIMAGE\cpxt_<tag>" --lang ru'                    # ждём 0x0013089C И 0x0012289C

# Lite/PRO — обе папки и обе CSP-копии по отдельности:
Run "install `"$out\<технический-id>`" --lang ru"
Run "install `"$out\<технический-id>_signature`" --lang ru"
Run 'checkexport "\\.\HDIMAGE\cpxt_<tag> [exchange]" --lang ru'         # ждём обмен 0x0013089C
Run 'checkexport "\\.\HDIMAGE\cpxt_<tag> [signature]" --lang ru'        # ждём подпись 0x0012289C
```
`…9C` — главное доказательство: запрет на экспорт снят. **Проверять обе пары.**
`checkexport` возвращает успех и когда один тип ключа отсутствует («ключ не
найден»), поэтому одной проверки на split-контейнере недостаточно: для Lite/PRO
проверяй именно обе копии, иначе E2E считается пройденным, а подписная ветка —
нет.

## 6. PFX (обе ветки)

`extractpfx` работает с папкой на диске, `topfx` — с **установленной CSP-копией**
(по её имени из шага 5). Для split-контейнеров Lite/PRO это две папки и две
CSP-копии, поэтому PFX собирается для каждой ветви отдельно, в разные файлы —
иначе подписной PFX не создаётся, а `topfx cpxt_<tag>` без суффикса не находит
HDIMAGE-копию (имена там `[exchange]`/`[signature]`) либо адресует ещё
подключённый неэкспортируемый контейнер токена.

`topfx` тоже адресуй по HDIMAGE-FQCN — по той же причине, что `checkexport`
(токен подключён, имя совпадает).

```powershell
# одноключевой случай (S/LT/ESMART):
Run "extractpfx `"$out\<технический-id>`" `"$out\<tag>.pfx`" <pfx-pass> `"`" --lang ru"       # для OpenSSL
Run "topfx `"\\.\HDIMAGE\cpxt_<tag>`" `"$out\<tag>_cp.pfx`" <pfx-pass> --lang ru"              # для КриптоПро (certmgr)
certutil -p <pfx-pass> -dump "$out\<tag>_cp.pfx" | Select-String 'Provider|Container'

# Lite/PRO — обе ветви в разные файлы:
Run "extractpfx `"$out\<технический-id>`" `"$out\<tag>_ex.pfx`" <pfx-pass> `"`" --lang ru"
Run "extractpfx `"$out\<технический-id>_signature`" `"$out\<tag>_sg.pfx`" <pfx-pass> `"`" --lang ru"
Run "topfx `"\\.\HDIMAGE\cpxt_<tag> [exchange]`" `"$out\<tag>_ex_cp.pfx`" <pfx-pass> --lang ru"
Run "topfx `"\\.\HDIMAGE\cpxt_<tag> [signature]`" `"$out\<tag>_sg_cp.pfx`" <pfx-pass> --lang ru"
```

## 7. Уборка (удалять ТОЛЬКО своё `cpxt_*`)

```powershell
# a) контейнер с токена. На смарт-картах требует интерактивный PIN даже с -password:
& $csptest -keyset -deletekeyset -container "\\.\<reader>\cpxt_<tag>" -provtype 80 -password <PIN>
#    Рутокен S/Lite и одна JaCarta так удаляются; ESMART и вторая JaCarta показывают
#    диалог «Аутентификация — КриптоПро CSP» — PIN в него вводится только SendInput
#    (WM_SETTEXT не работает), затем Enter. CryptAcquireContext(CRYPT_DELETEKEYSET)
#    на этих контейнерах даёт 0x8009001F — не годится, чистить через csptest.

# b) HDIMAGE-копии (без PIN). S/LT/ESMART — одна "cpxt_<tag>";
#    Lite/PRO — ДВЕ, "cpxt_<tag> [exchange]" и "cpxt_<tag> [signature]":
& $csptest -keyset -deletekeyset -container "\\.\HDIMAGE\cpxt_<tag>" -provtype 80
& $csptest -keyset -deletekeyset -container "\\.\HDIMAGE\cpxt_<tag> [exchange]" -provtype 80
& $csptest -keyset -deletekeyset -container "\\.\HDIMAGE\cpxt_<tag> [signature]" -provtype 80

# c) сертификаты из «Личное» — ТОЛЬКО текущего тега (у Lite/PRO их два, оба с
#    CN=cpxt_<tag>). Граница (,|$): CN бывает и с хвостом (CN=cpxt_<tag>, E=…),
#    и без него (CN=cpxt_<tag>). Wildcard '*CN=cpxt_*' снёс бы чужие cpxt_-тесты:
Get-ChildItem Cert:\CurrentUser\My | ? { $_.Subject -match 'CN=cpxt_<tag>(,|$)' } |
  % { Remove-Item ("Cert:\CurrentUser\My\" + $_.Thumbprint) -Force }

# d) рабочая папка $out — в ней остались снятые *.key, сертификаты и PFX с
#    ЭКСПОРТИРУЕМЫМ закрытым ключом; синтетика одноразовая, удалить целиком:
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
```
Затем сверить `enum_cont` с baseline из шага 0 — расхождений быть не должно.

**Одного `enum_cont` для приёмки мало (AGENTS п.31): под contention или после
холодного сброса он молча печатает только HDIMAGE, выходит с кодом 0, и
before/after ложно совпадают, хотя `cpxt_<tag>` остался на токене.** Поэтому
проверить целевой токен-контейнер напрямую — он должен **отсутствовать**:

```powershell
Run "checkexport `"\\.\<reader>\cpxt_<tag>`" --lang ru"   # ждём код 2 «нет контейнера/ключа»
```
Но код 2 сам по себе двусмыслен: `checkexport` вернёт 2 и когда токен **недоступен**
(любой `CryptAcquireContext` не прошёл), а `enum_cont` при этом мог отработать за
счёт других readers. Поэтому **до** приёмки кода 2 получить ПОЛОЖИТЕЛЬНЫЙ признак
живости именно этого reader — он должен быть виден в PKCS#11:

```powershell
Run 'list --lang ru'   # целевой reader присутствует в секции PKCS#11 (модель, свободная память)
```
Только при живом reader код 2 = контейнер действительно снят. Если reader в
PKCS#11 не виден — холодный сброс карты (PC/SC `SCARD_UNPOWER_CARD` или
переподключение), подождать секунду и повторить обе проверки.

## Особенности по семействам (грабли, уже наступавшие)

| Носитель | Бэкенд | Раскладка результата | Заметки |
|---|---|---|---|
| Рутокен S | `RutokenSApdu` | одна папка, оба ключа | `rtCOMLite` не использовать |
| Рутокен Lite | `RutokenLiteApdu` | **две** папки: базовая `<id>` (обмен) + `<id>_signature` | контейнеры = DF-индексы `lite_XX` |
| eToken PRO | `JaCartaProApdu` | **две** папки | `--container` обязателен, только технический `jacartapro_XX` |
| JaCarta LT | `JaCartaLtApdu` | одна папка, оба ключа | несколько контейнеров различаются байтом Type в таблице объектов (0x03, 0x0E…) — см. AGENTS п.43 |
| ESMART (оба) | `EsmartApdu` | одна папка | `makecert`/`deletekeyset` показывают PIN-диалог; нужен `-password`/SendInput |

- **Селектор `--container` матчит технический `OutputName`** (`rutokens_0B00`,
  `jacartalt_0F`), а не видимое имя. При вводе имени — «Контейнер «…» не найден».
- **stdout WinExe виден только при redirect в файл** (см. помощник `Run` в §1);
  читать в UTF-8. `.exe` из git-bash не запускается — только `Start-Process`.
- **FQCN контейнера — с двойным ведущим слэшем** `\\.\<reader>\<имя>`: в PowerShell
  бэкслеш не экранирует, одинарный `\.\` адресует другой (неверный) контейнер.
