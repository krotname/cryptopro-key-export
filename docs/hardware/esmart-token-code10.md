# ESMART Token VID_2CE4/PID_7479: Code 10 и восстановление PnP

Проверено на живом устройстве 21.08.2026. Стойких системных изменений не было, кроме
одного точечного перезапуска PnP-устройства; Windows не перезагружалась. Более ранняя
попытка передать bundle параметр `/extract` кратко запустила MSI, завершилась кодом 1603
и откатилась: повторный readback не нашёл продукта, каталогов или vendor INF. PIN не
вводился, `C_Login` не вызывался, контейнеры и сертификаты не изменялись. Полный PnP
Instance ID, серийник, ATR и данные владельца не сохранялись.

## Симптом

- Физически подключено ровно одно устройство `USB\VID_2CE4&PID_7479`, USB class `0B/00/00`,
  `BusReportedDeviceDesc = ESMART Token`.
- PnP class — `SmartCardReader`; состояние — `CM_PROB_FAILED_START` (`Code 10`),
  `DEVPKEY_Device_ProblemStatus = 0xC0000001` (`STATUS_UNSUCCESSFUL`). Microsoft указывает,
  что Code 10 означает отказ одного из драйверов стека на `IRP_MN_START_DEVICE`, а точный
  возврат следует читать из `DEVPKEY_Device_ProblemStatus`.
- Выбран inbox-драйвер Microsoft `wudfusbcciddriver.inf` версии `10.0.26100.3323`, service
  `WUDFRd`, lower filter `WinUsb`. Он подписан Microsoft и имеет лучший rank; VID-specific
  vendor INF в Driver Store отсутствовал.
- Kernel-PnP Event 400 настроил `wudfusbcciddriver`, Event 411 зафиксировал отказ запуска с
  `Problem 0xA` и `Status 0xC0000001`.
- В `setupapi.dev.log` отдельной install section для этого target не было; отсутствие такой
  записи не использовалось как доказательство успешного или неуспешного старта.
- WUDF USB CCID прочитал class descriptor, после чего возник burst Event 7
  `ReaderCompletionUnknownMsgType`. Целевой reader исчез из PC/SC; соседние Rutoken,
  JaCarta и ESMART USB 64K при этом работали через тот же общий Windows smart-card stack.

По документации Microsoft наличие Code 10 подтверждает failed-start, но само по себе не
называет виновный слой. Здесь сочетание событий CCID и исправности соседних устройств
локализует сбой в состоянии запуска именно этого устройства, а не в общем PC/SC/WUDF.

## Официальный ESMART PKI Client 4.17

[Страница загрузок ESMART](https://token.esmart.ru/downloads) предлагает рекомендованный
Windows x86/x64 PKI Client 4.17 от 09.06.2025. Проверенный
[bundle](https://cdn.esmart.ru/token/software/pkiclient/update/current/ESMART_PKI_Client_bundle.zip):

- ZIP: 40 932 449 байт,
  SHA-256 `16527284529ed83744b4c4a0d156280518527d4610c32d9fef513242ca2d62a8`;
- `setup.exe`: SHA-256
  `020d0c1adc31ab2f4c5307715c76a0a1079e70f8df1f3f58d0f808e090a7bcac`,
  Authenticode `Valid`, signer `AT bureau OOO`, timestamp DigiCert;
- вложенный x64 MSI: product `ESMART PKI Client 4.17.4`, SHA-256
  `f73d874d67b2918937e7c97749baf83eede872b9e51fc03b76708bedceb06ba8`,
  Authenticode `Valid` с тем же signer.

Разбор MSI без исполнения показал PKCS#11-библиотеки и smart-card minidriver-пакеты,
привязанные к `SCFILTER\CID_*`, но не VID-specific USB/CCID INF для `2CE4:7479`.
Custom action `InstallWudfDriver` вызывает старую форму `pnputil -i -a` для уже системного
`%SystemRoot%\INF\wudfusbcciddriver.inf` и игнорирует ошибку этого шага. То есть пакет
повторно добавляет тот же inbox CCID-драйвер; его PKCS#11-часть работает поверх
`WinSCard.dll` и не может заменить отсутствующий PC/SC reader.

Отдельный старый Windows-драйвер ESMART Token USB 64K не применялся: официальный сайт
помечает его как драйвер для старых Windows, который не работает в Windows 10.

## Восстановление и readback

После проверки, что найдено ровно одно совпадающее устройство, выполнен один штатный
точечный перезапуск без флага `/reboot`:

```powershell
$device = Get-PnpDevice -PresentOnly |
    Where-Object InstanceId -Like 'USB\VID_2CE4&PID_7479*'
if (@($device).Count -ne 1) { throw 'Expected exactly one target device.' }
pnputil /restart-device $device.InstanceId
```

Результат после обязательного readback:

- PnP: `Status = OK`, `ProblemCode = 0`; INF, version, service и lower filter не изменились;
- PC/SC: появился четвёртый reader `ISBC ESMART Token 0`, карта имеет состояние `Present`;
- после restart WUDF зарегистрировал только Event 104/105 с CCID descriptor и не создал
  нового Event 7;
- ESMART/ISBC product, каталог Program Files и vendor driver package по-прежнему отсутствуют.

Поэтому установка PKI Client не выполнялась: она уже не была оправдана для ремонта Code 10.
Подтверждённая первопричина на доступной глубине — временный failed-start состояния CCID
у конкретного устройства, восстановимый повторным PnP start на том же драйвере. Более узкая
формулировка «гонка питания/готовности firmware» согласуется с изменившимся после restart
CCID descriptor, но остаётся гипотезой без vendor firmware trace.

## Диагностика в приложении

`deps` теперь опрашивает present-устройства PnP class `SmartCardReader` через SetupAPI до
PKCS#11. Если reader физически подключён, но имеет ненулевой Problem Code, отчёт показывает:

- безопасное имя (`BusReportedDeviceDesc`/friendly name);
- только USB VID/PID без полного Instance ID;
- PnP Code и `ProblemStatus` в hex.

Это закрывает прежний слепой участок: failed-start reader отсутствует и в PC/SC, и в PKCS#11,
поэтому раньше `deps` не мог отличить неподключённый токен от подключённого устройства с
не запустившимся драйвером.

## Первичные источники

- [Microsoft: Code 10 — CM_PROB_FAILED_START](https://learn.microsoft.com/ru-ru/windows-hardware/drivers/install/cm-prob-failed-start)
- [Microsoft: PnPUtil `/restart-device`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax#restart-device)
- [USB-IF: CCID Rev 1.1](https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf)
- [ESMART Token: загрузки](https://token.esmart.ru/downloads)
