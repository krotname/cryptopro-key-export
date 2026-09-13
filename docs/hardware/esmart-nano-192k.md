# ESMART Token Nano 192K: полный аппаратный E2E

Проверено 10.09.2026 на подключённом `ESMART Token Nano 192K 0`. На носителе
создан отдельный синтетический двухключевой контейнер `cpxt_0910_esnano_c6a1`;
боевой контейнер не читался и не изменялся.

## Причина прежнего отказа

У ESMART общий entry module `isbc_pkcs11_main.dll` загружает отдельные backend DLL
по семействам устройств. В portable-комплекте был только
`isbc_esmart_token_mod.dll`, поэтому Nano 192K либо пропадал из PKCS#11, либо
останавливался проверкой неподтверждённого reader.

Из официального полного ESMART PKI Client 4.17 добавлены подписанные x86-модули:

| Файл | SHA-256 |
|---|---|
| `isbc_esmart_token_192k_mod.dll` | `DAB600F3DDF23FC804109B10A073C0B4089FFDA2757628F8EF212F41AA950DA8` |
| `esmart_token_gost_mod.dll` | `145CFE5A19AF2292D1C42849B0563079DAFD4CD9265C5BF1CEFF9525CB4604FD` |

Обе подписи Authenticode действительны, издатель — `AT bureau OOO`. Теперь
`BundledCandidate` распаковывает entry module и все три backend DLL, а
`IsLibraryComplete` не позволяет неполному системному комплекту скрыть полную
встроенную копию. Источник: [страница загрузок ESMART](https://token.esmart.ru/downloads),
[полный пакет 4.17](https://cdn.esmart.ru/token/software/pkiclient/4.17/ESMART_PKI_Client_4.17_full.zip).

## Проверенный цикл

1. `list` подтвердил PKCS#11-модель `ESMART Token 192K`, производителя `ISBC` и
   новый контейнер `[APDU esmart_F200] cpxt_0910_esnano_c6a1`.
2. Точный CSP-FQCN до экспорта показал обе неэкспортируемые пары:
   `0x00130898` и `0x00122898`.
3. `tokenfull` прочитал `name/header/primary/masks/primary2/masks2` и успешно
   выполнил `p12utility --cprepair --keyexport`.
4. HDIMAGE-копия дала `0x0013089C` и `0x0012289C`.
5. `extractpfx` создал PFX длиной 1313 байт, SHA-256
   `3E8C0949FF512FAA794B5AEBEE7BA6885450A486D3A66A3315BC1AFE0C16CEAA`;
   `topfx` — 1315 байт, SHA-256
   `F9C4614F23A4D140C8DD2B80F78461CA36BD36B83BD487E1145D53907A50BB7F`.
   Первый разобран OpenSSL, второй — `certutil` с ожидаемыми provider/container.

Reader допускается только как точное индексированное семейство
`ESMART Token Nano 192K N` при одновременном подтверждении ESMART/ISBC через
PKCS#11. Строка без цифрового индекса и похожие reader по-прежнему отклоняются.

