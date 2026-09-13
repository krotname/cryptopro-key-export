# Профиль выпуска CryptoProExport

Общий порядок: [релиз](release.md).

| Поле | Значение |
|---|---|
| Репозиторий | krotname/cryptopro-key-export, private |
| Канал | GitHub Releases |
| Версия | 1.9.0 |
| Предыдущая версия | 1.8.0 |
| Тег | v1.9.0, аннотированный на main |
| Источник версии | Version в App и Core csproj |
| Версия файла | 1.9.0.0 |
| Артефакты | CryptoProExport-1.9.0.0-portable-x86.exe и .exe.sha256 |
| Сборка | build/publish.ps1, self-contained win-x86 |
| CI | .github/workflows/ci.yml |
| Публикация | release job через REST API, exe из GHCR по digest |
| Проверка | SHA-256 скачанного exe, FileVersion, --selftest |
| Checkpoint | artifacts/release-checkpoint.json, локально без секретов |

Публикация разрешена владельцем в текущем поручении. Перед тегом обязательны
успешные CI PR и main на точном SHA и применимое ревью.
Существующие незавершённые изменения в других рабочих деревьях не включаются.
