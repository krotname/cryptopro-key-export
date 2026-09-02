# Выпуск релиза

Runbook выпуска очередной версии портативной сборки. Задача — получить на странице
релизов один `.exe` с контрольной суммой, собранный CI из ровно того коммита, что
лежит в `main`. Всю работу делает job «Релиз по тегу» в `.github/workflows/ci.yml`;
руками выкладывать файлы не нужно и нельзя — сумма тогда ничем не подтверждена.

Проверено на выпуске v1.8.0 (02.09.2026).

## 0. Что делает CI по тегу

Тег вида `v*` запускает всю сборку заново, а следом job «Релиз по тегу»:

1. тянет портативный exe из приватного GHCR **по digest** той же сборки (не
   пересобирает — иначе файл в релизе отличался бы от проверенного);
2. переименовывает его в `CryptoProExport-<версия сборки>-portable-x86.exe`,
   где `<версия сборки>` — это `<Version>` из csproj, а **не** имя тега;
3. пересчитывает SHA-256 под итоговым именем и сверяет с суммой из сборки;
4. создаёт релиз через REST API и прикладывает `.exe` и `.exe.sha256`.

Отсюда главное правило: **версию в csproj поднимают до тега**. Тег без бампа даст
в релизе `v1.8.0` файл с именем `CryptoProExport-1.7.0.0-portable-x86.exe`.

## 1. Убедиться, что `main` готов

```powershell
cd <worktree>
git fetch --prune origin
git log --oneline -1 origin/main
gh pr list --state open --json number --jq 'length'    # должно быть 0

# Именно workflow сборки и именно тот коммит: без --workflow сюда попадёт любой
# другой прогон ветки (например, плановая «Clean expired private CI artifacts»),
# и упавшая или устаревшая сборка останется незамеченной.
$sha = git rev-parse origin/main
gh run list --workflow ci.yml --branch main --commit $sha --limit 1 `
  --json status,conclusion,headSha,displayTitle
```

- открытых PR нет (иначе релиз выйдет без чужой готовой работы);
- прогон `ci.yml` **на коммите `origin/main`** завершился `success`;
- локальное дерево чистое, worktree синхронизирован с `origin/main`.

## 2. Собрать состав релиза

```powershell
git log --oneline v<предыдущая>..origin/main
```

Из списка убрать шум («Ревью Codex: …», merge-коммиты) и оставить содержательные
пункты — они пойдут в раздел «Текущее состояние» ROADMAP и в тело релиза.

## 3. Поднять версию и документы

Отдельная ветка `release/v<версия>`, один коммит:

- `src/App/CryptoProExport.App.csproj` — `<Version>`;
- `src/Core/CryptoProExport.Core.csproj` — `<Version>` (обе версии совпадают:
  из версии App берётся имя релизного артефакта, из версии сборки — каталог кэша
  вшитых зависимостей `%LOCALAPPDATA%\CryptoProExport\bundled\<версия>`);
- `ROADMAP.md` — заголовок «Текущее состояние (vX.Y.Z)», абзац о том, что
  добавилось после прошлой версии, актуальный счётчик тестов и путь кэша;
- `README.md` — упоминания версии в разделе про локализацию;
- сам этот runbook — если процесс изменился.

Дальше обычный цикл: проверки → PR → зелёный CI → ревью Codex → merge.

```powershell
dotnet build CryptoProExport.slnx -c Release -warnaserror
dotnet test  CryptoProExport.slnx -c Release --no-build
pwsh build\publish.ps1 -OutDir "$env:TEMP\cpx-release"   # внутри гоняет --selftest
```

Портативная сборка обязательна: локальный framework-dependent exe на машине
владельца молча висит без x86-рантайма (AGENTS п. 46). В её выводе видно и имя
версии — сверить, что оно уже новое.

## 4. Поставить тег на merge-коммит

Тег ставится **на коммит в `main`**, а не на ветку релиза: в релиз попадает то,
что смержено.

```powershell
git fetch origin
git tag -a v1.8.0 <sha merge-коммита> -m "Версия 1.8.0"
git push origin v1.8.0
```

Аннотированный тег (`-a`) — чтобы у релиза была дата и автор.

## 5. Дождаться job и проверить результат

```powershell
gh run list --workflow ci.yml --limit 3 --json displayTitle,status,conclusion,headBranch
gh release view v1.8.0 --json name,tagName,assets,createdAt
```

Готово, когда:

- job «Релиз по тегу» завершился `success`;
- в релизе два ассета: `CryptoProExport-<версия>-portable-x86.exe` и `.sha256`;
- версия в имени файла совпадает с `<Version>` из csproj;
- скачанный файл сходится по SHA-256 с содержимым `.sha256`:

```powershell
gh release download v1.8.0 --dir "$env:TEMP\rel"
Get-FileHash "$env:TEMP\rel\CryptoProExport-1.8.0.0-portable-x86.exe" -Algorithm SHA256
Get-Content "$env:TEMP\rel\CryptoProExport-1.8.0.0-portable-x86.exe.sha256"
```

Последний шаг — самопроверка **скачанного** файла: релиз проверяется тем же
способом, что и сборка, но уже на том, что получит пользователь. Просто запустить
exe недостаточно: это WinExe, своей консоли у него нет, и `SELFTEST OK` виден
только в перенаправленном файле (AGENTS п. 1). Нужны и код возврата, и маркер:

```powershell
$exe = "$env:TEMPel\CryptoProExport-1.8.0.0-portable-x86.exe"
$log = "$env:TEMPel\selftest.txt"
$p = Start-Process $exe '--selftest' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
$out = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($log))
$out
if ($p.ExitCode -ne 0 -or $out -notmatch 'SELFTEST OK') { throw 'Самопроверка релиза не прошла' }
```

Из этого же вывода сверить строку «Процесс: x86, версия <версия>» — она должна
совпадать с версией в имени файла.

## 6. Если job упал

- **`gh: command not found`** — исторический отказ на собственном раннере; job уже
  переведён на REST API через `curl`, возвращать `gh` не нужно.
- **Собственный раннер недоступен** — переменная репозитория `CI_RUNS_ON`
  временно переводит job на другой раннер: `["ubuntu-latest"]`.
- **Сумма разошлась** — артефакт испорчен между job: перезапустить прогон тега,
  руками файлы не выкладывать.
- **Тег поставлен по ошибке** — удалить и тег, и созданный релиз, поднять версию
  и повторить: `gh release delete v1.8.0 --yes`, `git push origin :refs/tags/v1.8.0`.
  Удалять релиз, который кто-то мог скачать, без спроса владельца нельзя.
