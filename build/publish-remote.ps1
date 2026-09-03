<#
.SYNOPSIS
    Собрать портативный exe на домашнем Ubuntu-сервере и забрать результат.

.DESCRIPTION
    Windows-приложение собирается на Linux благодаря EnableWindowsTargeting: SDK берёт
    reference-пакеты Windows Desktop из NuGet. Компилировать так можно всё, а запускать —
    нет, поэтому тесты и самопроверка остаются на Windows (см. build/publish.ps1).

    Зачем: сборка занимает ~20 секунд на 12-ядерном сервере и не отнимает ресурсы у ноутбука.

    Дерево исходников уезжает tar-архивом по SSH (rsync на Windows обычно нет),
    без .git, bin, obj и publish. И архив, и готовый exe передаются файлами, а не через
    конвейер PowerShell: он декодирует вывод нативных команд как текст и портит двоичные
    данные. Результат — один exe — забирается обратно, для него считается SHA-256.

.PARAMETER SshHost
    Алиас или адрес сборщика. По умолчанию adler-black-u2.lan (домашний Ubuntu-сервер).

.EXAMPLE
    pwsh build\publish-remote.ps1
    pwsh build\publish-remote.ps1 -SshHost adler-black-u2.lan -OutDir publish-remote
#>
[CmdletBinding()]
param(
    [string]$SshHost = 'adler-black-u2.lan',
    [string]$Rid = 'win-x86',
    [string]$Configuration = 'Release',
    [string]$OutDir = 'publish',
    [string]$RemoteDir = '/srv/build/cryptopro'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    foreach ($tool in 'ssh', 'tar') {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "Не найден $tool — он нужен для передачи исходников на сборщик"
        }
    }

    # 1. Сборщик на месте и с нужным SDK
    Write-Host "Сборщик: $SshHost" -ForegroundColor DarkGray
    $sdk = & ssh -o BatchMode=yes -o ConnectTimeout=8 $SshHost 'command -v dotnet >/dev/null && dotnet --version' 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $sdk) {
        throw "На $SshHost нет .NET SDK. Поставить: apt-get install -y dotnet-sdk-10.0"
    }
    Write-Host "  .NET SDK $sdk" -ForegroundColor DarkGray

    # 2. Исходники: tar-архивом, без мусора и без .git.
    # Гнать `tar -czf -` в ssh через конвейер PowerShell нельзя по той же причине, что и
    # в шаге 4: вывод нативной команды PowerShell декодирует как текст и перекодирует
    # в OutputEncoding, поэтому gzip-поток доезжает битым («gzip: invalid compressed data»).
    # Архив пишется во временный файл и передаётся на уровне процесса — scp, а если его
    # нет, перенаправлением stdin у ssh.
    Write-Host "Передаём исходники…" -ForegroundColor DarkGray
    $localTar = Join-Path ([IO.Path]::GetTempPath()) ("cpx-src-" + [guid]::NewGuid().ToString('N') + ".tar.gz")
    $remoteTar = "/tmp/" + (Split-Path -Leaf $localTar)
    & tar -czf $localTar --exclude=.git --exclude=bin --exclude=obj --exclude=publish --exclude=publish-remote --exclude=.claude .
    if ($LASTEXITCODE -ne 0) { throw "Не удалось упаковать исходники в $localTar" }

    if (Get-Command scp -ErrorAction SilentlyContinue) {
        & scp -q -o BatchMode=yes $localTar "${SshHost}:$remoteTar"
        if ($LASTEXITCODE -ne 0) { throw "Не удалось передать исходники на $SshHost" }
    }
    else {
        $up = Start-Process ssh -Wait -PassThru -NoNewWindow -RedirectStandardInput $localTar `
                            -ArgumentList '-o', 'BatchMode=yes', $SshHost, "cat > '$remoteTar'"
        if ($up.ExitCode -ne 0) { throw "Не удалось передать исходники на $SshHost (ssh cat вернул $($up.ExitCode))" }
    }

    $remoteUnpack = "rm -rf '$RemoteDir' && mkdir -p '$RemoteDir' && " +
                    "tar -xzf '$remoteTar' -C '$RemoteDir'; rc=`$?; rm -f '$remoteTar'; exit `$rc"
    & ssh -o BatchMode=yes $SshHost $remoteUnpack
    if ($LASTEXITCODE -ne 0) { throw "Не удалось распаковать исходники на $SshHost" }

    # 3. Сборка
    Write-Host "Собираем на $SshHost…" -ForegroundColor DarkGray
    $publish = "cd '$RemoteDir' && dotnet publish src/App/CryptoProExport.App.csproj " +
               "-c $Configuration -r $Rid --self-contained true -p:DebugType=embedded -o out"
    & ssh -o BatchMode=yes $SshHost $publish
    if ($LASTEXITCODE -ne 0) { throw "Сборка на $SshHost завершилась ошибкой" }

    # 4. Забираем ровно один файл.
    # Через конвейер PowerShell гнать нельзя — он портит двоичные данные, поэтому scp
    # (а если его нет — перенаправление вывода ssh на уровне процесса).
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $exe = Join-Path (Resolve-Path $OutDir) 'CryptoProExport.exe'
    Remove-Item $exe -ErrorAction SilentlyContinue

    if (Get-Command scp -ErrorAction SilentlyContinue) {
        & scp -q -o BatchMode=yes "${SshHost}:$RemoteDir/out/CryptoProExport.exe" $exe
    }
    else {
        $p = Start-Process ssh -Wait -PassThru -NoNewWindow -RedirectStandardOutput $exe `
                           -ArgumentList '-o', 'BatchMode=yes', $SshHost, "cat '$RemoteDir/out/CryptoProExport.exe'"
        if ($p.ExitCode -ne 0) { throw "ssh cat вернул $($p.ExitCode)" }
    }
    if (-not (Test-Path $exe) -or (Get-Item $exe).Length -lt 1MB) { throw "Файл не забрался: $exe" }

    # Сверяем с суммой на сборщике — так ловится порча при передаче
    $remoteHash = (& ssh -o BatchMode=yes $SshHost "sha256sum '$RemoteDir/out/CryptoProExport.exe' | cut -d' ' -f1").Trim()
    $localHash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($remoteHash -and $remoteHash -ne $localHash) {
        throw "Файл побился при передаче: на сборщике $remoteHash, здесь $localHash"
    }

    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    Write-Host ""
    Write-Host ("Готово: {0} ({1:N1} МБ)" -f $exe, ((Get-Item $exe).Length / 1MB)) -ForegroundColor Green
    Write-Host "SHA-256: $hash" -ForegroundColor DarkGray
    Write-Host "Проверить его можно только на Windows: .\$OutDir\CryptoProExport.exe --selftest" -ForegroundColor DarkGray
}
finally {
    if ($localTar -and (Test-Path $localTar)) { Remove-Item $localTar -Force -ErrorAction SilentlyContinue }
    Pop-Location
}
