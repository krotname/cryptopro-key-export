<#
.SYNOPSIS
    Собрать портативный exe на домашнем Ubuntu-сервере и забрать результат.

.DESCRIPTION
    Windows-приложение собирается на Linux благодаря EnableWindowsTargeting: SDK берёт
    reference-пакеты Windows Desktop из NuGet. Компилировать так можно всё, а запускать —
    нет, поэтому тесты и самопроверка остаются на Windows (см. build/publish.ps1).

    Зачем: сборка занимает ~20 секунд на 12-ядерном сервере и не отнимает ресурсы у ноутбука.

    Дерево исходников передаётся tar-потоком по SSH (rsync на Windows обычно нет),
    без .git, bin, obj и publish. Результат — один exe — забирается обратно, для него
    считается SHA-256.

.PARAMETER SshHost
    Алиас или адрес сборщика. По умолчанию ubuntu-xeon (домашний Ubuntu-сервер).

.EXAMPLE
    pwsh build\publish-remote.ps1
    pwsh build\publish-remote.ps1 -SshHost ubuntu-xeon -OutDir publish-remote
#>
[CmdletBinding()]
param(
    [string]$SshHost = 'ubuntu-xeon',
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

    # 2. Исходники: tar-потоком, без мусора и без .git
    Write-Host "Передаём исходники…" -ForegroundColor DarkGray
    $remoteUnpack = "rm -rf '$RemoteDir' && mkdir -p '$RemoteDir' && tar -xzf - -C '$RemoteDir'"
    & tar -czf - --exclude=.git --exclude=bin --exclude=obj --exclude=publish --exclude=publish-remote --exclude=.claude . |
        & ssh -o BatchMode=yes $SshHost $remoteUnpack
    if ($LASTEXITCODE -ne 0) { throw "Не удалось передать исходники на $SshHost" }

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
    Pop-Location
}
