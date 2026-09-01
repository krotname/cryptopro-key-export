<#
.SYNOPSIS
    Портативная сборка CryptoProExport: один .exe, внутри которого всё нужное.

.DESCRIPTION
    Собирает self-contained single-file приложение. Внутрь попадают:
      • среда .NET (запускать не нужно ничего доустанавливать);
      • p12utility.win32.exe и rtCOMLite.dll (вшиты как ресурсы, распаковываются
        в %LOCALAPPDATA%\CryptoProExport\bundled\<версия> при первом запуске);
      • библиотеки PKCS#11 Рутокен ЭЦП/Lite, JaCarta и ESMART — запасной путь для
        машины без драйверов носителя (системная копия всегда приоритетнее).
    Снаружи остаётся единственная зависимость — КриптоПро CSP на целевой машине.

    Разрядность x86 и есть универсальная: такой exe идёт и на x64 (WOW64), и на
    ARM64 (эмуляция), а вшитый 32-битный rtCOMLite.dll грузится в процесс без
    регистрации в системе только при совпадении разрядности.

.EXAMPLE
    pwsh build\publish.ps1
    pwsh build\publish.ps1 -OutDir C:\temp\cpx -SkipSelfTest
#>
[CmdletBinding()]
param(
    [string]$Rid = 'win-x86',
    [string]$Configuration = 'Release',
    [string]$OutDir = 'publish',
    [switch]$SkipSelfTest
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # 1. Проверяем, что вшиваемые зависимости на месте (без них exe соберётся, но будет неполным)
    $required = @(
        'tools\p12utility.win32.exe', 'tools\rtCOMLite.dll',
        'tools\rtPKCS11ECP.dll', 'tools\jcPKCS11-2.dll',
        'tools\isbc_pkcs11_main.dll', 'tools\isbc_esmart_token_mod.dll')
    $missing = $required | Where-Object { -not (Test-Path (Join-Path $root $_)) }
    if ($missing) {
        Write-Warning "Не найдены зависимости для упаковки: $($missing -join ', ')"
        Write-Warning "Приложение соберётся, но их придётся доставлять на целевую машину отдельно."
    }

    if ($Rid -ne 'win-x86') {
        Write-Warning "RID '$Rid': вшитый rtCOMLite.dll 32-битный и в таком процессе не загрузится — понадобится установленный компонент rtCOMLite."
    }

    # 2. Сборка
    $publishArgs = @(
        'publish', 'src/App/CryptoProExport.App.csproj',
        '-c', $Configuration, '-r', $Rid, '--self-contained', 'true',
        '-p:DebugType=embedded',   # символы внутрь exe, чтобы в папке не оставалось .pdb
        '-o', $OutDir
    )
    Write-Host "dotnet $($publishArgs -join ' ')" -ForegroundColor DarkGray
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish завершился с кодом $LASTEXITCODE" }

    $exe = Join-Path (Resolve-Path $OutDir) 'CryptoProExport.exe'
    if (-not (Test-Path $exe)) { throw "После publish не найден $exe" }

    # 3. Что получилось
    $files = Get-ChildItem $OutDir -File
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    Write-Host ""
    Write-Host ("Готово: {0} ({1:N1} МБ)" -f $exe, ((Get-Item $exe).Length / 1MB)) -ForegroundColor Green
    Write-Host "SHA-256: $hash" -ForegroundColor DarkGray
    if ($files.Count -gt 1) {
        Write-Host "Рядом лежат ещё файлы (для запуска не нужны, кроме .exe):" -ForegroundColor DarkGray
        $files | Where-Object { $_.Name -ne 'CryptoProExport.exe' } |
            ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor DarkGray }
    }

    # 4. Быстрая проверка: собранный exe стартует и видит свои зависимости
    if (-not $SkipSelfTest) {
        $selfTestId = [Guid]::NewGuid().ToString('N')
        $log = Join-Path $env:TEMP ("cpx-selftest-$selfTestId.txt")
        try {
            $p = Start-Process $exe '--selftest' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $log
            $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($log))
            Write-Host $text
            if ($p.ExitCode -ne 0) { throw "--selftest вернул код $($p.ExitCode)" }
            Write-Host "Самопроверка пройдена." -ForegroundColor Green
        }
        finally {
            [IO.File]::Delete($log)
        }
    }
}
finally {
    Pop-Location
}
