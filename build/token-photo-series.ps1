<#
.SYNOPSIS
    Rebuilds the canonical nine-token evidence photo series.

.DESCRIPTION
    Uses only deterministic ImageMagick operations over the evidence originals:
    rotation (never mirroring), crop, one percentile contrast
    normalization, Lanczos resize, border, and composition on a graphite canvas.

    The per-side crop boxes are explicit so the result is reproducible and the
    physical token remains wholly visible. The originals are never overwritten.

.EXAMPLE
    pwsh build\token-photo-series.ps1
#>
[CmdletBinding()]
param(
    [string[]]$Model
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$imageRoot = Join-Path $root 'docs\images'
$magick = Get-Command magick -ErrorAction Stop

$canvasWidth = 2048
$canvasHeight = 1152
$panelWidth = 1408
$panelHeight = 448
$frameWidth = 16
$frameX = 304
$frontY = 56
$rearY = 616
$contrastStretch = '0.20%x0.20%'

$series = @(
    [pscustomobject]@{
        Slug = 'etoken-pro'
        Front = [pscustomobject]@{ File = 'etoken-pro-front-original.png'; Rotation = 90; Crop = '1936x616+110+542' }
        Rear  = [pscustomobject]@{ File = 'etoken-pro-rear-original.png';  Rotation = 90; Crop = '1980x630+36+551' }
    }
    [pscustomobject]@{
        Slug = 'esmart-token'
        Front = [pscustomobject]@{ File = 'esmart-token-front-original.jpg'; Rotation = 180; Crop = '418x133+243+494' }
        Rear  = [pscustomobject]@{ File = 'esmart-token-rear-original.jpg';  Rotation = 0;   Crop = '418x133+271+644' }
    }
    [pscustomobject]@{
        Slug = 'esmart-token-usb64k'
        Front = [pscustomobject]@{ File = 'esmart-token-usb64k-front-original.jpg'; Rotation = 0; Crop = '572x182+154+680' }
        Rear  = [pscustomobject]@{ File = 'esmart-token-usb64k-rear-original.jpg';  Rotation = 0; Crop = '572x182+152+659' }
    }
    [pscustomobject]@{
        Slug = 'jacarta-lt'
        Front = [pscustomobject]@{ File = 'jacarta-lt-front-original.jpg'; Rotation = 0; Crop = '506x161+174+680' }
        Rear  = [pscustomobject]@{ File = 'jacarta-lt-rear-original.jpg';  Rotation = 0; Crop = '462x147+248+631' }
    }
    [pscustomobject]@{
        Slug = 'jacarta-lt-nano'
        Front = [pscustomobject]@{ File = 'jacarta-lt-nano-front-original.jpg'; Rotation = 0; Crop = '396x126+280+683' }
        Rear  = [pscustomobject]@{ File = 'jacarta-lt-nano-rear-original.jpg';  Rotation = 0; Crop = '418x133+327+608' }
    }
    [pscustomobject]@{
        Slug = 'rutoken-ecp-2'
        Front = [pscustomobject]@{ File = 'rutoken-ecp-2-front-original.png'; Rotation = 180; Crop = '1430x455+819+512' }
        Rear  = [pscustomobject]@{ File = 'rutoken-ecp-2-rear-original.png';  Rotation = 180; Crop = '1452x462+1012+555' }
    }
    [pscustomobject]@{
        Slug = 'rutoken-ecp-3'
        Front = [pscustomobject]@{ File = 'rutoken-ecp-3-front-original.jpg'; Rotation = 180; Crop = '506x161+186+490' }
        Rear  = [pscustomobject]@{ File = 'rutoken-ecp-3-rear-original.jpg';  Rotation = 180; Crop = '462x147+231+424' }
    }
    [pscustomobject]@{
        Slug = 'rutoken-lite'
        Front = [pscustomobject]@{ File = 'rutoken-lite-front-original.jpg'; Rotation = 0;   Crop = '616x196+141+505' }
        Rear  = [pscustomobject]@{ File = 'rutoken-lite-rear-original.jpg';  Rotation = 180; Crop = '616x196+150+534' }
    }
    [pscustomobject]@{
        Slug = 'rutoken-s'
        Front = [pscustomobject]@{ File = 'rutoken-s-front-original.jpg'; Rotation = 0;   Crop = '484x154+249+741' }
        Rear  = [pscustomobject]@{ File = 'rutoken-s-rear-original.jpg';  Rotation = 180; Crop = '440x140+249+464' }
    }
)

function Invoke-Magick {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & $magick.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ImageMagick failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function New-Panel {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][int]$Rotation,
        [Parameter(Mandatory)][string]$Crop,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Evidence original is missing: $Source"
    }

    $arguments = @(
        $Source,
        '-rotate', $Rotation.ToString(),
        '+repage',
        '-crop', $Crop,
        '+repage',
        '-colorspace', 'sRGB',
        '-channel', 'RGB',
        '-contrast-stretch', $contrastStretch,
        '+channel',
        '-filter', 'Lanczos',
        '-resize', "${panelWidth}x${panelHeight}!",
        '-strip',
        '-depth', '8',
        '-bordercolor', '#e8e7e3',
        '-border', $frameWidth.ToString(),
        $Destination
    )
    Invoke-Magick -Arguments $arguments
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("token-photo-series-" + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

try {
    $requestedModels = @($Model | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $unknownModels = @($requestedModels | Where-Object { $_ -notin $series.Slug })
    if ($unknownModels.Count -gt 0) {
        throw "Unknown model slug(s): $($unknownModels -join ', ')"
    }

    $selectedSeries = if ($requestedModels.Count -gt 0) {
        @($series | Where-Object Slug -In $requestedModels)
    }
    else {
        $series
    }

    foreach ($seriesModel in $selectedSeries) {
        $modelDirectory = Join-Path $imageRoot $seriesModel.Slug
        if (-not (Test-Path -LiteralPath $modelDirectory -PathType Container)) {
            throw "Canonical image directory is missing: $modelDirectory"
        }

        $frontSource = Join-Path $modelDirectory $seriesModel.Front.File
        $rearSource = Join-Path $modelDirectory $seriesModel.Rear.File
        $frontPanel = Join-Path $temporaryRoot ("$($seriesModel.Slug)-front-panel.png")
        $rearPanel = Join-Path $temporaryRoot ("$($seriesModel.Slug)-rear-panel.png")
        $destination = Join-Path $modelDirectory ("$($seriesModel.Slug)-front-rear-studio.png")

        New-Panel -Source $frontSource -Rotation $seriesModel.Front.Rotation -Crop $seriesModel.Front.Crop -Destination $frontPanel
        New-Panel -Source $rearSource -Rotation $seriesModel.Rear.Rotation -Crop $seriesModel.Rear.Crop -Destination $rearPanel

        $composeArguments = @(
            '-size', "${canvasWidth}x${canvasHeight}",
            'radial-gradient:#3b4248-#171b1f',
            $frontPanel,
            '-geometry', "+${frameX}+${frontY}",
            '-composite',
            $rearPanel,
            '-geometry', "+${frameX}+${rearY}",
            '-composite',
            '-colorspace', 'sRGB',
            '-strip',
            '-depth', '8',
            '-define', 'png:color-type=2',
            '-define', 'png:compression-level=9',
            $destination
        )
        Invoke-Magick -Arguments $composeArguments

        $dimensions = & $magick.Source identify -format '%wx%h' $destination
        if ($LASTEXITCODE -ne 0 -or $dimensions -ne "${canvasWidth}x${canvasHeight}") {
            throw "Unexpected output dimensions for ${destination}: $dimensions"
        }

        Write-Host "Built $($seriesModel.Slug): $dimensions" -ForegroundColor Green
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        [IO.Directory]::Delete($temporaryRoot, $true)
    }
}
