# Генерация иконки приложения: ключ на скруглённом квадрате. Пишет многоразмерный .ico (PNG внутри).
param([Parameter(Mandatory)][string]$OutIco)
$ErrorActionPreference = 'Stop'
trap { "СБОЙ на строке $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"; break }
Add-Type -AssemblyName System.Drawing

function New-IconBitmap([int]$size) {
    $bmp = New-Object Drawing.Bitmap($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.InterpolationMode = 'HighQualityBicubic'
    $g.Clear([Drawing.Color]::Transparent)

    $s = [double]$size
    $pad = $s * 0.06
    # аргументы считаем заранее: в New-Object запятая связывает сильнее арифметики
    $rxy = [single]$pad
    $rwh = [single]($s - 2 * $pad)
    $rect = New-Object Drawing.RectangleF($rxy, $rxy, $rwh, $rwh)
    $radius = $s * 0.22

    # скруглённый квадрат-подложка
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $d = $radius * 2
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc($rect.Right - $d, $rect.Y, $d, $d, 270, 90)
    $path.AddArc($rect.Right - $d, $rect.Bottom - $d, $d, $d, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $d, $d, $d, 90, 90)
    $path.CloseFigure()

    $brush = New-Object Drawing.Drawing2D.LinearGradientBrush(
        (New-Object Drawing.PointF(0, 0)),
        (New-Object Drawing.PointF($s, $s)),
        [Drawing.Color]::FromArgb(255, 30, 58, 95),
        [Drawing.Color]::FromArgb(255, 46, 102, 148))
    $g.FillPath($brush, $path)

    # ключ: кольцо + стержень + два зуба
    $white = [Drawing.Color]::FromArgb(255, 245, 248, 252)
    $penW = [Math]::Max(1.0, $s * 0.085)
    $pen = New-Object Drawing.Pen($white, $penW)
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'

    $ringD = $s * 0.34
    $ringX = $s * 0.17
    $ringY = $s * 0.32
    $g.DrawEllipse($pen, $ringX, $ringY, $ringD, $ringD)

    $shaftY = $ringY + $ringD / 2
    $shaftX1 = $ringX + $ringD
    $shaftX2 = $s * 0.84
    $g.DrawLine($pen, $shaftX1, $shaftY, $shaftX2, $shaftY)

    $toothLen = $s * 0.16
    $g.DrawLine($pen, ($shaftX2 - $s*0.02), $shaftY, ($shaftX2 - $s*0.02), ($shaftY + $toothLen))
    $g.DrawLine($pen, ($shaftX2 - $s*0.20), $shaftY, ($shaftX2 - $s*0.20), ($shaftY + $toothLen*0.62))

    $pen.Dispose(); $brush.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

$sizes = 16, 24, 32, 48, 64, 128, 256
$pngs = @()
foreach ($sz in $sizes) {
    $bmp = New-IconBitmap $sz
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
    $pngs += ,@{ Size = $sz; Data = $ms.ToArray() }
    $ms.Dispose(); $bmp.Dispose()
}

# сборка ICO: заголовок 6 байт + по 16 байт на запись + сами PNG
$out = New-Object IO.MemoryStream
$bw = New-Object IO.BinaryWriter($out)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$pngs.Count)
$offset = 6 + 16 * $pngs.Count
foreach ($p in $pngs) {
    $dim = if ($p.Size -ge 256) { 0 } else { $p.Size }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim)
    $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$p.Data.Length); $bw.Write([uint32]$offset)
    $offset += $p.Data.Length
}
foreach ($p in $pngs) { $bw.Write($p.Data) }
$bw.Flush()
[IO.File]::WriteAllBytes($OutIco, $out.ToArray())
$bw.Dispose(); $out.Dispose()
"Иконка: $OutIco ($((Get-Item $OutIco).Length) байт, размеры: $($sizes -join ', '))"
