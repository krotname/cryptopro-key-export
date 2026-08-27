# Создать контейнер прямо на токене (генерация ключа на месте, без импорта с диска).
# Та же техника, что в make-ref-container.ps1: Био ДСЧ собирает энтропию из ДВИЖЕНИЙ мыши
# уровня драйвера (SendInput), а модальные диалоги закрываются посылкой WM_COMMAND.
# Отличие — произвольный путь контейнера и PIN носителя.
param(
  [Parameter(Mandatory = $true)][string]$ContainerPath,   # напр. \\.\Aktiv Rutoken ECP 0\cpxref
  [string]$Password = '12345678',
  [int]$ProvType = 80,
  [int]$TimeoutSec = 180
)
$ErrorActionPreference = 'Stop'

Add-Type @'
using System;using System.Text;using System.Runtime.InteropServices;using System.Collections.Generic;
public class Inp2 {
 [StructLayout(LayoutKind.Sequential)] struct MOUSEINPUT {
   public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
 [StructLayout(LayoutKind.Sequential)] struct INPUT {
   public uint type; public MOUSEINPUT mi; public long pad1; public long pad2; }
 [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint n, INPUT[] p, int size);
 [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
 [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
 const uint MOUSEEVENTF_MOVE = 0x0001;
 public static uint Wiggle(int dx, int dy) {
   var inp = new INPUT[1];
   inp[0].type = 0;
   inp[0].mi.dx = dx; inp[0].mi.dy = dy; inp[0].mi.dwFlags = MOUSEEVENTF_MOVE;
   return SendInput(1, inp, Marshal.SizeOf(typeof(INPUT))); }
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
 [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
 [DllImport("user32.dll")] public static extern IntPtr PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 delegate bool EnumProc(IntPtr h, IntPtr p);
 public static List<string> Dialogs(uint pid) {
   var res = new List<string>();
   EnumWindows((h,p) => {
     uint wp; GetWindowThreadProcessId(h, out wp);
     if (wp != pid) return true;
     var c = new StringBuilder(64); GetClassNameW(h,c,64);
     if (c.ToString() != "#32770") return true;
     var t = new StringBuilder(512); GetWindowTextW(h,t,512);
     res.Add(((long)h) + "|" + t);
     return true; }, IntPtr.Zero);
   return res; }
}
'@

$exe = 'C:\Program Files\Crypto Pro\CSP\csptest.exe'
$stdout = [IO.Path]::GetTempFileName()
$stderr = [IO.Path]::GetTempFileName()

# Окно НЕ скрываем: Био ДСЧ рисует прогресс и должен быть на переднем плане.
$cmdline = "-keyset -newkeyset -container `"$ContainerPath`" -provtype $ProvType -password $Password -protected=none"
Write-Host "csptest -keyset -newkeyset -container `"$ContainerPath`" -provtype $ProvType -password [REDACTED] -protected=none"
$proc = Start-Process $exe -ArgumentList $cmdline -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr

[Inp2+POINT]$origin = New-Object 'Inp2+POINT'
[void][Inp2]::GetCursorPos([ref]$origin)
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$seen = @{}

try {
  while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
    $bio = $false
    foreach ($w in [Inp2]::Dialogs($proc.Id)) {
      $parts = $w -split '\|', 2
      $h = [IntPtr][long]$parts[0]
      $title = $parts[1]
      if (-not $seen.ContainsKey($title)) { $seen[$title] = 0; Write-Host "DIALOG: $title" }
      $seen[$title]++
      if ($title -match 'ДСЧ|DRNG|random') {
        $bio = $true
        [void][Inp2]::SetForegroundWindow($h)
      } else {
        [void][Inp2]::PostMessageW($h, 0x0111, [IntPtr]1, [IntPtr]::Zero)   # IDOK
      }
    }
    if ($bio) {
      for ($i = 0; $i -lt 40; $i++) {
        [void][Inp2]::Wiggle(7, 3); [void][Inp2]::Wiggle(-3, 7)
        [void][Inp2]::Wiggle(-7, -3); [void][Inp2]::Wiggle(3, -7)
      }
      Start-Sleep -Milliseconds 30
    } else {
      Start-Sleep -Milliseconds 300
    }
  }
} finally {
  [void][Inp2]::SetCursorPos($origin.X, $origin.Y)
}

if (-not $proc.HasExited) { Write-Host 'TIMEOUT, снимаю процесс'; $proc.Kill() }
# WaitForExit() без аргумента нужен и после нормального выхода: HasExited становится true
# раньше, чем закрываются перенаправленные потоки, и чтение файла падает с «used by another
# process». Ждём именно здесь, а не только в ветке TIMEOUT.
$proc.WaitForExit()
Write-Host '---- stdout ----'
Write-Host ([Text.Encoding]::GetEncoding(866).GetString([IO.File]::ReadAllBytes($stdout)))
Write-Host '---- stderr ----'
Write-Host ([Text.Encoding]::GetEncoding(866).GetString([IO.File]::ReadAllBytes($stderr)))
Write-Host "---- exit: 0x$('{0:X8}' -f $proc.ExitCode) ----"
Remove-Item $stdout, $stderr -ErrorAction SilentlyContinue
exit $proc.ExitCode
