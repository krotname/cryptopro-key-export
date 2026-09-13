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
   public uint type; public MOUSEINPUT mi; }
 [DllImport("user32.dll", SetLastError=true)] static extern uint SendInput(uint n, INPUT[] p, int size);
 [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
 [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
 [DllImport("user32.dll")] static extern int GetSystemMetrics(int n);
 [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
 const uint MOUSEEVENTF_MOVE = 0x0001;
 public static uint Wiggle(int dx, int dy) {
   var inp = new INPUT[1];
   inp[0].type = 0;
   inp[0].mi.dx = dx; inp[0].mi.dy = dy; inp[0].mi.dwFlags = MOUSEEVENTF_MOVE;
   return SendInput(1, inp, Marshal.SizeOf(typeof(INPUT))); }
 public static bool CenterCursor() { return SetCursorPos(GetSystemMetrics(0) / 2, GetSystemMetrics(1) / 2); }
 [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
 [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
 [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
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
     var all = new StringBuilder(2048); var t = new StringBuilder(512); GetWindowTextW(h,t,512); all.Append(t).Append(' ');
     EnumChildWindows(h, (ch,cp) => { if (!IsWindowVisible(ch)) return true;
       var ct = new StringBuilder(512); GetWindowTextW(ch,ct,512);
       if (ct.Length > 0) all.Append(ct).Append(' '); return true; }, IntPtr.Zero);
     res.Add(((long)h) + "|" + all);
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
$random = [Random]::new()

try {
  while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
    $bio = $false
    foreach ($w in [Inp2]::Dialogs($proc.Id)) {
      $parts = $w -split '\|', 2
      $h = [IntPtr][long]$parts[0]
      $dialogText = $parts[1]
      if (-not $seen.ContainsKey($dialogText)) { $seen[$dialogText] = 0; Write-Host "DIALOG: $dialogText" }
      $seen[$dialogText]++
      if ($dialogText -match 'ДСЧ|DRNG|random') {
        $bio = $true
        $instruction = $dialogText
        [void][Inp2]::SetForegroundWindow($h)
      } else {
        [void][Inp2]::PostMessageW($h, 0x0111, [IntPtr]1, [IntPtr]::Zero)   # IDOK
      }
    }
    if ($bio) {
      [void][Inp2]::CenterCursor()
      $axisX = 0; $axisY = 0
      if ($instruction -match 'лев|left') { $axisX = -1 }
      elseif ($instruction -match 'прав|right') { $axisX = 1 }
      elseif ($instruction -match 'выше|верх|up') { $axisY = -1 }
      elseif ($instruction -match 'ниже|низ|down') { $axisY = 1 }
      for ($i = 0; $i -lt 16; $i++) {
        if ($axisX -ne 0) {
          $dx = $axisX * $random.Next(20,61); $dy = $random.Next(-3,4)
        } elseif ($axisY -ne 0) {
          $dx = $random.Next(-3,4); $dy = $axisY * $random.Next(20,61)
        } else {
          $dx = $random.Next(-128,129); $dy = $random.Next(-100,101)
        }
        [void][Inp2]::Wiggle($dx, $dy)
        Start-Sleep -Milliseconds $random.Next(1,4)
      }
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
