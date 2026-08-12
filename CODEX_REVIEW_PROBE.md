# Проверка автоматического ревью Codex

Временный файл. Нужен, чтобы открыть PR и проверить, приходит ли автоматическое
ревью `chatgpt-codex-connector[bot]`: на PR #14 оно пришло за 4 минуты, на #15 и
#16 не пришло вовсе. После проверки PR закрывается без merge, а ветка удаляется.

Ниже — черновик вспомогательной проверки портативной сборки. Ревьюеру есть на что
посмотреть: сравнение контрольной суммы и разбор кода возврата.

```powershell
param([string]$Exe = 'publish/CryptoProExport.exe', [string]$Expected)

$hash = (Get-FileHash $Exe -Algorithm SHA256).Hash
if ($hash -ne $Expected) { throw "Сумма не совпала: $hash" }

$p = Start-Process $Exe 'deps' -Wait -PassThru
if ($p.ExitCode = 0) { 'КриптоПро CSP найден' } else { 'CSP не найден' }
```
