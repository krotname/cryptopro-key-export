$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir

# 1. real winscard alongside, renamed so forwarders don't recurse
Copy-Item 'C:\Windows\System32\winscard.dll' (Join-Path $dir 'winscard_real.dll') -Force

# 2. full export list of winscard.dll
$all = @(
'ClassInstall32','SCardAccessNewReaderEvent','SCardAccessStartedEvent','SCardAddReaderToGroupA',
'SCardAddReaderToGroupW','SCardAudit','SCardBeginTransaction','SCardCancel','SCardConnectA','SCardConnectW',
'SCardControl','SCardDisconnect','SCardEndTransaction','SCardEstablishContext','SCardForgetCardTypeA',
'SCardForgetCardTypeW','SCardForgetReaderA','SCardForgetReaderGroupA','SCardForgetReaderGroupW','SCardForgetReaderW',
'SCardFreeMemory','SCardGetAttrib','SCardGetCardTypeProviderNameA','SCardGetCardTypeProviderNameW','SCardGetDeviceTypeIdA',
'SCardGetDeviceTypeIdW','SCardGetProviderIdA','SCardGetProviderIdW','SCardGetReaderDeviceInstanceIdA','SCardGetReaderDeviceInstanceIdW',
'SCardGetReaderIconA','SCardGetReaderIconW','SCardGetStatusChangeA','SCardGetStatusChangeW','SCardGetTransmitCount',
'SCardIntroduceCardTypeA','SCardIntroduceCardTypeW','SCardIntroduceReaderA','SCardIntroduceReaderGroupA','SCardIntroduceReaderGroupW',
'SCardIntroduceReaderW','SCardIsValidContext','SCardListCardsA','SCardListCardsW','SCardListInterfacesA',
'SCardListInterfacesW','SCardListReaderGroupsA','SCardListReaderGroupsW','SCardListReadersA','SCardListReadersW',
'SCardListReadersWithDeviceInstanceIdA','SCardListReadersWithDeviceInstanceIdW','SCardLocateCardsA','SCardLocateCardsByATRA','SCardLocateCardsByATRW',
'SCardLocateCardsW','SCardPciRaw','SCardPciT0','SCardPciT1','SCardReadCacheA',
'SCardReadCacheW','SCardReconnect','SCardReleaseAllEvents','SCardReleaseContext','SCardReleaseNewReaderEvent',
'SCardReleaseStartedEvent','SCardRemoveReaderFromGroupA','SCardRemoveReaderFromGroupW','SCardSetAttrib','SCardSetCardTypeProviderNameA',
'SCardSetCardTypeProviderNameW','SCardState','SCardStatusA','SCardStatusW','SCardTransmit',
'SCardWriteCacheA','SCardWriteCacheW'
)
$data = @('g_rgSCardRawPci','g_rgSCardT0Pci','g_rgSCardT1Pci')
$hook = @{
 'SCardConnectA'='MyConnectA'; 'SCardConnectW'='MyConnectW'; 'SCardTransmit'='MyTransmit';
 'SCardControl'='MyControl'; 'SCardBeginTransaction'='MyBegin'; 'SCardEndTransaction'='MyEnd';
 'SCardReconnect'='MyReconnect'; 'SCardDisconnect'='MyDisconnect'; 'SCardStatusA'='MyStatusA'; 'SCardStatusW'='MyStatusW'
}

$dataSet = @{}; foreach ($d in $data) { $dataSet[$d] = $true }
$lines = @('#pragma once')
foreach ($n in $hook.Keys) { $lines += "#pragma comment(linker, `"/EXPORT:$n=$($hook[$n])`")" }
foreach ($n in $data)      { $lines += "#pragma comment(linker, `"/EXPORT:$n=winscard_real.$n,DATA`")" }
foreach ($n in $all) { if (-not $hook.ContainsKey($n) -and -not $dataSet.ContainsKey($n)) { $lines += "#pragma comment(linker, `"/EXPORT:$n=winscard_real.$n`")" } }
Set-Content -Path (Join-Path $dir 'forwarders.h') -Value $lines -Encoding ASCII

# 3. compile x64 within vcvars64
$vc = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$cmd = "call `"$vc`" >nul && cl /nologo /O2 /MT /LD proxy.c /Fe:winscard.dll"
cmd /c $cmd
Write-Host "exit=$LASTEXITCODE"
Get-ChildItem (Join-Path $dir 'winscard.dll') -ErrorAction SilentlyContinue | Select-Object FullName,Length
