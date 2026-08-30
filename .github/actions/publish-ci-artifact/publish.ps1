$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-RequiredEnvironmentValue {
    param([Parameter(Mandatory)][string] $Name)

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Name is required"
    }
    return $value
}

function Write-ActionOutput {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Value
    )

    Add-Content -LiteralPath $script:githubOutput -Value "$Name=$Value" -Encoding utf8
}

$artifactName = Get-RequiredEnvironmentValue 'ARTIFACT_NAME'
$artifactPaths = Get-RequiredEnvironmentValue 'ARTIFACT_PATHS'
$noFilesBehaviour = Get-RequiredEnvironmentValue 'NO_FILES_BEHAVIOUR'
$retentionText = Get-RequiredEnvironmentValue 'RETENTION_DAYS'
$ghcrToken = Get-RequiredEnvironmentValue 'GHCR_TOKEN'
$repository = Get-RequiredEnvironmentValue 'GITHUB_REPOSITORY'
$repositoryOwner = Get-RequiredEnvironmentValue 'GITHUB_REPOSITORY_OWNER'
$runId = Get-RequiredEnvironmentValue 'GITHUB_RUN_ID'
$runAttempt = Get-RequiredEnvironmentValue 'GITHUB_RUN_ATTEMPT'
$workflowSha = Get-RequiredEnvironmentValue 'GITHUB_SHA'
$sourceSha = Get-RequiredEnvironmentValue 'SOURCE_SHA'
$script:githubOutput = Get-RequiredEnvironmentValue 'GITHUB_OUTPUT'
$githubStepSummary = Get-RequiredEnvironmentValue 'GITHUB_STEP_SUMMARY'
$runnerTemp = Get-RequiredEnvironmentValue 'RUNNER_TEMP'

if ($noFilesBehaviour -notin @('error', 'warn', 'ignore')) {
    throw 'if-no-files-found must be error, warn, or ignore'
}

$retentionDays = 0
if (-not [int]::TryParse($retentionText, [ref] $retentionDays) -or $retentionDays -lt 1 -or $retentionDays -gt 7) {
    throw 'retention-days must be an integer from 1 to 7'
}

$workspace = [IO.Path]::GetFullPath((Get-Location).Path)
$workspacePrefix = $workspace.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$matchedPaths = [Collections.Generic.List[string]]::new()
$seenPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$excludePatterns = [Collections.Generic.List[string]]::new()

foreach ($rawLine in [regex]::Split($artifactPaths, '\r?\n')) {
    $pattern = $rawLine.Trim()
    if ([string]::IsNullOrWhiteSpace($pattern)) {
        continue
    }
    if ($pattern.StartsWith('!', [StringComparison]::Ordinal)) {
        $excludePatterns.Add($pattern.Substring(1))
        continue
    }

    $searchPattern = $pattern
    if ($searchPattern.EndsWith('/**', [StringComparison]::Ordinal)) {
        $searchPattern = $searchPattern.Substring(0, $searchPattern.Length - 3)
    }

    $items = @()
    if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($searchPattern)) {
        $items = @(Get-ChildItem -Path $searchPattern -Force -ErrorAction SilentlyContinue)
    } elseif (Test-Path -LiteralPath $searchPattern) {
        $items = @(Get-Item -LiteralPath $searchPattern -Force)
    }

    foreach ($item in $items) {
        $fullPath = [IO.Path]::GetFullPath($item.FullName)
        if ($fullPath -ne $workspace -and -not $fullPath.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Artifact path escapes the workspace: $fullPath"
        }
        $relativePath = [IO.Path]::GetRelativePath($workspace, $fullPath)
        if ($seenPaths.Add($relativePath)) {
            $matchedPaths.Add($relativePath)
        }
    }
}

if ($matchedPaths.Count -eq 0) {
    Write-ActionOutput -Name 'published' -Value 'false'
    switch ($noFilesBehaviour) {
        'error' { throw "No files matched artifact $artifactName" }
        'warn' { Write-Output "::warning::No files matched artifact $artifactName" }
        'ignore' { Write-Output "::notice::No files matched artifact $artifactName; publication skipped" }
    }
    exit 0
}

$runnerTempFull = [IO.Path]::GetFullPath($runnerTemp)
$staging = [IO.Path]::GetFullPath((Join-Path $runnerTempFull ('ci-artifact.' + [guid]::NewGuid().ToString('N'))))
$runnerTempPrefix = $runnerTempFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $staging.StartsWith($runnerTempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to create a staging directory outside RUNNER_TEMP'
}
New-Item -ItemType Directory -Path $staging | Out-Null

$registryConfig = Join-Path $staging 'registry.json'
$loggedIn = $false

try {
    $nameSlug = ($artifactName.ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim([char] '-')
    if ([string]::IsNullOrWhiteSpace($nameSlug)) {
        $nameSlug = 'artifact'
    }
    if ($nameSlug.Length -gt 48) {
        $nameSlug = $nameSlug.Substring(0, 48)
    }

    $nameBytes = [Text.Encoding]::UTF8.GetBytes($artifactName)
    $nameHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($nameBytes)).ToLowerInvariant().Substring(0, 8)
    $archiveName = "$nameSlug.tar.gz"
    $archivePath = Join-Path $staging $archiveName

    $tarPath = (Get-Command tar.exe -ErrorAction Stop).Source
    $tarArguments = [Collections.Generic.List[string]]::new()
    $tarArguments.Add('-czf')
    $tarArguments.Add($archivePath)
    foreach ($excludePattern in $excludePatterns) {
        $tarArguments.Add("--exclude=$excludePattern")
    }
    $tarArguments.Add('--')
    foreach ($matchedPath in $matchedPaths) {
        $tarArguments.Add($matchedPath)
    }
    & $tarPath @tarArguments
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed with exit code $LASTEXITCODE"
    }

    $archiveSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $archiveBytes = (Get-Item -LiteralPath $archivePath).Length
    $created = [DateTime]::UtcNow
    $expires = $created.AddDays($retentionDays)
    $createdAt = $created.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $expiresAt = $expires.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $expiryTag = $expires.ToString('yyyyMMddTHHmmss', [Globalization.CultureInfo]::InvariantCulture)

    $repositoryName = $repository.Split('/', 2)[1]
    $owner = $repositoryOwner.ToLowerInvariant()
    $package = "$($repositoryName.ToLowerInvariant())-ci-artifacts"
    $tag = "run-$runId-a$runAttempt-$nameSlug-$nameHash-e$expiryTag"
    $reference = "ghcr.io/$owner/$package`:$tag"

    $workflowName = [Environment]::GetEnvironmentVariable('GITHUB_WORKFLOW')
    if ([string]::IsNullOrWhiteSpace($workflowName)) { $workflowName = 'unknown' }
    $jobName = [Environment]::GetEnvironmentVariable('GITHUB_JOB')
    if ([string]::IsNullOrWhiteSpace($jobName)) { $jobName = 'unknown' }

    $manifest = [ordered]@{
        schemaVersion = 1
        artifactName = $artifactName
        archive = $archiveName
        archiveSha256 = $archiveSha256
        archiveBytes = $archiveBytes
        repository = $repository
        commit = $sourceSha
        workflowSha = $workflowSha
        workflow = $workflowName
        job = $jobName
        runId = $runId
        runAttempt = $runAttempt
        createdAt = $createdAt
        expiresAt = $expiresAt
    }
    $manifestPath = Join-Path $staging 'manifest.json'
    $manifestJson = $manifest | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($manifestPath, $manifestJson + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))

    $orasPath = (Get-Command oras.exe -ErrorAction Stop).Source
    $actor = [Environment]::GetEnvironmentVariable('GITHUB_ACTOR')
    if ([string]::IsNullOrWhiteSpace($actor)) { $actor = 'github-actions' }

    $ghcrToken | & $orasPath login ghcr.io --username $actor --password-stdin --registry-config $registryConfig
    if ($LASTEXITCODE -ne 0) {
        throw "oras login failed with exit code $LASTEXITCODE"
    }
    $loggedIn = $true

    $serverUrl = [Environment]::GetEnvironmentVariable('GITHUB_SERVER_URL')
    if ([string]::IsNullOrWhiteSpace($serverUrl)) { $serverUrl = 'https://github.com' }

    Push-Location $staging
    try {
        $pushOutput = @(& $orasPath push $reference `
            --registry-config $registryConfig `
            --artifact-type 'application/vnd.krotname.ci-artifact.v1' `
            --annotation "org.opencontainers.image.source=$serverUrl/$repository" `
            --annotation "org.opencontainers.image.revision=$sourceSha" `
            --annotation "org.opencontainers.image.created=$createdAt" `
            --annotation "io.krotname.ci-artifact.expires-at=$expiresAt" `
            --format go-template `
            --template '{{.digest}}' `
            "$archiveName`:application/gzip" `
            'manifest.json:application/vnd.krotname.ci-artifact.metadata.v1+json')
        if ($LASTEXITCODE -ne 0) {
            throw "oras push failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }

    $digest = @($pushOutput | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ -match '^sha256:[0-9a-f]{64}$' } | Select-Object -Last 1)
    if ($digest.Count -ne 1) {
        throw 'oras push did not return exactly one manifest digest'
    }
    $digest = $digest[0]

    $resolved = (& $orasPath resolve $reference --registry-config $registryConfig).Trim()
    if ($LASTEXITCODE -ne 0 -or $resolved -ne $digest) {
        throw "GHCR digest readback $resolved does not match pushed digest $digest"
    }

    Write-ActionOutput -Name 'published' -Value 'true'
    Write-ActionOutput -Name 'package' -Value $package
    Write-ActionOutput -Name 'reference' -Value $reference
    Write-ActionOutput -Name 'digest' -Value $digest
    Write-ActionOutput -Name 'sha256' -Value $archiveSha256
    Write-ActionOutput -Name 'expires-at' -Value $expiresAt

    @(
        "### Private GHCR artifact: $artifactName"
        ''
        "- Reference: ``$reference@$digest``"
        "- Payload SHA-256: ``$archiveSha256``"
        "- Expires: ``$expiresAt``"
    ) | Add-Content -LiteralPath $githubStepSummary -Encoding utf8
} finally {
    if ($loggedIn) {
        & (Get-Command oras.exe -ErrorAction SilentlyContinue).Source logout ghcr.io --registry-config $registryConfig 2>$null | Out-Null
    }
    if (Test-Path -LiteralPath $staging) {
        $stagingReadback = [IO.Path]::GetFullPath($staging)
        if ($stagingReadback.StartsWith($runnerTempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stagingReadback -Recurse -Force
        }
    }
}
