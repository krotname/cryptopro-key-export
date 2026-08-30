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
$positivePatterns = [Collections.Generic.List[string]]::new()
$excludePatterns = [Collections.Generic.List[string]]::new()

function Convert-ArtifactGlobToRegex {
    param([Parameter(Mandatory)][string] $Pattern)

    $normalized = $Pattern.Replace('\', '/')
    $builder = [Text.StringBuilder]::new('^')
    for ($index = 0; $index -lt $normalized.Length; $index++) {
        $character = $normalized[$index]
        if ($character -eq '*' -and $index + 2 -lt $normalized.Length -and
            $normalized[$index + 1] -eq '*' -and $normalized[$index + 2] -eq '/') {
            [void]$builder.Append('(?:.*/)?')
            $index += 2
        } elseif ($character -eq '*' -and $index + 1 -lt $normalized.Length -and
                  $normalized[$index + 1] -eq '*') {
            [void]$builder.Append('.*')
            $index += 1
        } elseif ($character -eq '*') {
            [void]$builder.Append('[^/]*')
        } elseif ($character -eq '?') {
            [void]$builder.Append('[^/]')
        } elseif ($character -eq '[') {
            $closingIndex = $normalized.IndexOf([char] ']', $index + 1)
            if ($closingIndex -le $index + 1) {
                [void]$builder.Append('\[')
                continue
            }

            $classContent = $normalized.Substring($index + 1, $closingIndex - $index - 1)
            $negated = $classContent.StartsWith('!', [StringComparison]::Ordinal) -or
                $classContent.StartsWith('^', [StringComparison]::Ordinal)
            if ($negated) {
                $classContent = $classContent.Substring(1)
            }
            if ([string]::IsNullOrEmpty($classContent) -or $classContent.Contains('/')) {
                [void]$builder.Append('\[')
                continue
            }

            $escapedClass = $classContent.Replace('\', '\\').Replace(']', '\]')
            if ($escapedClass.StartsWith('^', [StringComparison]::Ordinal)) {
                $escapedClass = '\' + $escapedClass
            }
            [void]$builder.Append('[')
            if ($negated) { [void]$builder.Append('^') }
            [void]$builder.Append($escapedClass)
            [void]$builder.Append(']')
            $index = $closingIndex
        } else {
            [void]$builder.Append([regex]::Escape($character))
        }
    }
    [void]$builder.Append('$')
    return [regex]::new($builder.ToString(), [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Test-ArtifactPathMatchesGlob {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $Pattern
    )

    $pathParts = $Path.Split('/')
    $patternParts = $Pattern.Split('/')
    $pending = [Collections.Generic.Stack[Tuple[int, int]]]::new()
    $pending.Push([Tuple]::Create(0, 0))
    $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

    while ($pending.Count -gt 0) {
        $state = $pending.Pop()
        $pathIndex = $state.Item1
        $patternIndex = $state.Item2
        if (-not $visited.Add("$pathIndex,$patternIndex")) {
            continue
        }
        if ($patternIndex -eq $patternParts.Count) {
            if ($pathIndex -eq $pathParts.Count) {
                return $true
            }
            continue
        }

        $patternPart = $patternParts[$patternIndex]
        if ($patternPart -eq '**') {
            $pending.Push([Tuple]::Create($pathIndex, $patternIndex + 1))
            if ($pathIndex -lt $pathParts.Count -and -not $pathParts[$pathIndex].StartsWith('.', [StringComparison]::Ordinal)) {
                $pending.Push([Tuple]::Create($pathIndex + 1, $patternIndex))
            }
            continue
        }
        if ($pathIndex -eq $pathParts.Count) {
            continue
        }

        $pathPart = $pathParts[$pathIndex]
        if ($pathPart.StartsWith('.', [StringComparison]::Ordinal) -and
            -not $patternPart.StartsWith('.', [StringComparison]::Ordinal)) {
            continue
        }
        if ((Convert-ArtifactGlobToRegex -Pattern $patternPart).IsMatch($pathPart)) {
            $pending.Push([Tuple]::Create($pathIndex + 1, $patternIndex + 1))
        }
    }

    return $false
}

function Get-ArtifactArchiveItems {
    param([Parameter(Mandatory)][IO.FileSystemInfo] $Item)

    $isReparsePoint = ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    if ($isReparsePoint -or -not $Item.PSIsContainer) {
        return @($Item)
    }

    return @(Get-ChildItem -LiteralPath $Item.FullName -Force -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $relative = [IO.Path]::GetRelativePath($Item.FullName, $_.FullName)
            foreach ($part in $relative.Split([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) {
                if ($part.StartsWith('.', [StringComparison]::Ordinal)) {
                    return $false
                }
            }
            $childIsReparsePoint = ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            if ($_.PSIsContainer -and -not $childIsReparsePoint) {
                return $false
            }
            return $true
        })
}

function ConvertTo-NormalizedArtifactPattern {
    param([Parameter(Mandatory)][string] $Pattern)

    $normalized = $Pattern.Trim().Replace('\', '/')
    while ($normalized.StartsWith('./', [StringComparison]::Ordinal)) {
        $normalized = $normalized.Substring(2)
    }
    if ([string]::IsNullOrWhiteSpace($normalized) -or
        [IO.Path]::IsPathRooted($Pattern) -or
        $normalized.StartsWith('/', [StringComparison]::Ordinal) -or
        $normalized.Split('/') -contains '..') {
        throw "Artifact pattern must stay relative to the workspace: $Pattern"
    }
    return $normalized
}

foreach ($rawLine in [regex]::Split($artifactPaths, '\r?\n')) {
    $pattern = $rawLine.Trim()
    if ([string]::IsNullOrWhiteSpace($pattern)) {
        continue
    }
    if ($pattern.StartsWith('!', [StringComparison]::Ordinal)) {
        $excludePatterns.Add((ConvertTo-NormalizedArtifactPattern -Pattern $pattern.Substring(1)))
        continue
    }

    $positivePatterns.Add((ConvertTo-NormalizedArtifactPattern -Pattern $pattern))
}

foreach ($purePattern in $positivePatterns) {
    $items = @()
    $recursivePrefix = if ($purePattern.EndsWith('/**', [StringComparison]::Ordinal)) {
        $purePattern.Substring(0, $purePattern.Length - 3)
    } else {
        $null
    }
    if ($null -ne $recursivePrefix -and
        -not [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($recursivePrefix)) {
        $literalDirectory = Join-Path $workspace $recursivePrefix
        if (Test-Path -LiteralPath $literalDirectory) {
            $items = @(Get-Item -LiteralPath $literalDirectory -Force)
        }
    } elseif ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($purePattern)) {
        $segments = $purePattern.Split('/')
        $literalSegments = [Collections.Generic.List[string]]::new()
        foreach ($segment in $segments) {
            if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($segment)) { break }
            $literalSegments.Add($segment)
        }
        $searchRoot = if ($literalSegments.Count -eq 0) {
            $workspace
        } else {
            Join-Path $workspace ([IO.Path]::Combine($literalSegments.ToArray()))
        }
        if (Test-Path -LiteralPath $searchRoot) {
            $items = @(Get-ChildItem -LiteralPath $searchRoot -Force -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    $candidateRelative = [IO.Path]::GetRelativePath($workspace, $_.FullName).Replace('\', '/')
                    Test-ArtifactPathMatchesGlob -Path $candidateRelative -Pattern $purePattern
                })
        }
    } else {
        $literalPath = Join-Path $workspace $purePattern
        if (Test-Path -LiteralPath $literalPath) {
            $items = @(Get-Item -LiteralPath $literalPath -Force)
        }
    }

    foreach ($item in $items) {
        foreach ($archiveItem in Get-ArtifactArchiveItems -Item $item) {
            $fullPath = [IO.Path]::GetFullPath($archiveItem.FullName)
            if ($fullPath -ne $workspace -and -not $fullPath.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Artifact path escapes the workspace: $fullPath"
            }
            if (($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                try {
                    $resolvedTarget = $archiveItem.ResolveLinkTarget($true)
                } catch {
                    throw "Unable to resolve artifact link target: $fullPath"
                }
                if ($null -eq $resolvedTarget) {
                    throw "Unable to resolve artifact link target: $fullPath"
                }
                $resolvedTargetPath = [IO.Path]::GetFullPath($resolvedTarget.FullName)
                if ($resolvedTargetPath -ne $workspace -and
                    -not $resolvedTargetPath.StartsWith($workspacePrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "Artifact link target escapes the workspace: $fullPath -> $resolvedTargetPath"
                }
            }
            $relativePath = [IO.Path]::GetRelativePath($workspace, $fullPath).Replace('\', '/')
            $excluded = $false
            foreach ($excludePattern in $excludePatterns) {
                if ((Test-ArtifactPathMatchesGlob -Path $relativePath -Pattern $excludePattern) -or
                    (-not [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($excludePattern) -and
                     $relativePath.StartsWith($excludePattern.TrimEnd('/') + '/', [StringComparison]::OrdinalIgnoreCase))) {
                    $excluded = $true
                    break
                }
            }
            if (-not $excluded -and $seenPaths.Add($relativePath)) {
                $matchedPaths.Add($relativePath)
            }
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
    $pathList = Join-Path $staging 'paths.nul'

    $pathListStream = [IO.File]::Open($pathList, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        foreach ($matchedPath in $matchedPaths) {
            $pathBytes = [Text.Encoding]::UTF8.GetBytes($matchedPath)
            $pathListStream.Write($pathBytes, 0, $pathBytes.Length)
            $pathListStream.WriteByte(0)
        }
    } finally {
        $pathListStream.Dispose()
    }

    $tarPath = (Get-Command tar -ErrorAction Stop).Source
    & $tarPath '-czf' $archivePath '--null' '-T' $pathList
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

    $orasPath = (Get-Command oras -ErrorAction Stop).Source
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
        & (Get-Command oras -ErrorAction SilentlyContinue).Source logout ghcr.io --registry-config $registryConfig 2>$null | Out-Null
    }
    if (Test-Path -LiteralPath $staging) {
        $stagingReadback = [IO.Path]::GetFullPath($staging)
        if ($stagingReadback.StartsWith($runnerTempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $stagingReadback -Recurse -Force
        }
    }
}
