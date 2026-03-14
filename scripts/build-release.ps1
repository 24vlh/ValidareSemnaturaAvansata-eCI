[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias("Build", "Mode")]
    [ValidateSet("all", "folder", "portable")]
    [string]$Target = "all",

    [Parameter(Position = 1)]
    [string]$Version,

    [string]$PythonExe
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$AppName = "ValidareSemnaturaAvansata-eCI"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$SourceFile = Join-Path $ProjectRoot "$AppName.py"
$AssetsDir = Join-Path $ProjectRoot "assets"
$BuildInfoPath = Join-Path $AssetsDir "build_info.json"
$DistDir = Join-Path $ProjectRoot "dist"
$BuildDir = Join-Path $ProjectRoot "build"
$VenvDir = Join-Path $ProjectRoot ".venv"
$ManagedVenvPython = Join-Path $VenvDir "Scripts\python.exe"
$BuildRequirementsPath = Join-Path $ProjectRoot "requirements-build.txt"
$IconPath = Join-Path $AssetsDir "app.ico"
$FolderBuildPath = Join-Path $DistDir $AppName
$FolderZipPath = $null
$PortableExePath = $null

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label not found: $Path"
    }
}

function Get-AppVersionFromSource {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $match = [regex]::Match($content, '(?m)^APP_VERSION\s*=\s*"(?<version>[^"]+)"')
    if (-not $match.Success) {
        throw "Could not read APP_VERSION from $Path"
    }

    return $match.Groups["version"].Value
}

function Write-BuildInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    $payload = [ordered]@{
        build_date = (Get-Date -Format "yyyy-MM-dd")
        version    = $Version
        target     = $Target
    }

    if (-not (Test-Path -LiteralPath $AssetsDir)) {
        New-Item -ItemType Directory -Path $AssetsDir | Out-Null
    }

    $payload | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage Exit code: $LASTEXITCODE."
    }
}

function Resolve-BootstrapPython {
    if ($PythonExe) {
        $resolved = Get-Command $PythonExe -ErrorAction SilentlyContinue
        if (-not $resolved) {
            throw "Requested Python executable not found: $PythonExe"
        }

        return @{
            FilePath = $resolved.Source
            PrefixArgs = @()
        }
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        return @{
            FilePath = $pyLauncher.Source
            PrefixArgs = @("-3")
        }
    }

    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        return @{
            FilePath = $pythonCmd.Source
            PrefixArgs = @()
        }
    }

    throw "No Windows Python interpreter was found. Install Windows Python or the 'py' launcher. WSL Python cannot build Windows executables with PyInstaller."
}

function Ensure-ManagedVenv {
    Assert-PathExists -Path $BuildRequirementsPath -Label "Build requirements file"

    if (-not (Test-Path -LiteralPath $ManagedVenvPython)) {
        $bootstrap = Resolve-BootstrapPython
        Write-Host "Managed Windows venv missing. Creating: $VenvDir"
        Invoke-ExternalCommand `
            -FilePath $bootstrap.FilePath `
            -Arguments ($bootstrap.PrefixArgs + @("-m", "venv", $VenvDir)) `
            -FailureMessage "Failed to create managed Windows virtual environment."
    }

    $script:PythonExe = $ManagedVenvPython
}

function Install-BuildRequirements {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InterpreterPath
    )

    Write-Host "Installing/updating build requirements..."
    Invoke-ExternalCommand `
        -FilePath $InterpreterPath `
        -Arguments @("-m", "pip", "install", "--upgrade", "pip") `
        -FailureMessage "Failed to upgrade pip in the selected Python environment."
    Invoke-ExternalCommand `
        -FilePath $InterpreterPath `
        -Arguments @("-m", "pip", "install", "-r", $BuildRequirementsPath) `
        -FailureMessage "Failed to install build requirements into the selected Python environment."
}

function Invoke-PyInstallerBuild {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("folder", "portable")]
        [string]$Mode
    )

    $workPath = Join-Path $BuildDir "pyinstaller-$Mode"
    $specPath = Join-Path $BuildDir "spec-$Mode"

    if (Test-Path -LiteralPath $workPath) {
        Remove-Item -LiteralPath $workPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $specPath) {
        Remove-Item -LiteralPath $specPath -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

    $pyInstallerArgs = @(
        "-m", "PyInstaller",
        "--clean",
        "--noconfirm",
        "--noconsole",
        "--name", $AppName,
        "--distpath", $DistDir,
        "--workpath", $workPath,
        "--specpath", $specPath
    )

    if ($Mode -eq "portable") {
        $pyInstallerArgs += "--onefile"
    }

    if (Test-Path -LiteralPath $IconPath) {
        $pyInstallerArgs += @("--icon", $IconPath)
    }

    if (Test-Path -LiteralPath $AssetsDir) {
        $pyInstallerArgs += @("--add-data", "$AssetsDir;assets")
    }

    $pyInstallerArgs += $SourceFile

    & $PythonExe @pyInstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller $Mode build failed with exit code $LASTEXITCODE."
    }
}

function New-FolderBuildZip {
    Assert-PathExists -Path $FolderBuildPath -Label "Folder build"

    if (Test-Path -LiteralPath $FolderZipPath) {
        Remove-Item -LiteralPath $FolderZipPath -Force
    }

    Compress-Archive -Path $FolderBuildPath -DestinationPath $FolderZipPath -Force
}

function Publish-PortableExe {
    $rawPortableExe = Join-Path $DistDir "$AppName.exe"
    Assert-PathExists -Path $rawPortableExe -Label "Portable build"

    if (Test-Path -LiteralPath $PortableExePath) {
        Remove-Item -LiteralPath $PortableExePath -Force
    }

    Move-Item -LiteralPath $rawPortableExe -Destination $PortableExePath -Force
}

Assert-PathExists -Path $SourceFile -Label "Application source"
Assert-PathExists -Path $BuildRequirementsPath -Label "Build requirements file"

if ($PythonExe) {
    $resolvedPython = Get-Command $PythonExe -ErrorAction SilentlyContinue
    if (-not $resolvedPython) {
        throw "Python executable not found: $PythonExe"
    }
    $PythonExe = $resolvedPython.Source
}
else {
    Ensure-ManagedVenv
}

Install-BuildRequirements -InterpreterPath $PythonExe

$sourceVersion = Get-AppVersionFromSource -Path $SourceFile
if ($Version) {
    if ($Version -notmatch '^\d+\.\d+\.\d+$') {
        throw "Invalid version format '$Version'. Expected x.y.z."
    }
    if ($sourceVersion -ne $Version) {
        throw "Version mismatch: script received '$Version' but APP_VERSION in $SourceFile is '$sourceVersion'. Update one of them so they match."
    }
}
else {
    $Version = $sourceVersion
}

$FolderZipPath = Join-Path $DistDir "$AppName-v$Version-portable-folder-build.zip"
$PortableExePath = Join-Path $DistDir "$AppName-v$Version-portable.exe"

Push-Location $ProjectRoot
try {
    Write-Host "Build target : $Target"
    Write-Host "Version      : $Version"
    Write-Host "Project root : $ProjectRoot"
    Write-Host "Python       : $PythonExe"
    Invoke-ExternalCommand -FilePath $PythonExe -Arguments @("--version") -FailureMessage "Failed to invoke Python executable."

    Write-BuildInfo -Path $BuildInfoPath -Version $Version -Target $Target

    if ($Target -in @("all", "folder")) {
        Invoke-PyInstallerBuild -Mode "folder"
        New-FolderBuildZip
    }

    if ($Target -in @("all", "portable")) {
        Invoke-PyInstallerBuild -Mode "portable"
        Publish-PortableExe
    }

    Write-Host ""
    Write-Host "Artifacts:"
    if (Test-Path -LiteralPath $FolderBuildPath) {
        Write-Host " - Folder build : $FolderBuildPath"
    }
    if (Test-Path -LiteralPath $FolderZipPath) {
        Write-Host " - Folder zip   : $FolderZipPath"
    }
    if (Test-Path -LiteralPath $PortableExePath) {
        Write-Host " - Portable exe : $PortableExePath"
    }
}
finally {
    Pop-Location
}
