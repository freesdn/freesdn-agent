# =============================================================================
# FreeSDN Agent — Windows MSI Builder (WiX Toolset v4)
#
# Usage:
#   .\build_msi.ps1 -Version "0.4.0" -BinaryPath "dist\freesdn-agent.exe"
#
# Prerequisites:
#   - WiX Toolset v4: dotnet tool install --global wix
#   - Or: winget install FireGiant.WiX
# =============================================================================
param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,

    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"

$ProductName = "FreeSDN Agent"
$Manufacturer = "FreeSDN Team"
$UpgradeCode = "7A3B4C5D-6E7F-8A9B-0C1D-2E3F4A5B6C7D"
$OutputMsi = Join-Path $OutputDir "freesdn-agent-${Version}-win64.msi"

# Validate binary
if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 1
}

# Verify WiX is installed
$wixPath = Get-Command "wix" -ErrorAction SilentlyContinue
if (-not $wixPath) {
    Write-Error @"
WiX Toolset not found. Install with:
  dotnet tool install --global wix
  OR
  winget install FireGiant.WiX
"@
    exit 1
}

Write-Host "Building MSI installer v${Version}..."

# Get absolute paths
$BinaryFullPath = (Resolve-Path $BinaryPath).Path
$WxsTemplate = Join-Path $PSScriptRoot "wix\product.wxs"

if (-not (Test-Path $WxsTemplate)) {
    Write-Error "WiX template not found: $WxsTemplate"
    exit 1
}

# Build with WiX v4
wix build `
    -src "$WxsTemplate" `
    -d "Version=$Version" `
    -d "BinaryPath=$BinaryFullPath" `
    -d "ProductName=$ProductName" `
    -d "Manufacturer=$Manufacturer" `
    -d "UpgradeCode=$UpgradeCode" `
    -out "$OutputMsi" `
    -arch x64

if ($LASTEXITCODE -ne 0) {
    Write-Error "WiX build failed"
    exit 1
}

# Generate checksum
$hash = Get-FileHash -Path $OutputMsi -Algorithm SHA256
$hash.Hash | Out-File "${OutputMsi}.sha256" -Encoding ascii
Write-Host "SHA-256: $($hash.Hash)"

$size = (Get-Item $OutputMsi).Length / 1MB
Write-Host "Built: $OutputMsi ($([math]::Round($size, 1)) MB)"
