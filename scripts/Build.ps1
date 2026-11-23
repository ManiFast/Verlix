param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    msbuild Velrix.sln /restore /m /p:Configuration=$Configuration /p:ContinuousIntegrationBuild=true /verbosity:minimal
    if ($LASTEXITCODE -ne 0) { throw "Application build failed: $LASTEXITCODE" }
    $version = ([xml](Get-Content src\Velrix\Velrix.csproj)).Project.PropertyGroup.Version
    $source = Join-Path $root "src\Velrix\bin\$Configuration\net48"
    $out = Join-Path $root 'artifacts'
    New-Item -ItemType Directory -Force $out | Out-Null
    $wixBin = if ($env:WIX) { Join-Path $env:WIX 'bin' } else { Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3.14\bin' }
    $candle = Join-Path $wixBin 'candle.exe'; $light = Join-Path $wixBin 'light.exe'
    if (!(Test-Path $candle)) { throw 'WiX Toolset 3.14 is required to build the MSI.' }
    & $candle -nologo -arch x64 "-dSourceDir=$source" "-dRepoRoot=$root" "-dAppVersion=$version" -out "$out\Product.wixobj" installer\Product.wxs
    if ($LASTEXITCODE -ne 0) { throw "Candle failed: $LASTEXITCODE" }
    & $light -nologo -ext WixUIExtension -cultures:ru-ru -out "$out\Velrix-$version-x64.msi" "$out\Product.wixobj"
    if ($LASTEXITCODE -ne 0) { throw "Light failed: $LASTEXITCODE" }
    $portable = Join-Path $out 'portable'
    New-Item -ItemType Directory -Force $portable | Out-Null
    Copy-Item "$source\Velrix.exe", "$source\Velrix.exe.config", "$root\LICENSE" $portable -Force
    Compress-Archive -Path "$portable\*" -DestinationPath "$out\Velrix-$version-portable.zip" -Force
    Get-FileHash "$out\Velrix-$version-x64.msi", "$out\Velrix-$version-portable.zip" -Algorithm SHA256 |
        ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path $_.Path -Leaf)" } | Set-Content "$out\SHA256SUMS.txt" -Encoding ASCII
    Write-Host "Built Velrix $version"
} finally { Pop-Location }
