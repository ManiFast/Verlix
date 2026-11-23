param([string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    # Exact user project; ApplicationIcon is a build property, not a change to diagnostic code.
    msbuild Velrix.sln /restore /m /p:Configuration=$Configuration /p:ApplicationIcon=Velrix.ico /verbosity:minimal
    if ($LASTEXITCODE -ne 0) { throw "Application build failed: $LASTEXITCODE" }
    $version = (Get-Content installer\version.txt -Raw).Trim()
    $source = Join-Path $root "src\Mobks.SecurityCheck\bin\$Configuration"
    $out = Join-Path $root 'artifacts'
    New-Item -ItemType Directory -Force $out | Out-Null
    $wixBin = if ($env:WIX) { Join-Path $env:WIX 'bin' } else { Join-Path ${env:ProgramFiles(x86)} 'WiX Toolset v3.14\bin' }
    $candle = Join-Path $wixBin 'candle.exe'; $light = Join-Path $wixBin 'light.exe'
    if (!(Test-Path $candle)) { throw 'WiX Toolset 3.14 is required.' }
    & $candle -nologo -arch x64 "-dSourceDir=$source" "-dRepoRoot=$root" "-dAppVersion=$version" -out "$out\Product.wixobj" installer\Product.wxs
    if ($LASTEXITCODE -ne 0) { throw "Candle failed: $LASTEXITCODE" }
    $msi = "$out\Velrix-$version-x64.msi"
    & $light -nologo -ext WixUIExtension -ext WixNetFxExtension -cultures:ru-ru -out $msi "$out\Product.wixobj"
    if ($LASTEXITCODE -ne 0) { throw "Light failed: $LASTEXITCODE" }
    $deps = Join-Path $out 'dependencies'
    New-Item -ItemType Directory -Force $deps | Out-Null
    $runtime = Join-Path $deps 'NetFx48Runtime.exe'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest 'https://go.microsoft.com/fwlink/?linkid=2088631' -OutFile $runtime -UseBasicParsing
    $sig = Get-AuthenticodeSignature $runtime
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'CN=Microsoft Corporation') { throw 'Microsoft Runtime signature verification failed.' }
    $info = (Get-Item $runtime).VersionInfo
    if ($info.FileMajorPart -ne 4 -or $info.FileMinorPart -ne 8) { throw 'Unexpected Runtime version.' }
    $runtimeHash = (Get-FileHash $runtime -Algorithm SHA256).Hash.ToLowerInvariant()
    @("Official URL: https://go.microsoft.com/fwlink/?linkid=2088631", "Signature: $($sig.Status)", "Signer: $($sig.SignerCertificate.Subject)", "File version: $($info.FileVersion)", "SHA256: $runtimeHash") | Set-Content "$out\Runtime-verification.txt"
    & $candle -nologo -ext WixBalExtension -ext WixUtilExtension "-dRepoRoot=$root" "-dAppVersion=$version" "-dRuntimePath=$runtime" "-dMsiPath=$msi" -out "$out\Bundle.wixobj" installer\Bundle.wxs
    if ($LASTEXITCODE -ne 0) { throw "Bundle compile failed: $LASTEXITCODE" }
    & $light -nologo -ext WixBalExtension -ext WixUtilExtension -out "$out\Velrix-$version-Setup.exe" "$out\Bundle.wixobj"
    if ($LASTEXITCODE -ne 0) { throw "Bundle link failed: $LASTEXITCODE" }
    $portable = Join-Path $out 'portable'
    New-Item -ItemType Directory -Force $portable | Out-Null
    Copy-Item "$source\Mobks.SecurityCheck.exe", "$source\Mobks.SecurityCheck.exe.config", "$root\LICENSE" $portable -Force
    Compress-Archive -Path "$portable\*" -DestinationPath "$out\Velrix-$version-portable.zip" -Force
    Get-FileHash $msi, "$out\Velrix-$version-Setup.exe", "$out\Velrix-$version-portable.zip" -Algorithm SHA256 |
        ForEach-Object { "$($_.Hash.ToLowerInvariant())  $(Split-Path $_.Path -Leaf)" } | Set-Content "$out\SHA256SUMS.txt" -Encoding ASCII
    Write-Host "PASS: built package $version from user application 1.0.0; signed Microsoft Runtime embedded."
} finally { Pop-Location }
