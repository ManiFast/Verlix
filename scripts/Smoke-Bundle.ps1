param([Parameter(Mandatory=$true)][string]$SetupPath)
$ErrorActionPreference = 'Stop'
$setup = (Resolve-Path $SetupPath).Path
$out = Split-Path $setup
$folder = Join-Path $env:ProgramFiles 'Velrix'
$installLog = Join-Path $out 'bundle-install.log'
$uninstallLog = Join-Path $out 'bundle-uninstall.log'
$before = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
try {
    $p = Start-Process $setup -ArgumentList "/quiet /norestart /log `"$installLog`"" -Wait -PassThru
    if ($p.ExitCode -notin 0,3010) { throw "Bundle install failed: $($p.ExitCode)" }
    if (!(Test-Path "$folder\Mobks.SecurityCheck.exe")) { throw 'Bundle did not install the application.' }
    $log = Get-Content $installLog -Raw
    if ($before -ge 528040 -and $log -notmatch 'Planned package: NetFx48,.*execute: None') { throw 'Existing compatible Framework was not skipped.' }
    Write-Host 'PASS: offline bundle installed the app and skipped the already installed compatible Framework.'
} finally {
    $p = Start-Process $setup -ArgumentList "/uninstall /quiet /norestart /log `"$uninstallLog`"" -Wait -PassThru
    if ($p.ExitCode -notin 0,3010) { throw "Bundle uninstall failed: $($p.ExitCode)" }
}
if (Test-Path "$folder\Mobks.SecurityCheck.exe") { throw 'Bundle left the application installed.' }
$after = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release
if ($before -ne $after) { throw 'Bundle unexpectedly changed existing Framework.' }
Write-Host 'PASS: bundle removed the app and retained the shared Framework.'
