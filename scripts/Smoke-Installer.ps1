param([Parameter(Mandatory=$true)][string]$MsiPath)
$ErrorActionPreference = 'Stop'
$msi = (Resolve-Path $MsiPath).Path
$folder = Join-Path $env:ProgramFiles 'Velrix'
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Velrix.lnk'
$installLog = Join-Path (Split-Path $msi) 'install.log'
$uninstallLog = Join-Path (Split-Path $msi) 'uninstall.log'
try {
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /l*v `"$installLog`"" -PassThru -Wait
    if ($p.ExitCode -notin 0,3010) { throw "Install failed: $($p.ExitCode)" }
    if (!(Test-Path "$folder\Velrix.exe") -or !(Test-Path $shortcut)) { throw 'Installed executable or Start menu shortcut missing.' }
    if ((Get-Item "$folder\Velrix.exe").VersionInfo.FileVersion -ne '1.0.0.0') { throw 'Wrong installed version.' }
    Write-Host 'PASS: MSI installed application and Start menu shortcut.'
} finally {
    $p = Start-Process msiexec.exe -ArgumentList "/x `"$msi`" /qn /norestart /l*v `"$uninstallLog`"" -PassThru -Wait
    if ($p.ExitCode -notin 0,3010,1605) { throw "Uninstall failed: $($p.ExitCode)" }
}
if ((Test-Path "$folder\Velrix.exe") -or (Test-Path $shortcut)) { throw 'Application or shortcut remained after uninstall.' }
Write-Host 'PASS: MSI uninstalled application and Start menu shortcut.'
