param([Parameter(Mandatory=$true)][string]$ExePath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path $ExePath))
[System.Windows.Application]::ResourceAssembly = $assembly
$app = [Activator]::CreateInstance($assembly.GetType('Mobks.SecurityCheck.App', $true))
$app.InitializeComponent()
$window = [Activator]::CreateInstance($assembly.GetType('Mobks.SecurityCheck.MainWindow', $true))
try {
    $window.Show(); $window.UpdateLayout()
    if ($window.FindName('VersionButton').Content -ne 'v1.0.0') { throw 'Version link was not initialized.' }
    foreach ($name in 'InternetStatus','AntivirusStatus','AntivirusTestStatus','FirewallStatus','FirewallTestStatus','SaveReportButton') {
        if (!$window.FindName($name)) { throw "Missing control: $name" }
    }
    $bitmap = New-Object System.Windows.Media.Imaging.RenderTargetBitmap ([int]$window.ActualWidth),([int]$window.ActualHeight),96,96,([System.Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($window)
    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [IO.File]::Create((Join-Path (Resolve-Path artifacts) 'Velrix-start.png'))
    try { $encoder.Save($stream) } finally { $stream.Dispose() }
    Write-Host 'PASS: WPF window, version link and five check controls initialized. No protection tests were executed.'
} finally { $window.Close(); $app.Shutdown() }
