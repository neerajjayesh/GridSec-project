param([string]$Distro = "Ubuntu-24.04", [switch]$Demo)
$ErrorActionPreference = "Stop"
$projectDirectory = $PSScriptRoot
$linuxDirectory = (& wsl.exe -d $Distro -e wslpath -a $projectDirectory).Trim()
if ($LASTEXITCODE -ne 0 -or -not $linuxDirectory) {
    throw "Cannot access this checkout inside WSL distribution $Distro."
}
$launchArguments = @("-d", $Distro, "-e", "bash", "$linuxDirectory/run.sh")
if ($Demo) { $launchArguments += "--demo" }
& wsl.exe @launchArguments
if ($LASTEXITCODE -ne 0) {
    throw "GridSec did not start successfully. Review the error above; verify WSLg is available."
}
