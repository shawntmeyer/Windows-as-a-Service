# This script automatically generates a setupconfig.ini file for Windows Features updates.
# See https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview for more details.
# amd https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options

[CmdletBinding()]
param (
    # Version of Script for Stamping into File in IPUDirectory
    [Parameter(ValueFromPipelineByPropertyName,
    Position = 0)]
    [version]
    $Version = "1.0.0.0",

    # Directory where SetupComplete.cmd and supporting files will be stored.
    [Parameter(ValueFromPipelineByPropertyName,
    Position = 1)]
    [string]
    $IPUPostProcDir = "$($env:SystemRoot)\IPUPostProcessing",

    # Directory where Drivers Will be staged for Feature Updates.
    [Parameter(ValueFromPipelineByPropertyName,
    Position = 2)]
    [string]
    $IPUDriversDir = "$($env:SystemRoot)\IPUDrivers"
)

function Get-LogDir
{
  try
  {
    $ts = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
    if ($ts.Value("LogPath") -ne "")
    {
        $logDir = $ts.Value("LogPath")
    }
    else
    {
        $logDir = $ts.Value("_SMSTSLogPath")
    }
  }
  catch
  {
    $logDir = $env:temp
  }
  $ts=$null
  return $logDir
}

$TranscriptDir = Get-LogDir
[string]$scriptFullName = $MyInvocation.MyCommand.Definition
[string]$LogName=[IO.Path]::GetFileNameWithoutExtension($scriptFullName) + ".log"

$Transcript = "$TranscriptDir\$LogName"

Start-Transcript -Path $Transcript -Force

Write-Output "Starting $ScriptFullName"

# The following directory is required and must contain setupconfig.ini in order to run post upgrade commands.
$WSUSDir = "$($env:SystemDrive)\Users\Default\AppData\Local\Microsoft\Windows\WSUS"
$SetupConfigFile = "$WSUSDir\setupconfig.ini"

#Copy Contents of Source Folder over to $IPUPostProcDir. This will contain setupcomplete.cmd and supporting files.
Copy-Item -Path $PSScriptRoot\Source -Destination $IPUPostProcDir -Recurse -Force

# Create SetupConfig.ini

If (Test-Path $SetupConfigFile)
{
    $content = Get-Content $SetupConfigFile
    ForEach ($line in $Content)
    {
        If ($line -match "ReflectDrivers") {$ReflectDrivers=$line}
    }
}
ElseIf (!(Test-Path $WSUSDir))
{
    New-Item -Path $WSUSDir -ItemType Directory
}
Else
{
}
# Remove for Bitlocker or no Encryption
<#--
If (!($ReflectDrivers))
{
    $McafeeEEPath="%programfiles%\McAfee\Endpoint Encryption\OSUpgrade"

    If (Test-Path "$McafeeEEPath")
    {
        $ReflectDrivers = "ReflectDrivers=`"$McafeeEEPath`""
    }
}
--##>

New-Item -Path $SetupConfigFile -ItemType File -Force
Add-Content -Path $SetupConfigFile -Value "[SetupConfig]"
Add-Content -Path $SetupConfigFile -Value "`nPostOOBE=`"$IPUPostProcDir`""
If (Test-Path "$IPUDriversDir")
{
    Add-Content -Path $SetupConfigFile -Value "`nInstallDrivers=`"$IPUDriversDir`""
}
If ($ReflectDrivers)
{
    Add-Content -Path $SetupConfigFile -Value "$ReflectDrivers"
}
# Create SetupComplete.cmd
New-Item -Path $IPUPostProcDir\setupcomplete.cmd -ItemType File -Force
Add-content -Path $IPUPostProcDir\setupcomplete.cmd -value "powershell.exe -executionpolicy bypass -file `"$IPUPostProcDir\RemoveApps\Remove-Apps.ps1`""
If (Test-Path "$IPUDriversDir")
{
    Add-Content -Path $IPUPostProcDir\setupcomplete.cmd -value "RD `"$IPUDriversDir`" /S /Q"
}
New-Item -Path $IPUPostProcDir\version.txt -ItemType File -Force
Add-Content -Path $IPUPostProcDir\Version.txt -value "$Version"

Stop-Transcript

