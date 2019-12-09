<#
    .Synopsis
    This script queries a XML containing SCCM package details for an appropriate PackageID.
    .DESCRIPTION
    Long description
    .EXAMPLE
    Example of how to use this cmdlet
    .EXAMPLE
    Another example of how to use this cmdlet
#>

[CmdletBinding()]
param (
    # Property of Package to match with model (and operating system for Drivers)
    [string]
    $XMLMatchProperty = "Name",

    # Model Name (defaults to actual Model Name from WMI)
    [string]
    $ModelName = (Get-WmiObject -Class win32_computersystemproduct -Namespace root\cimv2).Name,

    # Path and name of Package XML
    [string]
    $PackageXMLLibrary = ".\packages.xml",

    # Search for Drivers
    [switch]
    $Drivers,

    # Include Operating System Version in search
    [string]
    $PackageTargetOSVersion = ""

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

function Get-CMDynamicPackage
{
  [OutputType([string])]
  Param
  (
    [string]
    $XMLMatchProperty,

    [string]
    $ModelName,

    [string]
    $PackageXMLLibrary,

   # Search for Drivers
    [switch]
    $Drivers,

    [string]
    $PackageTargetOSVersion
  )

    #environment variable call for task sequence only
    try
    {
      $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
      $tsenvInitialized = $true
    }
    catch
    {
      $tsenvInitialized = $false
    }

    write-output "Function `"$($MyInvocation.MyCommand.Name)`" called with Parameters:"
    write-output "  XMLMatchProperty = $XMLMatchProperty"
    write-output "  ModelName = $ModelName"
    write-output "  PackageXMLLibrary = $PackageXMLLibrary"
    write-output "  Drivers = $Drivers"
    write-output "  PackageTargetOSVersion = $PackageTargetOSVersion"    

    # Download Package XML Manifest
    If ($PackageXMLLibrary.ToUpper().Contains("HTTP"))
    {
        # changed for Powershell 2.0
        $Protocol=Split-Path $PackageXMLLibrary -qualifier
        $XML = $packageXMLLibrary.replace("$protocol","C:")
        $XML = $XML.Replace("//","/")
        $XML = $XML.Replace("/","\")
        $XML = Split-Path $XML -Leaf
        write-output "Downloading PackageXMLLibrary from `"$PackageXMLLibrary`" to `"$logpath\$XML`""
        $webclient=New-Object Net.WebClient
        $WebClient.DownloadFile("$PackageXMLLibrary", "$logpath\$XML")        
    }
    Else
    {
        $XML=Split-Path $PackageXMLLibrary -leaf
        write-output "Copying PackageXMLLibrary from `"$PackageXMLLibrary`" to `"$logpath\$XML`""
        Copy-Item -Path $PackageXMLLibrary -Destination "$LogPath\$XML" -Force
    }

    $Packages = Import-CliXML "$logpath\$XML" | Sort-Object -Property Version

    # Search for Firmware Update Package
    if (! $Drivers)
    {
        ForEach ($Package in $Packages)
        {
            # Exclude firmware with "TEST" in comment field.
            If ($Package.$XMLMatchProperty -match $ModelName -and $Package.$XMLMatchProperty -match "Firmware" -and $Package.Description -notmatch "TEST")
            {
                $PackageName=$Package.Name
                $PackageID=$Package.PackageID
                $PackageDescription=$Package.Description
                $PackageVersion=$Package.Version
                write-output "Found matching package with the following properties:"
                write-output "  Package Name         : $PackageName"
                write-output "  PackageID            : $PackageID"
                write-output "  FlashCMD             : $PackageDescription"
                write-output "  FirmwareTargetVersion: $PackageVersion"

                if ($tsenvInitialized)
                {
                    $tsenv.Value('FirmwarePackageID') = $PackageID
                    $tsenv.Value('FirmwareFlashCmd') = $PackageDescription
                    $tsenv.Value('FirmwareTargetVersion') = $PackageVersion
                }
            }
        }
    }
    # Search for Package with Drivers
    else
    {
        ForEach ($Package in $Packages)
        {
            # Exclude drivers with "TEST" in comment field.
            If ($PackageTargetOSVersion -and $PackageTargetOSVersion -ne "")
            {
                If ($Package.$XMLMatchProperty -match $ModelName -and $Package.$XMLMatchProperty -match "Drivers" -and $Package.$XMLMatchProperty -match $PackageTargetOSVersion -and $Package.Description -notmatch "TEST")
                {
                    $PackageName=$Package.Name
                    $PackageID=$Package.PackageID
                    $PackageDescription=$Package.Description
                    $PackageVersion=$Package.Version
                    write-output "Found matching package with the following properties:"
                    write-output "  Package Name         : $PackageName"
                    write-output "  PackageID            : $PackageID"
                    write-output "  Package Version      : $PackageVersion"
                    if ($tsenvInitialized)
                    {
                        $tsenv.Value('DriverPackageID') = $PackageID
                        $tsenv.Value('DriverPackageVersion') = $PackageVersion
                    }
                }
            }
            Else
            {
                If ($Package.$XMLMatchProperty -match $ModelName -and $Package.$XMLMatchProperty -match "Drivers" -and $Package.Description -notmatch "TEST")
                {
                    $PackageName=$Package.Name
                    $PackageID=$Package.PackageID
                    $PackageDescription=$Package.Description
                    $PackageVersion=$Package.Version
                    write-output "Found matching package with the following properties:"
                    write-output "  Package Name         : $PackageName"
                    write-output "  PackageID            : $PackageID"
                    write-output "  Package Version      : $PackageVersion"
                    if ($tsenvInitialized)
                    {
                        $tsenv.Value('DriverPackageID') = $PackageID
                        $tsenv.Value('DriverPackageVersion') = $PackageVersion
                    }
                }

            }

        }
    }
}

$Logpath = Get-LogDir

[string]$scriptFullName = $MyInvocation.MyCommand.Definition

If ($Drivers) {
    [string]$LogName=[IO.Path]::GetFileNameWithoutExtension($scriptFullName) + "-Drivers.log"
}
Else
{
    [string]$LogName=[IO.Path]::GetFileNameWithoutExtension($scriptFullName) + "-Firmware.log"
}

Start-Transcript -Path "$Logpath\$LogName" -Force

write-output "Now Running Script: $ScriptFullName"
If ($Drivers -and ($PackageTargetOSVersion -ne "" -and $PackageTargetOSVersion))
{
    Get-CMDynamicPackage -XMLMatchProperty $XMLMatchProperty -ModelName $ModelName -PackageXMLLibrary $PackageXMLLibrary -PackageTargetOSVersion $PackageTargetOSVersion -Drivers
}
ElseIf ($Drivers)
{
    Get-CMDynamicPackage -XMLMatchProperty $XMLMatchProperty -ModelName $ModelName -PackageXMLLibrary $PackageXMLLibrary -Drivers
}
Else
{
    Get-CMDynamicPackage -XMLMatchProperty $XMLMatchProperty -ModelName $ModelName -PackageXMLLibrary $PackageXMLLibrary
}
write-output "Exiting Script"
Stop-Transcript