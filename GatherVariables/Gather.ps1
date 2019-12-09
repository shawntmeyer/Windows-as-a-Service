﻿<#
    Name: Gather.ps1
    Author: Johan Schrewelius, Onevinn AB
    Date: 2018-10-17
    Command: powershell.exe -executionpolicy bypass -file Gather.ps1 [-debug]
    Usage: Run in SCCM Task Sequence as lightweight replacement for MDT Gather Step
    Remark: Creates and sets a limited number of MDT Task Sequence variables, the most commonly used - subjectiveley
    Updated by Sassan Fanai, Onevinn: Added switch parameter and logic to handle Lenovo models
    Revision 1.1, 2018-12-21: Added more variables and debug switch, aligned variable names with MDT
#>

param (
[switch]$UseOldLenovoName,
[switch]$Debug
)

$TSvars = @{}

$DesktopChassisTypes = @("3","4","5","6","7","13","15","16")
$LatopChassisTypes = @("8","9","10","11","12","14","18","21","30","31")
$ServerChassisTypes = @("23")

$VirtualHosts = @{ "Virtual Machine"="Hyper-V"; "VMware Virtual Platform"="VMware"; "VirtualBox"="VirtualBox"; "Xen"="Xen" }

function Get-ComputerSystemProductInfo {

    $cmp = gwmi -Class 'Win32_ComputerSystemProduct'

    If ($cmp.Vendor -eq "LENOVO" -and $UseOldLenovoName -ne $true) {
        $tempModel = $cmp.Version
    }
    else {
        $tempModel = $cmp.Name
    }

    $TSvars.Add("Model", $tempModel)
    $TSvars.Add("UUID", $cmp.UUID)
    $TSvars.Add("Vendor", $cmp.Vendor)

    if($VirtualHosts.ContainsKey($tempModel)) {
        $TSvars.Add("IsVM", "True")
        $TSvars.Add("VMPlatform", $VirtualHosts[$tempModel])
    }
    else {
        $TSvars.Add("IsVM", "False")
        $TSvars.Add("VMPlatform", "")
    }
}

function Get-ComputerSystemInfo {

    $cmp = gwmi -Class 'Win32_ComputerSystem'
    $TSvars.Add("Memory", ($cmp.TotalPhysicalMemory / 1024 / 1024).ToString())
}

function Get-Product {

    $bb = gwmi -Class 'Win32_BaseBoard'
    $TSvars.Add("Product", $bb.Product)
}

function Get-BiosInfo {

    $bios = gwmi -Class 'Win32_BIOS'
    $TSvars.Add("SerialNumber", $bios.SerialNumber)
    $TSvars.Add("BIOSVersion", $bios.SMBIOSBIOSVersion)
}

function Get-OsInfo {

    $Os = gwmi -Class 'Win32_OperatingSystem'
    $TSvars.Add("OSCurrentVersion", $Os.Version)
    $TSvars.Add("OSCurrentBuild", $Os.BuildNumber)
}

function Get-SystemEnclosureInfo {

    $chassi = gwmi -Class 'Win32_SystemEnclosure' 
    $TSvars.Add("AssetTag", $chassi.SMBIOSAssetTag)

    $chassi.ChassisTypes | foreach {

        if($TSvars.ContainsKey("IsDesktop")) {
            $TSvars["IsDesktop"] = [string]$DesktopChassisTypes.Contains($_.ToString())
        }
        else {
            $TSvars.Add("IsDesktop", [string]$DesktopChassisTypes.Contains($_.ToString()))
        }

        if($TSvars.ContainsKey("IsLaptop")) {
            $TSvars["IsLaptop"] = [string]$LatopChassisTypes.Contains($_.ToString())
        }
        else {
            $TSvars.Add("IsLaptop", [string]$LatopChassisTypes.Contains($_.ToString()))
        }

        if($TSvars.ContainsKey("IsServer")) {
            $TSvars["IsServer"] = [string]$ServerChassisTypes.Contains($_.ToString())
        }
        else {
            $TSvars.Add("IsServer", [string]$ServerChassisTypes.Contains($_.ToString()))
        }
    }
}

function Get-NicConfigurationInfo {

    (gwmi -Class 'Win32_NetworkAdapterConfiguration' -Filter "IPEnabled = 1") | foreach {
        
        $_.IPAddress |% {
            if($_ -ne $null) {
                if($_.IndexOf('.') -gt 0 -and !$_.StartsWith("169.254") -and $_ -ne "0.0.0.0") {

                    if($TSvars.ContainsKey("IPAddress")) {
                         $TSvars["IPAddress"] = $TSvars["IPAddress"] + ',' + $_
                    }
                    else {
                        $TSvars.Add("IPAddress", $_)
                    }
                }
            }
        }

        $_.DefaultIPGateway |% {

            if($_ -ne $null -and $_.IndexOf('.') -gt 0) {

                if($TSvars.ContainsKey("DefaultGateway")) {
                    $TSvars["DefaultGateway"] = $TSvars["DefaultGateway"] + ',' + $_
                }
                else {
                    $TSvars.Add("DefaultGateway", $_)
                }
            }
        }
    }
}

function Get-MacInfo {

    $nic = (gwmi -Class 'Win32_NetworkAdapter' -Filter "NetConnectionStatus = 2")
    $TSvars.Add("MacAddress", $nic.MACAddress -join ',')
}

function Get-BatteryStatus {

    try {
        $AcConnected = (gwmi -Namespace 'root\wmi' -Query "SELECT * FROM BatteryStatus Where Voltage > 0" -EA SilentlyContinue).PowerOnline
    }
    catch { }

    if ($AcConnected -eq $null) {
        $AcConnected = "True"
    }

    $TSvars.Add("IsOnBattery", ((![bool]$AcConnected)).ToString())
}

function Get-Architecture {
    
    $arch = "X86"

    if($env:PROCESSOR_ARCHITECTURE.Equals("AMD64")) {
        $arch = "X64"
    }

    $TSvars.Add("Architecture", $arch)
}

function Get-Processor {

    $proc = gwmi -Class 'Win32_Processor' 
    $TSvars.Add("ProcessorSpeed", $proc.MaxClockSpeed.ToString())
}

Get-ComputerSystemProductInfo
Get-ComputerSystemInfo
Get-Product
Get-BiosInfo
Get-OsInfo
Get-SystemEnclosureInfo
Get-NicConfigurationInfo
Get-MacInfo
Get-BatteryStatus
Get-Architecture
Get-Processor

if($Debug) {
    $TSvars.Keys | Sort-Object |% {
        Write-Host "$($_) = $($TSvars[$_])"
    }
}
else {
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $TSvars.Add("OSDComputerName", $tsenv.Value("_SMSTSMachineName"))

    $TSvars.Keys |% {
        $tsenv.Value($_) = $TSvars[$_]
    }
}