<#
    .SYNOPSIS
        This script will repeatedly test for the vendor WMI class for BIOS
        settings until the timeout limit is reached.

    .PARAMETER  Timeout
        (Optional) Timeout before exiting with failure.  Default is 60 seconds.

    .EXAMPLE
        PS C:\> Test-BIOSWmiClass.ps1 -Timeout 30

    .INPUTS
       None.  This command does not accept pipeline input.

    .OUTPUTS
       None.  This command does not produce pipeline output.

    .NOTES
       Requires module TSUtility.psm1 and IniFile.psm1 in the same folder.  Dell
       Command | Monitor or Dell Command | Configure must be installed on Dell
       computers.
#>

#******************************************************************************
# File:     Test-BIOSWmiClass.ps1
# Version:  1.1.0
#
# Revisions:
# ----------
# 1.0.0   03/03/2016   Created script. 
# 1.1.0   03/03/2016   Added Toshiba section. 
#
#******************************************************************************

param(
    [Parameter(Mandatory=$False)][alias("Password")] [int]$Timeout = 60
)


# Set Script file path variables
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptExt = (Get-Item $ScriptPath).extension
$ScriptBaseName = $ScriptName -replace($ScriptExt ,"")
$ScriptFolder = Split-Path -parent $ScriptPath






# Import TSUtility module
import-module "$ScriptFolder\TSUtility.psm1" -force

# Start WMI if neccessary
Out-TSLogEntry -LogMsg "Starting winmgmt service if needed." -LogType LogTypeInfo
$StartTime = (Get-Date)

if ((Get-Service -Name winmgmt).Status -ne 'Running')
{
    Start-Service -Name winmgmt

    $StartTime = (Get-Date)
    Do {
        $CurrentTime = (Get-Date)
        $timespan = [int]((New-Timespan –Start $StartTime –End $CurrentTime).TotalSeconds)
        Out-TSLogEntry -LogMsg "Elapsed time (seconds): $timespan." -LogType LogTypeInfo
        If ($timespan -gt $Timeout)
        {
            Out-TSLogEntry -LogMsg "Unable to start winmgmt service." -LogType LogTypeError
            exit 113
        }
        Start-Sleep -Seconds 5
    } Until ((Get-Service -Name winmgmt).Status -eq 'Running') 
}

Out-TSLogEntry -LogMsg "Winmgmt service running." -LogType LogTypeInfo


# Query a WMI class instance
Out-TSLogEntry -LogMsg "Querying for Win32_ComputerSystem class." -LogType LogTypeInfo
$wmiComputerSystem = Get-WmiObject -Namespace "root\cimv2" -Class "Win32_ComputerSystem"
Out-TSLogEntry -LogMsg "Win32_ComputerSystem class Name property: $($wmiComputerSystem.Name)." -LogType LogTypeInfo


$Failure = $false
$wmiClassExists = $false
Out-TSLogEntry -LogMsg "Querying for $MakeAlias BIOS WMI namespace/class." -LogType LogTypeInfo

# Run proper code based on manufacturer friendly name
switch ($MakeAlias) 
{ 
    "Dell"
    {
        $waitWMIClass = Wait-WMIClass -Class "DCIM_BIOSService" -NameSpace 'ROOT\DCIM\SYSMAN'
        if ($waitWMIClass -eq $false)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI class or namespace not found. Trying $MakeAlias Command | Configure (CCTK)." -LogType LogTypeWarning

            if ($env:SystemDrive -eq 'X:')
            {
                $ExePath = "X:\CommandConfigure\cctk.exe"
            }
            elseif ($env:PROCESSOR_ARCHITECTURE -eq 'x86')
            {
                $ExePath = "$($env:ProgramFiles)\Dell\Command Configure\X86\cctk.exe"
            }
            else
            {
                $ExePath = "$(${env:ProgramFiles(x86)})\Dell\Command Configure\X86_64\cctk.exe"
            }

            If (Test-Path -Path $ExePath -PathType Leaf)
            {
                Out-TSLogEntry -LogMsg "$MakeAlias Command | Configure (CCTK) found." -LogType LogTypeInfo
            }
            else
            {
                Out-TSLogEntry -LogMsg "$MakeAlias Command | Configure (CCTK) not found. Exiting script." -LogType LogTypeError
                $Failure = $true
            }
        }
    }
    "Lenovo"
    {
        $waitWMIClass = Wait-WMIClass -Class "Lenovo_SetBiosSetting" -NameSpace 'root\wmi'
        if ($waitWMIClass -eq $false)
        {
            $Failure = $true
        }
    }
    "Hewlett-Packard" 
    {
        $waitWMIClass = Wait-WMIClass -Class "HP_BIOSSettingInterface" -NameSpace 'root\HP\InstrumentedBIOS'
        if ($waitWMIClass -eq $false)
        {
            $Failure = $true
        }
    }
    "TOSHIBA" 
    {
        $waitWMIClass = Wait-WMIClass -Class "ToshibaBiosElement" -NameSpace 'root\wmi'
        if ($waitWMIClass -eq $false)
        {
            $Failure = $true
        }
    }
    default 
    {
        Out-TSLogEntry -LogMsg "$MakeAlias computers not currently supported." -LogType LogTypeWarning
        exit 1
    }
}


If ($Failure)
{
    Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class or BIOS Utility not found." -LogType LogTypeError
    Out-TSLogEntry -LogMsg "Failure timout reached." -LogType LogTypeError
    Exit 113
}
Else
{
    Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class or BIOS Utility found." -LogType LogTypeInfo
    Out-TSLogEntry -LogMsg "Script completed successfully." -LogType LogTypeInfo
    Exit 0
}


