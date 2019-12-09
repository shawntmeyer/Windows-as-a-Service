<#
    .SYNOPSIS
        This script will run the appropriate venor-specific commands to save
        the BIOS settings from WMI to an INI file.

    .PARAMETER  File
        Name or path to the output file.

    .PARAMETER  Format
        File format for output file.  Valid choices are:
        CCTK - Output setting using the Dell Command | Configure tool (CCTK).
        CVS - Output settings CSV (comma separated value) file format.
        INI - Output settings INI file format.
        List - Output settings using Format-List on instances of the WMI
               firmware class.
        XML - Output settings XML file format.

    .EXAMPLE
        PS C:\> Export-BIOSSettings.ps1 -File BIOSSettings.ini

    .EXAMPLE
        PS C:\> Export-BIOSSettings.ps1 -File BIOSSettings.csv -Format CSV

    .INPUTS
       None.  This command does not accept pipeline input.

    .OUTPUTS
       None.  This command does not produce pipeline output.

    .NOTES
       Requires modules TSUtility.psm1 and IniFile.psm1 in the same folder.
       Dell Command | Monitor or Dell Command | Configure must be installed on
       Dell computers.
#>

#******************************************************************************
# File:     Export-BIOSSettings.ps1
# Version:  1.2.0
#
# Revisions:
# ----------
# 0.1.0   02/26/2016   Created script.  Only implemented Hewlett-Packard section.
# 0.2.0   02/26/2016   Added Dell and Lenovo sections.
# 1.0.0   03/03/2016   Revising version number to 1.0.0.
# 1.0.1   03/22/2016   Added changes to output file path for INI format when
#                      path is not a full path.
# 1.1.0   06/29/2016   Added CCTK to $Format to use the Dell Command | Configure
#                      tool to dump settings.
# 1.2.0   10/25/2016   Added Toshiba section.
#                      Added ValueParameterIndex and created ParameterSets for
#                      Export-BiosWMIClass and call for
#                      Convert-WMIClassPropertiesToIniFile. 
#******************************************************************************

param(
    [Parameter(Mandatory=$true)][string]$File,
    [Parameter(Mandatory=$False)][ValidateSet("INI","CCTK","CSV","List","XML")][string]$Format
)


# Set Script file path variables
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptExt = (Get-Item $ScriptPath).extension
$ScriptBaseName = $ScriptName -replace($ScriptExt ,"")
$ScriptFolder = Split-Path -parent $ScriptPath

# Import TSUtility module
import-module "$ScriptFolder\TSUtility.psm1" -force


function Export-BiosWMIClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $File,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Format,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $ComputerName = ".",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $NameSpace = "root/cimv2",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Class,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $KeyProperty = "Name",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true,ParameterSetName='ByValueName')][string] $ValueProperty = "",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true,ParameterSetName='ByValueIndex')][int] $ValuePropertyIndex = 1
    )


    $wmiClassExists = (Test-WMIClass -Class $BiosClass -NameSpace $BiosNamespace)
    if ($wmiClassExists -eq $true)
    {
        Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo
        
        switch ($Format) 
        { 
            "CCTK"
            {
                if ($MakeAlias -ne "Dell")
                {
                     Out-TSLogEntry -LogMsg "CCTK output only supported on Dell computers." -LogType LogTypeError
                    exit 1
                }

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
                    Out-TSLogEntry -LogMsg "Dumping BIOS settings using CCTK." -LogType LogTypeInfo
                    & $ExePath -o="$File"
                }
                else
                {
                    Out-TSLogEntry -LogMsg "$MakeAlias Command | Configure (CCTK) not found. Exiting script." -LogType LogTypeError
                    exit 1
                }
            }
            "CSV"
            {
                Get-WMIObject -NameSpace $BiosNamespace -Class $BiosClass | Export-Csv -Path $File -NoTypeInformation
            }
            "INI"
            {
                # A quirk of the Win32 Profile APIs causes INI writes to go to \Windows\System32 if a fully qualified path is not provided.
                # So if parent path to file is blank or ., then write to script filder.
                if ((Split-Path -parent $File) -eq "") { $File = "$ScriptFolder\$File" }
                if ((Split-Path -parent $File) -eq ".") { $File = $File -replace("^.",$ScriptFolder) }

                if (($ValueProperty -ne $null) -and ($ValueProperty -ne ""))
                {
                    Convert-WMIClassPropertiesToIniFile -File $File -Section $BiosClass -NameSpace $BiosNamespace -Class $BiosClass -KeyProperty $KeyProperty -ValueProperty $ValueProperty
                }
                else
                {
                    Convert-WMIClassPropertiesToIniFile -File $File -Section $BiosClass -NameSpace $BiosNamespace -Class $BiosClass -KeyProperty $KeyProperty -ValuePropertyIndex $ValuePropertyIndex
                }
            }
            "List"
            {
                Get-WMIObject -NameSpace $BiosNamespace -Class $BiosClass | Format-List | Out-File -FilePath $File
            }
            "XML"
            {
                Get-WMIObject -NameSpace $BiosNamespace -Class $BiosClass | Export-Clixml -Path $File
            }
        }
    }
    else
    {
        Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI class or namespace not found. Exiting script." -LogType LogTypeError
        exit 1
    }

}


# Run proper code based on manufacturer friendly name
switch ($MakeAlias) 
{ 
    "Dell"
    {
        $BiosNamespace = "ROOT\DCIM\SYSMAN"
        $BiosClass = "DCIM_BIOSEnumeration"
        $BiosNameProperty = "AttributeName"
        $BiosValueProperty = "CurrentValue"
    }
    "Lenovo"
    {
        $BiosNamespace = "root\wmi"
        $BiosClass = "Lenovo_BiosSetting"
        $BiosNameProperty = "CurrentSetting"
        $BiosValueProperty = ""
        $BiosValuePropertyIndex = 1
    }
    "Hewlett-Packard" 
    {
        $BiosNamespace = "root\HP\InstrumentedBIOS"
        $BiosClass = "HP_BIOSEnumeration"
        $BiosNameProperty = "Name"
        $BiosValueProperty = "CurrentValue"
    }
    "TOSHIBA" 
    {
        $BiosNamespace = "root\wmi"
        $BiosClass = "QueryBiosSettings"
        $BiosNameProperty = "CurrentSetting"
        $BiosValueProperty = ""
        $BiosValuePropertyIndex = 2
    }
    default 
    {
        Out-TSLogEntry -LogMsg "$MakeAlias computers not currently supported." -LogType LogTypeWarning
        exit 1
    }
}

if (($ValueProperty -ne $null) -and ($ValueProperty -ne ""))
{
    Export-BiosWMIClass -File $File -Format $Format -NameSpace $BiosNamespace -Class $BiosClass -KeyProperty $BiosNameProperty -ValueProperty $BiosValueProperty
}
else
{
    Export-BiosWMIClass -File $File -Format $Format -NameSpace $BiosNamespace -Class $BiosClass -KeyProperty $BiosNameProperty -ValuePropertyIndex $BiosValuePropertyIndex
}

