<#
    .SYNOPSIS
        This script will run the appropriate venor-specific WMI commands to set
        the BIOS password.

    .PARAMETER  CurrentPassword
        Current BIOS Admin password.

    .PARAMETER  NewPassword
        New BIOS Admin password to set.

    .EXAMPLE
        PS C:\> Set-BIOSPassword.ps1 -CurrentPassword "" -NewPassword "12345678"

    .EXAMPLE
        PS C:\> Set-BIOSPassword.ps1 -CurrentPassword "12345678" -NewPassword ""

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
# File:     Set-BIOSSettings.ps1
# Version:  1.1.0
#
# Revisions:
# ----------
# 1.0.0   2016-06-21   Created Script. 
# 1.1.0   2017-03-03   Added Toshiba section. 
#
#******************************************************************************

param(
    [Parameter(Mandatory=$false)] [string]$CurrentPassword = "",
    [Parameter(Mandatory=$false)] [string]$NewPassword = ""
)


# Set Script file path variables
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptExt = (Get-Item $ScriptPath).extension
$ScriptBaseName = $ScriptName -replace($ScriptExt ,"")
$ScriptFolder = Split-Path -parent $ScriptPath

# Import TSUtility module
import-module "$ScriptFolder\TSUtility.psm1" -force


#  Convert 8-bit ASCII string to EN-US keyboard scan code
function Convert-ToKbdString
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Input, Type string, String to be encoded with EN Keyboard Scan Code Hex Values.
        [Parameter(Mandatory=$true,
                   Position=0)]
        [string]
        $UTF16String
    )
    $kbdHexVals=New-Object System.Collections.Hashtable

    $kbdHexVals."a"="1E"
    $kbdHexVals."b"="30"
    $kbdHexVals."c"="2E"
    $kbdHexVals."d"="20"
    $kbdHexVals."e"="12"
    $kbdHexVals."f"="21"
    $kbdHexVals."g"="22"
    $kbdHexVals."h"="23"
    $kbdHexVals."i"="17"
    $kbdHexVals."j"="24"
    $kbdHexVals."k"="25"
    $kbdHexVals."l"="26"
    $kbdHexVals."m"="32"
    $kbdHexVals."n"="31"
    $kbdHexVals."o"="18"
    $kbdHexVals."p"="19"
    $kbdHexVals."q"="10"
    $kbdHexVals."r"="13"
    $kbdHexVals."s"="1F"
    $kbdHexVals."t"="14"
    $kbdHexVals."u"="16"
    $kbdHexVals."v"="2F"
    $kbdHexVals."w"="11"
    $kbdHexVals."x"="2D"
    $kbdHexVals."y"="15"
    $kbdHexVals."z"="2C"
    $kbdHexVals."A"="9E"
    $kbdHexVals."B"="B0"
    $kbdHexVals."C"="AE"
    $kbdHexVals."D"="A0"
    $kbdHexVals."E"="92"
    $kbdHexVals."F"="A1"
    $kbdHexVals."G"="A2"
    $kbdHexVals."H"="A3"
    $kbdHexVals."I"="97"
    $kbdHexVals."J"="A4"
    $kbdHexVals."K"="A5"
    $kbdHexVals."L"="A6"
    $kbdHexVals."M"="B2"
    $kbdHexVals."N"="B1"
    $kbdHexVals."O"="98"
    $kbdHexVals."P"="99"
    $kbdHexVals."Q"="90"
    $kbdHexVals."R"="93"
    $kbdHexVals."S"="9F"
    $kbdHexVals."T"="94"
    $kbdHexVals."U"="96"
    $kbdHexVals."V"="AF"
    $kbdHexVals."W"="91"
    $kbdHexVals."X"="AD"
    $kbdHexVals."Y"="95"
    $kbdHexVals."Z"="AC"
    $kbdHexVals."1"="02"
    $kbdHexVals."2"="03"
    $kbdHexVals."3"="04"
    $kbdHexVals."4"="05"
    $kbdHexVals."5"="06"
    $kbdHexVals."6"="07"
    $kbdHexVals."7"="08"
    $kbdHexVals."8"="09"
    $kbdHexVals."9"="0A"
    $kbdHexVals."0"="0B"
    $kbdHexVals."!"="82"
    $kbdHexVals."@"="83"
    $kbdHexVals."#"="84"
    $kbdHexVals."$"="85"
    $kbdHexVals."%"="86"
    $kbdHexVals."^"="87"
    $kbdHexVals."&"="88"
    $kbdHexVals."*"="89"
    $kbdHexVals."("="8A"
    $kbdHexVals.")"="8B"
    $kbdHexVals."-"="0C"
    $kbdHexVals."_"="8C"
    $kbdHexVals."="="0D"
    $kbdHexVals."+"="8D"
    $kbdHexVals."["="1A"
    $kbdHexVals."{"="9A"
    $kbdHexVals."]"="1B"
    $kbdHexVals."}"="9B"
    $kbdHexVals.";"="27"
    $kbdHexVals.":"="A7"
    $kbdHexVals."'"="28"
    $kbdHexVals."`""="A8"
    $kbdHexVals."``"="29"
    $kbdHexVals."~"="A9"
    $kbdHexVals."\"="2B"
    $kbdHexVals."|"="AB"
    $kbdHexVals.","="33"
    $kbdHexVals."<"="B3"
    $kbdHexVals."."="34"
    $kbdHexVals.">"="B4"
    $kbdHexVals."/"="35"
    $kbdHexVals."?"="B5"

    $kbdEncodedString=""
    foreach ($char in $UTF16String.ToCharArray())
    {
        $kbdEncodedString+=$kbdHexVals.Get_Item($char.ToString())
    }
    return $kbdEncodedString
}

# Define files to log all settings to before and after changes
$logBeforeSettings = "$($TSLogPath)\$($MakeAlias)_BIOS_PASSWORD_BEFORE.log"
$logAfterSettings = "$($TSLogPath)\$($MakeAlias)_BIOS_PASSWORD_AFTER.log"

# Initialize $FirmwareUpdated variable to false
$FirmwareUpdated = $false

# Run proper code based on manufacturer friendly name
switch ($MakeAlias) 
{ 
    "Dell"
    {
        $wmiClassExists = (Test-WMIClass -Class "DCIM_BIOSService" -NameSpace 'ROOT\DCIM\SYSMAN')
        if ($wmiClassExists -eq $true)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo


            #If ((Get-CimInstance -Namespace 'ROOT\DCIM\SYSMAN' -Class 'DCIM_BIOSPassword' | Where-Object {$_.AttributeName -eq 'AdminPwd'}).IsSet)
            If ((Get-WmiObject -Namespace "ROOT\DCIM\SYSMAN" -Class "DCIM_BIOSPassword" | Where-Object {$_.AttributeName -eq 'AdminPwd'}).IsSet)
            {
                Out-TSLogEntry -LogMsg "BIOS password is set." -LogType LogTypeInfo
                $IsPasswordSet = $true
            }
            Else
            {
                Out-TSLogEntry -LogMsg "BIOS password is not set." -LogType LogTypeInfo
                $IsPasswordSet = $false
            }

            
            Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "DCIM_BIOSEnumeration" -NameSpace "ROOT\DCIM\SYSMAN" -Class "DCIM_BIOSEnumeration" -KeyProperty "AttributeName" -ValueProperty "CurrentValue"


            Out-TSLogEntry -LogMsg "Changing BIOS password to desired value." -LogType LogTypeInfo
            $FirmwareUpdated = $true

            
            If ($IsPasswordSet -eq $true)
            {
                $CurrentPasswordString = "$($CurrentPassword)"
            }
            Else
            {
                $CurrentPasswordString = ""
            }

            try
            {
                #  The 9030 shipped with strong password enabled, which is possibly not compatible with some new passwords
                (Get-WmiObject -Namespace 'root\dcim\sysman' -Class 'DCIM_BIOSService').SetBIOSAttributes($null, $null, 'Strong Password', '1', $CurrentPasswordString) | Out-Null
                $WmiResult = (Get-WmiObject -Namespace "ROOT\DCIM\SYSMAN" -Class "DCIM_BIOSService").SetBIOSAttributes($null, $null, 'AdminPwd', $NewPassword, $CurrentPasswordString, $null)
                If ($WmiResult.ReturnValue -eq 'Success' -or $WmiResult.ReturnValue -eq 0)
                {
                     Out-TSLogEntry -LogMsg "WMI method call successfull." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "WMI method returned on non-zero return value.  RC = $($WmiResult.ReturnValue)" -LogType LogTypeError
                    $Failure = $true
                }
            }
            catch
            {
                Out-TSLogEntry -LogMsg "Exception occured.  Error = $($_)" -LogType LogTypeError
                $Failure = $true
            }


            if ($FirmwareUpdated) { 
                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logAfterSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValueProperty ""
            }

        }
        else
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
                Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
                & $ExePath -o="$logBeforeSettings"

                If (($CurrentPassword -eq "") -or ($CurrentPassword -eq $null))
                {
                    $CurrentPasswordString = ""
                }
                Else
                {
                    $CurrentPasswordString = "--valsetuppwd=$($CurrentPassword)"
                }

                Out-TSLogEntry -LogMsg "Setting BIOS Password" -LogType LogTypeInfo

                $cctk_LOG_FILE = "$($TSLogPath)\$($MakeAlias)_BIOS_PASSWORD_CHANGES.log"
                & $($ExePath) --setuppwd=$($NewPassword) $($CurrentPasswordString) --logfile="$($cctk_LOG_FILE)"

                If ($LASTEXITCODE -eq 0)
                {
                        Out-TSLogEntry -LogMsg "CCTK changes successfull." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "CCTK returned on non-zero return value.  RC = $($LASTEXITCODE)" -LogType LogTypeError
                    $Failure = $true
                }

                Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
                & $ExePath -o="$logAfterSettings"

            }
            else
            {
                Out-TSLogEntry -LogMsg "$MakeAlias Command | Configure (CCTK) not found. Exiting script." -LogType LogTypeError
                exit 1
            }
        }
    }
    "Lenovo"
    {
        #
        $wmiClassExists = (Test-WMIClass -Class "Lenovo_BiosPasswordSettings" -NameSpace 'root\wmi')
        
        if ($wmiClassExists -eq $true)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo


            #  PasswordState '2' is set, and '0' is not set, apparently
            If ((Get-WmiObject -Namespace 'ROOT\wmi' -Class 'Lenovo_BiosPasswordSettings').PasswordState -eq 2)
            {
                Out-TSLogEntry -LogMsg "BIOS password is set." -LogType LogTypeInfo
                $IsPasswordSet = $true
            }
            Else
            {
                Out-TSLogEntry -LogMsg "BIOS password is not set." -LogType LogTypeInfo
                $IsPasswordSet = $false
            }

            
            Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValueProperty ""

            Out-TSLogEntry -LogMsg "Changing BIOS Password to desired value." -LogType LogTypeInfo
            $FirmwareUpdated = $true

            
            try
            {
                #  Set the password to something "temporary" because you can't set it back if it's entirely removed.
                #  Three wrong passwords in a row will return all 'access denied' for future attempts, and will cause the BIOS to require entering a password on next boot
                $WmiResult = (Get-WmiObject -Namespace 'ROOT\wmi' -Class 'Lenovo_SetBiosPassword').SetBiosPassword("pap,$($CurrentPassword),$($NewPassword),ascii,us;")
                #  Results are 'Success', 'Not Supported', 'Invalid Parameter', 'Access Denied', and 'System Busy'
                If ($WmiResult.Return -eq 'Success')
                {
                     Out-TSLogEntry -LogMsg "WMI method call successfull." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "WMI method returned on non-zero return value.  RC = $($WmiResult.Return)" -LogType LogTypeError
                    $Failure = $true
                }
            }
            catch
            {
                Out-TSLogEntry -LogMsg "Exception occured.  Error = $($_)" -LogType LogTypeError
                $Failure = $true
            }


            if ($FirmwareUpdated) { 
                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logAfterSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValueProperty ""
            }

        }
        else
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI class or namespace not found. Exiting script." -LogType LogTypeError
            exit 1
        }
    }
    "Hewlett-Packard" 
    {
        #
        $wmiClassExists = (Test-WMIClass -Class "HP_BIOSSettingInterface" -NameSpace 'root\HP\InstrumentedBIOS')
        if ($wmiClassExists -eq $true)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo


            #  See if need to use the UTF-16 encoding style
            [Bool]$kbd = $true
            If (((Get-WmiObject -Namespace 'ROOT\HP\InstrumentedBIOS' -Class 'HP_BIOSSetting') | Where-Object -FilterScript {$_.Name -eq 'Setup Password'}).SupportedEncoding[0] -eq 'utf-16')
            {
                $kbd = $false
            }

            #  IsSet '1' is set, and '0' is not set, apparently
            If ((Get-WmiObject -Namespace 'root\HP\InstrumentedBIOS' -Class 'HP_BIOSSetting' -Filter "Name = 'Setup Password'").IsSet -eq 1)
            {
                Out-TSLogEntry -LogMsg "BIOS password is set." -LogType LogTypeInfo
                $IsPasswordSet = $true
            }
            Else
            {
                Out-TSLogEntry -LogMsg "BIOS password is not set." -LogType LogTypeInfo
                $IsPasswordSet = $false
            }

            
            Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "HP_BIOSEnumeration" -NameSpace "root\HP\InstrumentedBIOS" -Class "HP_BIOSEnumeration" -KeyProperty "Name" -ValueProperty "CurrentValue"


            Out-TSLogEntry -LogMsg "Changing BIOS Setting to desired value." -LogType LogTypeInfo
            $FirmwareUpdated = $true
            
            If ($IsPasswordSet -eq $false) { $CurrentPassword = "" }

            If ($kbd)
            {
                $CurrentPasswordString = "<kbd/>$(Convert-ToKbdString $CurrentPassword)"
                $NewPasswordString = "<kbd/>$(Convert-ToKbdString $NewPassword)"
            }
            Else
            {
                $CurrentPasswordString = "<utf-16/>$($CurrentPassword)"
                $NewPasswordString = "<utf-16/>$($NewPassword)"
            }

            try
            {
                $WmiResult = (Get-WmiObject -Namespace 'ROOT\HP\InstrumentedBIOS' -Class 'HP_BIOSSettingInterface').SetBIOSSetting('Setup Password', $NewPasswordString, $CurrentPasswordString)
                If ($WmiResult.Return -eq '0')
                {
                     Out-TSLogEntry -LogMsg "WMI method call successfull." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "WMI method returned on non-zero return value.  RC = $($WmiResult.Return)" -LogType LogTypeError
                    $Failure = $true
                }
            }
            catch
            {
                Out-TSLogEntry -LogMsg "Exception occured.  Error = $($_)" -LogType LogTypeError
                $Failure = $true
            }


            if ($FirmwareUpdated) { 
                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logAfterSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValueProperty ""
            }

        }
        else
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI class or namespace not found. Exiting script." -LogType LogTypeError
            exit 1
        }
    }
    "TOSHIBA"
    {
        #
        $wmiClassExists = (Test-WMIClass -Class "Password" -NameSpace 'root\wmi')
        
        if ($wmiClassExists -eq $true)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo


            If ((Get-WmiObject -Namespace 'ROOT\wmi' -Class 'QueryPasswordStatus' | Where-Object { $_.PasswordStatus -match "^SupervisorPassword," }).PasswordStatus -eq 'SupervisorPassword,NotRegistered')
            {
                Out-TSLogEntry -LogMsg "BIOS password is not set." -LogType LogTypeInfo
                Out-TSLogEntry -LogMsg "Unable to change BIOS password via WMI when BIOS Supervisor password is blank. Exiting script." -LogType LogTypeError
                $IsPasswordSet = $false
                exit 1
            }
            Else
            {
                Out-TSLogEntry -LogMsg "BIOS password is set." -LogType LogTypeInfo
                $IsPasswordSet = $true
            }

            
            If ($IsPasswordSet -eq $true)
            {
                Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "QueryBiosSettings" -NameSpace "root\wmi" -Class "QueryBiosSettings" -KeyProperty "CurrentSetting" -ValuePropertyIndex 2

                Out-TSLogEntry -LogMsg "Changing BIOS Password to desired value." -LogType LogTypeInfo


                $mode = Get-WmiObject –namespace "root\wmi" -class "ModeControl" | where {$_.InstanceName -match "ACPI\\pnp0c14\\0.0"} 
                $result = $mode.SetConfigurationMode("Start,$CurrentPassword;").Return 

                if ($result -eq 0)
                {
                    Out-TSLogEntry "Successful Authenticated" -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry "Authentication  failed, Error Code= "$result  -LogType LogTypeError
                    continue
                } 

                $FirmwareUpdated = $true

                try
                {
                    $WmiResult = (Get-WmiObject -Namespace 'root\wmi' -Class 'Password' | where {$_.InstanceName -match “ACPI\\pnp0c14\\0.0"}).SetPassword("SupervisorPassword,$CurrentPassword,$NewPassword;").Return
                    If ($WmiResult -eq 0)
                    {
                         Out-TSLogEntry -LogMsg "WMI method call successfull." -LogType LogTypeInfo
                    }
                    else
                    {
                        Out-TSLogEntry -LogMsg "WMI method returned on non-zero return value.  RC = $($WmiResult.Return)" -LogType LogTypeError
                        $Failure = $true
                    }
                }
                catch
                {
                    Out-TSLogEntry -LogMsg "Exception occured.  Error = $($_)" -LogType LogTypeError
                    $Failure = $true
                }


                $result = $mode.SetConfigurationMode("End,$NewPassword;").Return 

                if ($result -eq 0)
                {
                    Out-TSLogEntry "Successful Deauthenticated" -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry "Deauthenticated  failed, Error Code= "$result  -LogType LogTypeError
                } 

                if ($FirmwareUpdated) { 
                    Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                    Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "QueryBiosSettings" -NameSpace "root\wmi" -Class "QueryBiosSettings" -KeyProperty "CurrentSetting" -ValuePropertyIndex 2
                }

            }

        }
        else
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI class or namespace not found. Exiting script." -LogType LogTypeError
            exit 1
        }
    }
    default 
    {
        Out-TSLogEntry -LogMsg "$MakeAlias computers not currently supported." -LogType LogTypeWarning
        exit 1
    }
}


if ($FirmwareUpdated) { $TSEnv.Value("FirmwareSettingsUpdated") = "True" }


If ($Failure)
{
    Out-TSLogEntry -LogMsg "One or more operations failed." -LogType LogTypeError
    Exit 113
}
Else
{
    Out-TSLogEntry -LogMsg "Script completed successfully." -LogType LogTypeInfo
    Exit 0
}


