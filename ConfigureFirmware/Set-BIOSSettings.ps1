<#
    .SYNOPSIS
        This script will run the appropriate venor-specific WMI commands to set
        the required BIOS settings.

    .PARAMETER  BiosPassword
        (Optional) Current BIOS Admin password.  Default is blank.

    .EXAMPLE
        PS C:\> Set-BIOSSettings.ps1

    .INPUTS
       None.  This command does not accept pipeline input.

    .OUTPUTS
       None.  This command does not produce pipeline output.

    .NOTES
       Requires module TSUtility.psm1 in the same folder.  Dell Command | Monitor
       or Dell Command | Configure must be installed on Dell computers.
#>

#******************************************************************************
# File:     Set-BIOSSettings.ps1
# Version:  1.2.4
#
# Revisions:
# ----------
# 0.1.0   02/26/2016   Created script.  Only implemented and tested Hewlett-Packard 
#                                       section.
# 0.2.0   03/01/2016   Adding Dell functionality. 
# 0.2.1   03/01/2016   Added Try/Catch block around WMI setting calls to log 
#                      excepetions. 
# 1.0.0   03/03/2016   Adding Lenovo functionality. 
# 1.0.1   03/15/2016   Added SaveBiosSettings call to Lenovo section.  Changed when
#                      $TSEnv.Value("FirmwareUpdated") gets set.  Changed how WMI
#                      parameter strings are concatinated in Lenovo section.
# 1.1.0   03/16/2016   Adding fallback to Dell Command | Configure for Dell machine
#                      (necessary in WinPE). 
# 1.2.0   03/17/2016   Changed INI files calls to use cmdlets from IniFile.psm1.
# 1.2.1   03/22/2016   Changed FirmwareUpdated TS variable to FirmwareSettingsUpdated.
# 1.2.2   03/29/2016   Removed check for $makeINIFile near beginning.  Added logic
#                      to set $BiosPasswordString in Dell CCTK section.  Put quotes
#                      around file paths in -o commands in Dell CCTK section.
# 1.2.3   05/24/2016   Changed default vaule of $BiosPassword to "".
# 1.2.4   10/25/2016   Added Toshiba section.
#                      Added ValueParameterIndex to calls for
#                      Convert-WMIClassPropertiesToIniFile in Lenovo section. 
#
#******************************************************************************

param(
    # BIOS Password
    [Parameter(Mandatory=$False)]
    [alias("Password")]
    [string]$BiosPassword = "",
    # Convert to UEFI from BIOS
    [switch]$Convert
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

# Define the INI settings files to run based on manufacturer and model friendly names
If ($Convert)
{
    $makeINIFile = "$ScriptFolder\$MakeAlias-Convert.ini"
    $modelINIFile = "$ScriptFolder\$ModelAlias-Convert.ini"
}
Else
{
    $makeINIFile = "$ScriptFolder\$MakeAlias.ini"
    $modelINIFile = "$ScriptFolder\$ModelAlias.ini"
}

$arrINIFiles = $makeINIFile, $modelINIFile

# Define files to log all settings to before and after changes
$logBeforeSettings = "$($TSLogPath)\$($MakeAlias)_BIOS_SETTINGS_BEFORE.log"
$logAfterSettings = "$($TSLogPath)\$($MakeAlias)_BIOS_SETTINGS_AFTER.log"

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


            foreach ($iniFile in $arrINIFiles)
            {

                If ((Test-Path $iniFile) -eq $true)
                {
                    Out-TSLogEntry -LogMsg "Found settings file $iniFile." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "$iniFile not found." -LogType LogTypeWarning
                    Continue
                }
            
                $sections = (Get-IniSectionNames -File $iniFile)
                foreach ($section in $sections)
                {
                    Out-TSLogEntry -LogMsg "Found INI file section: $section" -LogType LogTypeInfo

                    $keys = (Get-IniSectionKeys -File $iniFile -Section $section)
                    foreach ($key in $keys)
                    {
                        Out-TSLogEntry -LogMsg "BIOS Setting name: $key" -LogType LogTypeInfo
                        $value = (Get-IniValue -File $iniFile -Section $section -Key $key)
                        Out-TSLogEntry -LogMsg "BIOS Setting desired value: $value" -LogType LogTypeInfo

                        $setting = (Get-WmiObject -Namespace 'ROOT\DCIM\SYSMAN' -Class 'DCIM_BIOSEnumeration' | Where-Object { $_.AttributeName -eq $key })
                        If ($setting -eq $null)
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting name `"$key`" not found in WMI" -LogType LogTypeWarning
                        }
                        else
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting current value: $($setting.CurrentValue)" -LogType LogTypeInfo
                            if ($setting.CurrentValue -eq $value)
                            {
                                Out-TSLogEntry -LogMsg "BIOS Setting current value already at desired value." -LogType LogTypeInfo
                            }
                            else
                            {
                                Out-TSLogEntry -LogMsg "Changing BIOS Setting to desired value." -LogType LogTypeInfo
                                $FirmwareUpdated = $true

                                
                                If ($IsPasswordSet -eq $true)
                                {
                                    $BiosPasswordString = "$($BiosPassword)"
                                }
                                Else
                                {
                                    $BiosPasswordString = ""
                                }
                                # write-host "$key, $value, $BiosPasswordString"
                                try
                                {
                                    $WmiResult = (Get-WmiObject -Namespace 'ROOT\DCIM\SYSMAN' -Class 'DCIM_BIOSService').SetBIOSAttributes($null, $null, $key, $value, $BiosPasswordString)
                                    If ($WmiResult.ReturnValue -eq '0')
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
                            }
                        }
                    }
                }
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
                # Define the CCTK settings files to run
                $makeCCTKFile = "$ScriptFolder\$MakeAlias.cctk"
                $modelCCTKFile = "$ScriptFolder\$ModelAlias.cctk"
                $arrCCTKFiles = $makeCCTKFile, $modelCCTKFile

                Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
                & $ExePath -o="$logBeforeSettings"

                If (($BiosPassword -eq "") -or ($BiosPassword -eq $null))
                {
                    $BiosPasswordString = ""
                }
                Else
                {
                    $BiosPasswordString = "--valsetuppwd=$($BiosPassword)"
                }

                foreach ($cctkFile in $arrCCTKFiles)
                {

                    If ((Test-Path -Path $cctkFile -PathType Leaf) -eq $true)
                    {
                        Out-TSLogEntry -LogMsg "Found settings file $cctkFile." -LogType LogTypeInfo

                        $cctk_LOG_FILE = "$($TSLogPath)\$($MakeAlias)_BIOS_SETTINGS_CHANGES.log"
                        & $($ExePath) --infile "$($cctkFile)" $($BiosPasswordString) --logfile="$($cctk_LOG_FILE)"

                        If ($LASTEXITCODE -eq 0)
                        {
                                Out-TSLogEntry -LogMsg "CCTK changes successfull." -LogType LogTypeInfo
                        }
                        else
                        {
                            Out-TSLogEntry -LogMsg "CCTK returned on non-zero return value.  RC = $($LASTEXITCODE)" -LogType LogTypeError
                            $Failure = $true
                        }
                    }
                    else
                    {
                        Out-TSLogEntry -LogMsg "$cctkFile not found." -LogType LogTypeWarning
                        Continue
                    }

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
        $wmiClassExists = (Test-WMIClass -Class "Lenovo_SetBiosSetting" -NameSpace 'root\wmi')
        
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
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValuePropertyIndex 1


            foreach ($iniFile in $arrINIFiles)
            {

                If ((Test-Path $iniFile) -eq $true)
                {
                    Out-TSLogEntry -LogMsg "Found settings file $iniFile." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "$iniFile not found." -LogType LogTypeWarning
                    Continue
                }
            
                $sections = (Get-IniSectionNames -File $iniFile)
                foreach ($section in $sections)
                {
                    Out-TSLogEntry -LogMsg "Found INI file section: $section" -LogType LogTypeInfo

                    $keys = (Get-IniSectionKeys -File $iniFile -Section $section)
                    foreach ($key in $keys)
                    {
                        Out-TSLogEntry -LogMsg "BIOS Setting name: $key" -LogType LogTypeInfo
                        $value = (Get-IniValue -File $iniFile -Section $section -Key $key)
                        Out-TSLogEntry -LogMsg "BIOS Setting desired value: $value" -LogType LogTypeInfo

                        $setting = (Get-WmiObject -Namespace 'root\wmi' -Class 'Lenovo_BiosSetting' | Where-Object { $_.CurrentSetting -match "^$($key)," })
                        If ($setting -eq $null)
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting name `"$key`" not found in WMI" -LogType LogTypeWarning
                        }
                        else
                        {
                            $settingString = $setting.CurrentSetting
                            $arrSetting = ($settingString).split(",")
                            
                            Out-TSLogEntry -LogMsg "BIOS Setting current value: $($arrSetting[1])" -LogType LogTypeInfo
                            if ("$($arrSetting[1])" -eq $value)
                            {
                                Out-TSLogEntry -LogMsg "BIOS Setting current value already at desired value." -LogType LogTypeInfo
                            }
                            else
                            {
                                Out-TSLogEntry -LogMsg "Changing BIOS Setting to desired value." -LogType LogTypeInfo
                                $FirmwareUpdated = $true

                                
                                If ($IsPasswordSet -eq $true)
                                {
                                    $BiosPasswordString = "$($BiosPassword),ascii,us;"
                                    $BiosParameterString = "$($key),$($value),$($BiosPasswordString)"
                                }
                                Else
                                {
                                    $BiosPasswordString = ";"
                                    $BiosParameterString = "$($key),$($value);"
                                }
                                # write-host "$($BiosParameterString)"
                                try
                                {
                                    $WmiResult = (Get-WmiObject -Namespace 'root\wmi' -Class 'Lenovo_SetBiosSetting').SetBiosSetting("$($BiosParameterString)")
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
                            }
                        }
                    }
                }
            }

            if ($FirmwareUpdated) { 
                # Save of settings required on Lenovo machines
                try
                {
                    # write-host "$($BiosPasswordString)"
                    $WmiResult = (Get-WmiObject -Namespace 'root\wmi' -Class 'Lenovo_SaveBiosSettings').SaveBiosSettings("$($BiosPasswordString)")
                    #  Results are 'Success', 'Not Supported', 'Invalid Parameter', 'Access Denied', and 'System Busy'
                    If ($WmiResult.Return -eq 'Success')
                    {
                         Out-TSLogEntry -LogMsg "WMI SaveBiosSettings method call successfull." -LogType LogTypeInfo
                    }
                    else
                    {
                        Out-TSLogEntry -LogMsg "WMI SaveBiosSettings method returned on non-zero return value.  RC = $($WmiResult.Return)" -LogType LogTypeError
                        $Failure = $true
                    }
                }
                catch
                {
                    Out-TSLogEntry -LogMsg "Exception occured.  Error = $($_)" -LogType LogTypeError
                    $Failure = $true
                }

                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logAfterSettings -Section "Lenovo_BiosSetting" -NameSpace "root\wmi" -Class "Lenovo_BiosSetting" -KeyProperty "CurrentSetting" -ValuePropertyIndex 1
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


            foreach ($iniFile in $arrINIFiles)
            {

                If ((Test-Path $iniFile) -eq $true)
                {
                    Out-TSLogEntry -LogMsg "Found settings file $iniFile." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "$iniFile not found." -LogType LogTypeWarning
                    Continue
                }
            
                $sections = (Get-IniSectionNames -File $iniFile)
                foreach ($section in $sections)
                {
                    Out-TSLogEntry -LogMsg "Found INI file section: $section" -LogType LogTypeInfo

                    $keys = (Get-IniSectionKeys -File $iniFile -Section $section)
                    foreach ($key in $keys)
                    {
                        Out-TSLogEntry -LogMsg "BIOS Setting name: $key" -LogType LogTypeInfo
                        $value = (Get-IniValue -File $iniFile -Section $section -Key $key)
                        Out-TSLogEntry -LogMsg "BIOS Setting desired value: $value" -LogType LogTypeInfo

                        $setting = (Get-WmiObject -Namespace 'ROOT\HP\InstrumentedBIOS' -Class 'HP_BIOSSetting' | Where-Object { $_.Name -eq $key })
                        If ($setting -eq $null)
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting name `"$key`" not found in WMI" -LogType LogTypeWarning
                        }
                        else
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting current value: $($setting.CurrentValue)" -LogType LogTypeInfo
                            if ($setting.CurrentValue -eq $value)
                            {
                                Out-TSLogEntry -LogMsg "BIOS Setting current value already at desired value." -LogType LogTypeInfo
                            }
                            else
                            {
                                Out-TSLogEntry -LogMsg "Changing BIOS Setting to desired value." -LogType LogTypeInfo
                                $FirmwareUpdated = $true
                                
                                If ($IsPasswordSet -eq $true)
                                {
                                    If ($kbd)
                                    {
                                        $BiosPasswordString = "<kbd/>$(Convert-ToKbdString $BiosPassword)"
                                    }
                                    Else
                                    {
                                        $BiosPasswordString = "<utf-16/>$($BiosPassword)"
                                    }
                                }
                                Else
                                {
                                    If ($kbd)
                                    {
                                        $BiosPasswordString = "<kbd/>"
                                    }
                                    Else
                                    {
                                        $BiosPasswordString = "<utf-16/>"
                                    }
                                }
                                #write-host "$key, $value, $BiosPasswordString"
                                try
                                {
                                    $WmiResult = (Get-WmiObject -Namespace 'ROOT\HP\InstrumentedBIOS' -Class 'HP_BIOSSettingInterface').SetBIOSSetting($key, $value, $BiosPasswordString)
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
                            }
                        }
                    }
                }
            }

            if ($FirmwareUpdated) { 
                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "HP_BIOSEnumeration" -NameSpace "root\HP\InstrumentedBIOS" -Class "HP_BIOSEnumeration" -KeyProperty "Name" -ValueProperty "CurrentValue"
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
        $wmiClassExists = (Test-WMIClass -Class "ToshibaBiosElement" -NameSpace 'root\wmi')
        
        if ($wmiClassExists -eq $true)
        {
            Out-TSLogEntry -LogMsg "$MakeAlias BIOS WMI namespace/class found." -LogType LogTypeInfo


            If ((Get-WmiObject -Namespace 'ROOT\wmi' -Class 'QueryPasswordStatus' | Where-Object { $_.PasswordStatus -match "^SupervisorPassword," }).PasswordStatus -eq 'SupervisorPassword,NotRegistered')
            {
                Out-TSLogEntry -LogMsg "BIOS password is not set." -LogType LogTypeInfo
                $IsPasswordSet = $false
            }
            Else
            {
                Out-TSLogEntry -LogMsg "BIOS password is set." -LogType LogTypeInfo
                $IsPasswordSet = $true
            }

            
            Out-TSLogEntry -LogMsg "Dumping BIOS settings before attemping changes." -LogType LogTypeInfo
            Convert-WMIClassPropertiesToIniFile -File $logBeforeSettings -Section "QueryBiosSettings" -NameSpace "root\wmi" -Class "QueryBiosSettings" -KeyProperty "CurrentSetting" -ValuePropertyIndex 2


            foreach ($iniFile in $arrINIFiles)
            {

                If ((Test-Path $iniFile) -eq $true)
                {
                    Out-TSLogEntry -LogMsg "Found settings file $iniFile." -LogType LogTypeInfo
                }
                else
                {
                    Out-TSLogEntry -LogMsg "$iniFile not found." -LogType LogTypeWarning
                    Continue
                }
            
                $sections = (Get-IniSectionNames -File $iniFile)
                foreach ($section in $sections)
                {
                    Out-TSLogEntry -LogMsg "Found INI file section: $section" -LogType LogTypeInfo

                    $keys = (Get-IniSectionKeys -File $iniFile -Section $section)
                    foreach ($key in $keys)
                    {
                        Out-TSLogEntry -LogMsg "BIOS Setting name: $key" -LogType LogTypeInfo
                        $value = (Get-IniValue -File $iniFile -Section $section -Key $key)
                        Out-TSLogEntry -LogMsg "BIOS Setting desired value: $value" -LogType LogTypeInfo

                        $setting = (Get-WmiObject -Namespace 'root\wmi' -Class 'QueryBiosSettings' | Where-Object { $_.CurrentSetting -match "^$($key)," })
                        If ($setting -eq $null)
                        {
                            Out-TSLogEntry -LogMsg "BIOS Setting name `"$key`" not found in WMI" -LogType LogTypeWarning
                        }
                        else
                        {
                            $settingString = $setting.CurrentSetting
                            $arrSetting = ($settingString).split(",")
                            
                            Out-TSLogEntry -LogMsg "BIOS Setting current value: $($arrSetting[2])" -LogType LogTypeInfo
                            if ("$($arrSetting[2])" -eq $value)
                            {
                                Out-TSLogEntry -LogMsg "BIOS Setting current value already at desired value." -LogType LogTypeInfo
                            }
                            else
                            {

                                if ("$($arrSetting[1])" -eq "RO")
                                {
                                    Out-TSLogEntry -LogMsg "BIOS Setting is read only." -LogType LogTypeInfo
                                }
                                else
                                {
                                    Out-TSLogEntry -LogMsg "Changing BIOS Setting to desired value." -LogType LogTypeInfo

                                    If ($IsPasswordSet -eq $true)
                                    {
                                        $mode = Get-WmiObject –namespace "root\wmi" -class "ModeControl" | where {$_.InstanceName -match "ACPI\\pnp0c14\\0.0"} 
                                        $result = $mode.SetConfigurationMode("Start,$BiosPassword;").Return 

                                        if ($result -eq 0)
                                        {
	                                        Out-TSLogEntry "Successful Authenticated" -LogType LogTypeInfo
                                        }
	                                    else
	                                    {
	                                        Out-TSLogEntry "Authentication  failed, Error Code= "$result  -LogType LogTypeError
                                            continue
	                                    } 
                                    }
                                    $FirmwareUpdated = $true


                                    $BiosParameterString = "$($key),$($value);"
                                    # write-host "$($BiosParameterString)"
                                    try
                                    {
                                        $WmiResult = (Get-WmiObject -Namespace 'root\wmi' -Class 'BiosSetting' | where {$_.InstanceName -match “ACPI\\pnp0c14\\0.0"}).SetBiosSetting("$($BiosParameterString)")
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


                                    If ($IsPasswordSet -eq $true)
                                    {
                                        $result = $mode.SetConfigurationMode("End,$BiosPassword;").Return 

                                        if ($result -eq 0)
                                        {
	                                        Out-TSLogEntry "Successful Deauthenticated" -LogType LogTypeInfo
                                        }
	                                    else
	                                    {
	                                        Out-TSLogEntry "Deauthenticated  failed, Error Code= "$result  -LogType LogTypeError
	                                    } 
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if ($FirmwareUpdated) { 
                Out-TSLogEntry -LogMsg "Dumping BIOS settings after attemping changes." -LogType LogTypeInfo
                Convert-WMIClassPropertiesToIniFile -File $logAfterSettings -Section "QueryBiosSettings" -NameSpace "root\wmi" -Class "QueryBiosSettings" -KeyProperty "CurrentSetting" -ValuePropertyIndex 2
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


