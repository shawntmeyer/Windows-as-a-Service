<#
    .SYNOPSIS
        This script creates boot a new BCS store for applied prestaged
        media to enable the prestaged media to boot.

    .PARAMETER
        None.  No parameters required.

    .EXAMPLE
        PS C:\> New-BcdStore.ps1

    .INPUTS
       None.  This command does not accept pipeline input.

    .OUTPUTS
       None.  This command does not produce pipeline output.

    .NOTES
       Requires module TSUtility.psm1 in the same folder.
       If any error occurs, the command will produce a terminating error.
#>

#******************************************************************************
# File:     New-BcdStore.ps1
# Version:  1.0.3
#
# Revisions:
# ----------
# 1.0.0   2016-03-23   Created script.
# 1.0.1   2016-04-04   Corrected line that sets $OSPart.  Added missing /f in
#                      bcdboot argument list.
# 1.0.2   2016-05-26   Replaced lines to set $OSPART and $EFIPART* variables
#                      with Set-TSPartitionVariables call.
# 1.0.3   2016-06-20   Put Set-TSPartitionVariables call into if block to see if
#                      OSDDiskIndex is set.  If so, use the value as the 
#                      DiskNumber parameter for Set-TSPartitionVariables.
#
#******************************************************************************

# Set Script file path variables
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$ScriptExt = (Get-Item $ScriptPath).extension
$ScriptBaseName = $ScriptName -replace($ScriptExt ,"")
$ScriptFolder = Split-Path -parent $ScriptPath


# Load Modules
import-module "$ScriptFolder\TSUtility.psm1" -force

# Trap any error, log, and exit
$ErrorActionPreference = 'Stop'
Trap
{
    Out-LogErrorInfo $_
    exit 1
}

if ($tsenv -ne $null) {
    if (($tsenv.Value('OSDDiskIndex') -ne "") -and ($tsenv.Value('OSDDiskIndex') -ne $null))
    {
        Set-TSPartitionVariables -DiskNumber $tsenv.Value('OSDDiskIndex')
    }
    else
    {
        Set-TSPartitionVariables
    }
}

$BCDBootOption = "UEFI"
$BCDDir = "EFI\Microsoft\Boot"
$EFIPARTBCD = "$EFIPARTLetter\$BcdDir\BCD"

$env:OSPART = $OSPART
$env:EFIPARTLetter = $EFIPARTLetter
$env:EFIPARTBCD = $EFIPARTBCD
$env:BCDBootOption = $BCDBootOption
$env:BCDDir = "EFI\Microsoft\Boot"

#Creates the BCD store on the boot partition

#& bcdboot.exe --% %OSPART%\windows /s %EFIPARTLetter% /f %BCDBootOption%
Start-Executable -FilePath "$($env:SystemRoot)\System32\bcdboot.exe" -ArgumentList @("$OSPART\windows", "/s", "$EFIPARTLetter", "/f", "$BCDBootOption") -FailAction Exit

Out-TSLogEntry -LogMsg "Running command: remove-item -Path `"$EFIPARTBCD`" -Force" -LogType LogTypeInfo
remove-item -Path "$EFIPARTBCD" -Force

Out-TSLogEntry -LogMsg "Running command: copy-item -Path `"$OSPART\$BCDDir\BCD`" -Destination `"$EFIPARTLetter\$BCDDir`" -Force" -LogType LogTypeInfo
copy-item -Path "$OSPART\$BCDDir\BCD" -Destination "$EFIPARTLetter\$BCDDir" -Force

#& bcdedit.exe --% /Store %EFIPARTBCD% /Set {ramdiskoptions} ramdisksdidevice partition=%OSPART%
Start-Executable -FilePath "$($env:SystemRoot)\System32\bcdedit.exe" -ArgumentList @('/Store', "$EFIPARTBCD", '/Set', '{ramdiskoptions}', 'ramdisksdidevice', "partition=$OSPART") -FailAction Exit

#& bcdedit.exe --% /Store %EFIPARTBCD% /Set {Default} device ramdisk=[%OSPART%]\sources\boot.wim,{ramdiskoptions}
Start-Executable -FilePath "$($env:SystemRoot)\System32\bcdedit.exe" -ArgumentList @('/Store', "$EFIPARTBCD", '/Set', '{Default}', 'device', "ramdisk=[$OSPART]\sources\boot.wim,{ramdiskoptions}") -FailAction Exit

#& bcdedit.exe --% /Store %EFIPARTBCD% /Set {Default} osdevice ramdisk=[%OSPART%]\sources\boot.wim,{ramdiskoptions}
Start-Executable -FilePath "$($env:SystemRoot)\System32\bcdedit.exe" -ArgumentList @('/Store', "$EFIPARTBCD", '/Set', '{Default}', 'osdevice', "ramdisk=[$OSPART]\sources\boot.wim,{ramdiskoptions}") -FailAction Exit

#& bcdedit.exe --% /Store %EFIPARTBCD% /Set {bootmgr} device partition=%EFIPARTLetter%
Start-Executable -FilePath "$($env:SystemRoot)\System32\bcdedit.exe" -ArgumentList @('/Store', "$EFIPARTBCD", '/Set', '{bootmgr}', 'device', "partition=$EFIPARTLetter") -FailAction Exit

