<#

.SYNOPSIS
Testing script for OSD In-place upgrade

.DESCRIPTION
OSD Inplace upgrade Pre-Flight script.

.NOTES
For support questions, mailto:G=EUC-CCMPE@wellsfargo.com

Can be run as a CI

#####
### DO NOT MODIFY THIS FILE, AUTOGENERATED
#####

#>

[cmdletbinding()]
param( 
    [string]$Version = '0.4.1804.2310',

    [switch] $DispalyUIAndReRun = $true,

    $RegConfig = 'HKLM:\Software\WaaS\PreFlight',

    $LogPath = 'c:\windows\CCM\Logs\PreFlight.log'

)

try
{
    $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
}
catch
{
	Write-Verbose "Not running in a task sequence."
}
if ($tsenv)
    {
    $SMSTS_BUILD = $tsenv.Value("SMSTS_BUILD")
    $RegConfig = "HKLM:\Software\WaaS\$SMSTS_BUILD"
    }

$script:Module = 'PreFlight'
$count = 0

#################

#region Library 1 IMPORTED FROM: [..\Nomad\Common.Library.ps1]
########################################
# Library 1 IMPORTED FROM: [..\Nomad\Common.Library.ps1]
# Common Library

Function Write-ToLog {
    [cmdletbinding()]
    param ( [parameter(ValueFromPipeline=$true)] [string] $Msg )

    begin {
        if ( -not $logpath ) { throw "missing $logPath" }
    }
    process {
        $msg | out-string -Width 200 | write-Verbose
        $msg | out-file -Encoding ascii -Force -Append -FilePath $LogPath
    }

}

function Set-AppSettingIncrement {
    [cmdletbinding()]
    param (
        [string] $Name
    )

    [int]$Value = Get-AppSettings @PSBoundParameters
    Set-AppSettings @PSBoundParameters -Value ($Value + 1).ToString()
}

function Get-AppSettings {
    [cmdletbinding()]
    param ( [string] $Name )

    if ( -not $RegConfig ) { throw "missing $RegConfig" }
    if ( -not ( test-path $RegConfig ) ) {
        new-item -ItemType Directory -Path $RegConfig -force -ErrorAction SilentlyContinue | Out-Null
    }
    try { Get-ItemPropertyValue -Path $RegConfig -name $Name | Write-Output } catch {}
}

function Set-AppSettings {
    [cmdletbinding()]
    param ( [string] $Name, $Value )
    if ( ( $Value.GetType().Name -in 'Int32','Int64','uint32','uint64','double' ) -and ($Value -gt 3MB ) ) {
        Write-ToLog ("`t`tSettings: [$Name] = [$value]  {0:N0} MB" -f ( $value / 1MB ))
    }
    else {
        Write-ToLog "`t`tSettings: [$Name] = [$value]"
    }
    if ( -not $RegConfig ) { throw "missing $RegConfig" }
    if ( -not ( test-path $RegConfig ) ) {
        new-item -ItemType Directory -Path $RegConfig -force -ErrorAction SilentlyContinue | Out-Null
    }
    Set-ItemProperty -path $RegConfig -name $Name -Value $Value | Out-Null
}

Function Exit-WithError {
    [cmdletbinding()]
    param ( 
        [int] $ExitCode,
        [string] $module = 'CacheUtility',
        [string] $Msg
    )

    if ( $ExitCode -ne 0 ) { 
        Write-ToLog "ERROR: $Msg"
        New-EventLog -LogName Application -Source $module -ErrorAction SilentlyContinue
        Write-EventLog -LogName Application -Source $module -EventId $ExitCode -Message $msg
    }
    else {
        Write-ToLog $Msg
    }

    Set-AppSettings -name 'LastStatusInt' -Value $ExitCode
    Set-AppSettings -name 'LastStatusMsg' -Value $Msg

    exit $ExitCode
}

function Approve-ObjectIfRemediate {
    [cmdletbinding()]
    param ( 
        [parameter(ValueFromPipeline=$true)]  $InputObject,
        [string] $PropertyName
        )

    process {
        if ( -not $CIRemediate ) {
            if ( $PropertyName ) {
                $Name = $InputObject | % $PropertyName
            }
            else {
                $Name = $InputObject
            }
            "Do not remediate object, flag for use later" | Write-ToLog
            $Name | out-string | write-tolog 
            $global:isComplaint = $Name
        }
        else {
            $InputObject | Write-Output
        }
    }
}

Function Get-VolumeEx {
<#
Windows 7 does not have Get-Volume
#>
    [cmdletbinding()]
    param ( $DriveLetter = 'c' )
    
    gwmi win32_logicaldisk -Filter "DeviceID='$($DriveLetter.Substring(0,1))`:'" |
        Select -Property Size,FileSystem,
        @{Name='SizeRemaining';Expression={$_.FreeSPace}},
        @{Name='DriveLetter';Expression={$_.Caption.SubString(0,1)}},
        @{Name='FileSystemLabel';Expression={$_.VolumeName}}
}

function Invoke-As64Bit {
    <#
    Re-Invoke Powershell, this time as a 64-bit process.
    Warning, will only return 1 or 0 as last error code.
    Example usage:
        if ( Invoke-As64Bit -Invokation $myInvocation -arks $args ) {
            write-host "finished $lastexitcode"
            exit $lastexitcode
        }
    #>
    [cmdletbinding()]
    param( [parameter(Mandatory=$true)] $Invokation, $arks )

    #Re-Invoke 
    if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
        if ($Invokation.Line) {
            write-verbose "RUn Line: $($Invokation.Line)"
            & "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -noninteractive -NoProfile $Invokation.Line
        }else{
            write-verbose "RUn Name: $($Invokation.InvocationName) $arks"
            & "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -noninteractive -NoProfile -file "$($Invokation.InvocationName)" $arks
        }
        return $true
    }
    return $false
}
#endregion

#region Library 2 IMPORTED FROM: [..\Nomad\Common.MessageBox.ps1]
########################################
# Library 2 IMPORTED FROM: [..\Nomad\Common.MessageBox.ps1]

function Show-MessageBox {
<#
 .SYNOPSIS
Display a MessageBox()

.DESCRIPTION
Display a message box with various parameters

.PARAMETER Message
    Body of Messagebox text

.PARAMETER Title
    Caption of Messagebox

.PARAMETER nType
    Type of buttons

    0 OK button only 
    1 OK and Cancel buttons 
    2 Abort, Retry, and Ignore buttons 
    3 Yes, No, and Cancel buttons 
    4 Yes and No buttons 
    5 Retry and Cancel buttons 

    Type of Icon, one of:

    16 Stop sign 
    32 Question mark 
    48 Exclamation point 
    64 Information (i) icon 

.OUTPUTS
    Returns a [System.Windows.Forms.DialogResult] object, can be one of:

    1 OK 
    2 Cancel 
    3 Abort 
    4 Retry 
    5 Ignore 
    6 Yes 
    7 No 

.EXAMPLE
    Show-MessageBox "Hello World"

.EXAMPLE
    (Show-MessageBox "Do you like Ice Cream?" -Buttons 4) -eq 6

#>

    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [String] $Message,
        [String] $Title = 'Error',
        [ValidateRange(0,5)]
        [int] $Buttons = 0,
        [ValidateRange(16,64)]
        [int] $Icons = 0,
        [int] $Timeout
    )


    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    Write-verbose "MessageBox('$Message','$Title', $($Buttons -bor $Icons))"
    if ($Timeout) {
        (new-object -ComObject WScript.Shell).popup($Message,$Timeout,$Title,$Buttons -bor $Icons) | Write-Output
    }
    else {
        [System.Windows.Forms.MessageBox]::Show($Message,$Title,$Buttons,$Icons) | Write-Output
    }

}
#endregion

#region Data
    $Data = 
#Data 3 IMPORTED FROM: [Data\PreFlight.json]
########################################
@'
[
    {
        "Category":  "General",
        "Name":  "isPCOSWorkstation",
        "ErrorNumber":  "536870913",
        "Description":  "Is machine a Client (as compared to Server)",
        "Remediate":  "Contact Technology Connection",
        "Value":  "1",
        "COmmand":  "GWMI Win32_OperatingSystem | ? ProductType -ne $args[0] "
    },
    {
        "Category":  "General",
        "Name":  "isPCOSEnglish",
        "ErrorNumber":  "536870914",
        "Description":  "Is machine running English",
        "Remediate":  "Contact Technology Connection",
        "Value":  "1033",
        "COmmand":  "GWMI Win32_OperatingSystem | ? OSLanguage -ne $args[0] "
    },
    {
        "Category":  "General",
        "Name":  "isPCOSx64",
        "ErrorNumber":  "536870915",
        "Description":  "Is machine running x64",
        "Remediate":  "Contact Technology Connection",
        "Value":  "64-Bit",
        "COmmand":  "GWMI win32_operatingsystem | ? OSArchitecture -ne $args[0] "
    },
    {
        "Category":  "General ",
        "Name":  "PCOSVersion",
        "ErrorNumber":  "536870917",
        "Description":  "Verify OS Version",
        "Remediate":  "Contact Technology Connection",
        "Value":  "10.0.14393",
        "Command":  "$test = $args[0]; GWMI WIn32_OperatingSystem | ? { [version]($_.Version) -lt $test }"
    },
    {
        "Category":  "Hardware",
        "Name":  "PCHWMemory",
        "ErrorNumber":  "536870918",
        "Description":  "Verify Hardware Info",
        "Remediate":  "Contact Technology Connection",
        "Value":  "1900000000",
        "Command":  "GWMI Win32_computersystem | ? TotalPhysicalMemory -lt $args[0]"
    },
    {
        "Category":  "General",
        "Name":  "PCHWFreeDiskSize",
        "ErrorNumber":  "536870919",
        "Description":  "Low Free Disk Space",
        "Remediate":  "Clean Disk",
        "Value":  "21474836480",
        "Command":  "get-volume c | ? SizeRemaining -lt $args[0]"
    },
    {
        "Category":  "General",
        "Name":  "OSIsRunningBattery",
        "ErrorNumber":  "536870922",
        "Description":  "System Running on Battery",
        "Remediate":  "Connect Power Adpater",
        "Value":  "TRUE",
        "Command":  "gwmi win32_battery | ? BatteryStatus -ne 2"
    },
    {
        "Category":  "General",
        "Name":  "CMMPCOnnectivity",
        "ErrorNumber":  "536870923",
        "Description":  "MP Connectivity Failure",
        "Remediate":  "Connect to Network",
        "Value":  "TRUE",
        "Command":  "gwmi -namespace \u0027root\\ccm\u0027 \u0027sms_authority\u0027 | % { $_.CurrentManagementPoint  } | test-netconnection -InformationLevel quiet | foreach-object { -not $_ }"
    },
    {
        "Category":  "General",
        "Name":  "KillSwitch",
        "ErrorNumber":  "536870924",
        "Description":  "Kill Switch Enabled",
        "Remediate":  "Remove c:\\Windows\\KillSwitch.txt",
        "Value":  "c:\\windows\\KillSwitch.txt",
        "Command":  "test-path $Args[0]"
    },
    {
        "Category":  "CoreApps",
        "Name":  "CMClientVersion",
        "ErrorNumber":  "536870925",
        "Description":  "CMClient Version Mismatch",
        "Remediate":  "Upgrade Software: CM Client",
        "Value":  "5.00.8577.1000",
        "Command":  "$test = $args[0]; gwmi -EA SilentlyContinue -NameSpace Root\\CIMV2\\SMS -Class sms_installedSoftware -Filter \u0027ARPDisplayName LIKE \u0027\u0027Configuration Manager Client\u0027\u0027\u0027 | ? { [version]($_.ProductVersion) -lt $test }"
    }
]
'@

#endregion

#region MAIN()

$TSProgressUI = $null

do {

    $LastErr = 0
    $IsNotCompliant = $null
    $DisplayMe = $Null

    foreach ( $TestOperation in $data | ConvertFrom-Json | % SYncRoot ) {

        if ( -not ( Invoke-command -ScriptBlock ([scriptblock]::Create($TestOperation.Command)) -ArgumentList $TEstOperation.Value ) ) {
            "Success: $($TestOperation.Category)\$($TestOperation.Name) - $($TestOperation.Description) = [$($TestOperation.Value)]" | Write-ToLog
        }
        else {
            $IsNotCompliant += ( "Error [0x{0:X8}]: $($TestOperation.Description)`r`n" -f ($TestOperation.ErrorNumber -bor 0 ) )
            $DisplayMe += ( "Error [0x{0:X8}]: $($TestOperation.Description)`r`n`tTo Fix: {1}`r`n" -f ($TestOperation.ErrorNumber -bor 0 ),($testOperation.Remediate) )
            "ERROR: $TestOperation" | write-tolog
            $LastErr = $TestOperation.ErrorNumber
        }

    }

    if ( $IsNotCompliant -and $DispalyUIAndReRun ) {

        $msg = @"
There were some errors when making preperations for 
running Windows 10 inplace upgrade

$DisplayMe

Press retry to run tests again.
"@
        if ( -not $TSProgressUI ) {
            $TSProgressUI = $TSProgressUI = new-object -comobject Microsoft.SMS.TSProgressUI
        }
        $TSProgressUI.CloseProgressDialog()
        $result = Show-MessageBox -Message $msg -Title "Windows 10 In Place Upgrade" -Icons 16 -Buttons 5 -Timeout (5 * 60)

        $Count += (5 * 60)

        if ( $result -eq 2 -or $Result -eq [System.Windows.Forms.DialogResult]::Cancel -or $count -gt ( 60 * 60 ) ) { Break }

    }
    else {

        write-verbose "No errors or no UI request!"
        break

    }

} while ( $true )

###########

if ( -not $IsNotCompliant ) { $IsNotCompliant = 'Compliant' }
Write-host $IsNotCompliant

#######################################

write-verbose "Write Summary to Registry"

Set-AppSettings -Name 'PreFlightLastRun' -Value ( get-date -f 's' ).Tostring()
Set-AppSettings -Name 'PreFlightVersion' -value $Version.ToString()

Set-AppSettings -Name 'PreFlightReturnCode' -Value $LastErr
Set-AppSettings -Name 'PreFlightReturnStatus' -Value $IsNotCompliant

Set-AppSettingIncrement 'PreFlightAttempts'

###########

if ( $IsNotCompliant -ne 'Compliant' ) {

    Set-AppSettings -Name 'Waas_Stage' -Value 'PreFlight_Failure'
}

exit $LastErr

#endregion
