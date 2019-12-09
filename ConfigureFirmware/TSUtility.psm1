# ***************************************************************************
# 
# File:      TSUtility.psm1
# 
# Version:   2.1.2
# 
# Purpose:   Provides a set of PowerShell advanced functions (cmdlets) to
#            provide some of the functionality of ZTIUtility.vbs for
#            PowerShell scripts.
#            This requires at least PowerShell 3.0.
#            Also requires IniFile.psm1 in the same folder.
#
# Usage:     This script must be imported using "import-module", e.g.:
#              import-module .\TSUtility.psm1
#            After it has been imported, the indivual functions below can be
#            used.  For details on the parameters each one takes, you can
#            use "get-help", e.g. "get-help Out-TSLogEntry".  Note that
#            there is no detailed help provided on the cmdlets.
#
# Revisions:
# -----   2016-??-??   Revisions before 2.0.0 - changes not documented.
# 2.0.0   2016-03-16   Replaced IniReader.cs with IniFile.psm1.  This
#                      module contains cmdlets for manipulating INI files.
#                      Added .Trim() to most WMI calls in Get-AssetInfo.
# 2.0.1   2016-03-22   Replaced the Org.Mentalis.Files.IniReader Write calls in 
#                      Convert-WMIClassPropertiesToIniFile with the Set-IniValue
#                      cmdlet from IniFile.psm1.
# 2.0.2   2016-03-23   Added Resolve-Error, Out-LogErrorInfo, and
#                      Start-Executable functions.
# 2.0.3   2016-05-26   Added Set-TSPartitionVariables function.
# 2.0.4   2016-05-27   Changed Write-Info call in Set-TSVariables to Out-TSLogEntry.
#                      Move line "Set-TSVariables -Variables $(Get-AssetInfo)" to
#                      just before Export-ModuleMember call.
# 2.0.5   2016-05-31   Changed Set-TSVariables to use Set-Variable instead of
#                      Invoke-Expression.  Set -Scope option to Global.
# 2.0.6   2016-06-13   Added Get-OSInfo function and Set-TSVariables call to
#                      use it.
# 2.0.7   2016-06-14   Added PSVariables parameter to Set-TSVariables and
#                      changed Set-TSVariables calls to use it.
#                      Added Set-TSListVariable and Get-TSListVariable
#                      functions.
# 2.0.8   2016-06-16   Added additional Manufacturer string (HP) to match
#                      Hewlett-Packard MakeAlias.  Added code to default
#                      MakeAlias to Make when there is no match.
# 2.0.9   2016-06-22   Changed logic for MakeAlias when Make if HP.
# 2.1.0   2016-09-21   Added functions ConvertFrom-Base64String, 
#                      Get-StandardNetworkConnectCredentials, Get-NAANameByIndex,
#                      and Get-AllNAACredentials.
# 2.1.1   2016-10-25   Added ValueParameterIndex and created ParameterSets for
#                      Convert-WMIClassPropertiesToIniFile. 
# 2.1.2   2016-10-25   Added Wait-WMIClass.
#
# ------------- DISCLAIMER -------------------------------------------------
# This script code is provided as is with no guarantee or waranty concerning
# the usability or impact on systems and may be used, distributed, and
# modified in any way provided the parties agree and acknowledge the 
# Microsoft or Microsoft Partners have neither accountabilty or 
# responsibility for results produced by use of this script.
#
# Microsoft will not provide any support through any means.
# ------------- DISCLAIMER -------------------------------------------------
#
# ***************************************************************************

##########################################################################################
# TSUtility Functions
##########################################################################################
##########################################################################################
# https://blogs.msdn.microsoft.com/powershell/2006/12/07/resolve-error/
function Resolve-Error {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.ErrorRecord]
        [ValidateNotNullOrEmpty()]
        $ErrorRecord = $Error[0]
    )
    $ErrorRecord | Format-List * -Force
    $ErrorRecord.InvocationInfo |Format-List *
    $Exception = $ErrorRecord.Exception
    for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException))
    {
        #"$i" * 80
        $Exception |Format-List * -Force
    }
}

##########################################################################################
# https://blogs.msdn.microsoft.com/powershell/2006/12/07/resolve-error/
function Out-LogErrorInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Management.Automation.ErrorRecord]
        [ValidateNotNullOrEmpty()]
        $ErrorRecord = $Error[0]
    )
    Out-TSLogEntry -LogMsg "*** Error Occurred ***" -LogType LogTypeError
    Out-TSLogEntry -LogMsg "*** ErrorRecord -" -LogType LogTypeError
    $ErrorRecord | Format-List * -Force | Out-String | Out-TSLogEntry -LogType LogTypeError
    Out-TSLogEntry -LogMsg "*** ErrorRecord InvocationInfo -" -LogType LogTypeError
    $ErrorRecord.InvocationInfo |Format-List * | Out-String | Out-TSLogEntry -LogType LogTypeError
    $Exception = $ErrorRecord.Exception
    for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException))
    {   
        # "$i" * 80
        Out-TSLogEntry -LogMsg "*** Exception $i -" -LogType LogTypeError
        $Exception |Format-List * -Force | Out-String  | Out-TSLogEntry -LogType LogTypeError
    }
}

##########################################################################################
# Based on sample from http://windowsitpro.com/powershell/running-executables-powershell
function Start-Executable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $FilePath,
        [parameter(mandatory = $false)][string[]] $ArgumentList,
        [parameter(mandatory = $false)][int[]] $SuccessCodes = @(0),
        [Parameter(Mandatory = $false)][ValidateSet("Continue", "Exit")][string] $FailAction = "Continue"
    )

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $FilePath
    $process.StartInfo.Arguments = $ArgumentList
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true

    if ( $process.Start() ) {
        $result = "Failure"
        $log = "LogTypeInfo"
        
        $stdOut = $process.StandardOutput.ReadToEnd() -replace "\r\n$",""
        $stdErr = $process.StandardError.ReadToEnd() -replace "\r\n$",""
        $process.WaitForExit()
        $exitCode = $process.ExitCode

        foreach ($code in $SuccessCodes) { if ($exitCode -eq $code) { $result = "Success" } }

        $outObject = New-Object PSCustomObject
        Add-Member -InputObject $outObject -MemberType NoteProperty -Name 'StdOut' -Value $stdOut
        Add-Member -InputObject $outObject -MemberType NoteProperty -Name 'StdErr' -Value $stdErr
        Add-Member -InputObject $outObject -MemberType NoteProperty -Name 'ExitCode' -Value $exitCode
        Add-Member -InputObject $outObject -MemberType NoteProperty -Name 'Result' -Value $result

        if ($result -eq "Failure") { $log = "LogTypeError" }

        Out-TSLogEntry -LogMsg "Ran executable: $FilePath" -LogType $log
        Out-TSLogEntry -LogMsg "  Arguments: `r`n$([string]::join(`"`r`n`", $ArgumentList))`r`n" -LogType $log
        Out-TSLogEntry -LogMsg "  StdOut: `r`n$($stdOut)`r`n" -LogType $log
        Out-TSLogEntry -LogMsg "  StdErr: `r`n$($stdErr)`r`n" -LogType $log
        Out-TSLogEntry -LogMsg "  ExitCode: $($exitCode)" -LogType $log
        Out-TSLogEntry -LogMsg "  Result: $($result)" -LogType $log

        if ($result -eq "Failure") {
            Out-TSLogEntry -LogMsg "Exiting on failure." -LogType $log
            if ($FailAction -eq "Exit") { exit $exitCode } 
        }

        & "$Env:SystemRoot\system32\cmd.exe" /c exit $process.ExitCode
        
        return $outObject
    }
}

##########################################################################################
function Write-Info {
    # Function to make the Write-Host output a bit prettier. 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $text
    )
    Write-Host "INFO   : $($text)  $([datetime]::now)" -ForegroundColor White
}

##########################################################################################
function Write-Trace {
    # Function to make the Write-Verbose output... well... exactly the same as it was before.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $text
    )

    # http://powershell.org/wp/2014/01/13/getting-your-script-module-functions-to-inherit-preference-variables-from-the-caller/
    # Doesn't work when calling function is in the module
    if (-not $PSBoundParameters.ContainsKey('Verbose'))
    {
        $VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
    }

    Write-Verbose "$($text)  $([datetime]::now)"
}

##########################################################################################
function Write-Err {
    # Function to make the Write-Host (NOT Write-Error) output prettier in the case of an error.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $text
    )
    Write-Host "ERROR  : $($text) (at line number: $($_.InvocationInfo.ScriptLineNumber)) $([datetime]::now)" -ForegroundColor Red
}

##########################################################################################
function Write-Warn {
    # Function to make the Write-Host (NOT Write-Warning) output prettier.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $text
    )
    Write-Warning  "$($text) $([datetime]::now)" 
}

##########################################################################################
function Set-TSVerbosePreference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]
        [ValidateSet("Stop", "Inquire", "Continue", "SilentlyContinue")]
        $Preference
    )
    $script:VerbosePreference = $Preference
}

##########################################################################################
function Get-TSEnvironmentObject {
    try {
        $tsenvTemp = New-Object -COMObject Microsoft.SMS.TSEnvironment
        Write-Trace "Script is running in a Task Sequence"
        return $tsenvTemp
    }
    catch
    {
        Write-Trace "Script is not running in a Task Sequence"
        return $null
    } 
}

##########################################################################################
function Set-TSVariables {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][hashtable][ValidateNotNullOrEmpty()] $Variables,
        [parameter(Mandatory=$false)] [switch] $PSVariables
    )
    $Variables.GetEnumerator() | Foreach-Object {    
        Out-TSLogEntry "Property $($_.Key) is now $($_.Value)" -LogType LogTypeInfo
        if ($tsenv -ne $null) { $tsenv.Value($_.Key) = $_.Value }
        if ($PSVariables) { Set-Variable -Name $_.Key -Value $_.Value -Scope Global }
    }
}

##########################################################################################
function Set-TSListVariable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Name,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][array][ValidateNotNullOrEmpty()] $Items,
        [parameter(Mandatory=$false)] [switch] $PSVariables
    )
    $count = 0
    $Items.GetEnumerator() | Foreach-Object {    
        $count++
        $countPadded = "000$count"
        $namePadded = $Name + $countPadded.substring($countPadded.length - 3, 3)
        Out-TSLogEntry "Property $($namePadded) is now $($_)" -LogType LogTypeInfo
        if ($tsenv -ne $null) { $tsenv.Value($namePadded) = $_ }
        if ($PSVariables) { Set-Variable -Name $namePadded -Value $_ -Scope Global }
    }

	# Blank out the next in case there was something there
	$count++
	$countPadded = "000$count"
	$namePadded = $Name + $countPadded.substring($countPadded.length - 3, 3)
	if ($tsenv -ne $null) {
		if (($tsenv.Value($namePadded) -ne "") -and ($tsenv.Value($namePadded) -ne $null))
		{
			$tsenv.Value($namePadded) = ""
		}
	}
	if ($PSVariables) {	Remove-Variable -Name $namePadded -ErrorAction SilentlyContinue }


	# Blank out the non-list item if it was there
	if ($tsenv -ne $null) {
		if (($tsenv.Value($Name) -ne "") -and ($tsenv.Value($Name) -ne $null))
		{
			$tsenv.Value($Name) = ""
		}
	}
	if ($PSVariables) { Remove-Variable -Name $Name -ErrorAction SilentlyContinue }
}

##########################################################################################
function Get-TSListVariable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Name
    )

	Out-TSLogEntry "Getting list item: $Name" -LogType LogTypeInfo

    $arrListItem = @()
	for ($count = 1; $count -le 999; $count++)
	{
        $countPadded = "000$count"
        $namePadded = $Name + $countPadded.substring($countPadded.length - 3, 3)
        $nameUnpadded = $Name + $count
		if (($tsenv.Value($namePadded) -ne "") -and ($tsenv.Value($namePadded) -ne $null))
		{
			Out-TSLogEntry "Property found: $namePadded = $($tsenv.Value($namePadded))" -LogType LogTypeInfo
			$arrListItem += $tsenv.Value($namePadded)
		}
		elseif (($tsenv.Value($nameUnpadded) -ne "") -and ($tsenv.Value($nameUnpadded) -ne $null))
		{
			Out-TSLogEntry "Property found: $nameUnpadded = $($tsenv.Value($nameUnpadded))" -LogType LogTypeInfo
			$arrListItem += $tsenv.Value($nameUnpadded)
		}
		else
		{
			break
		}
	}
	
	@($arrListItem)
}

##########################################################################################
function Out-TSLogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $LogMsg,
        [parameter(mandatory = $false)][string][validateNotnullorEmpty()] $Logfile,
        [Parameter(Mandatory = $False)][ValidateSet("LogTypeInfo", "LogTypeWarning", "LogTypeError", "LogTypeVerbose", "LogTypeDebug")][string] $LogType = "LogTypeInfo"
    )

    if ($Logtype -eq "LogTypeInfo"){
        Write-Info $logmsg
        $iLogtype = 1
    } elseif ($Logtype -eq "LogTypeWarning"){
        Write-Warn $LogMsg
        $iLogtype = 2
    } elseif ($Logtype -eq "LogTypeError"){
        Write-Err $LogMsg
        $iLogtype = 3
    } elseif ($Logtype -eq "LogTypeVerbose"){
        Write-Trace $LogMsg
        $iLogtype = 4
    } elseif ($Logtype -eq "LogTypeDebug"){
        Write-Debug $LogMsg
        $iLogtype = 6
    }

    try {
        $CallingScriptName = [IO.Path]::GetFileNameWithoutExtension($CallingScriptPath)
    } catch {
        $CallingScriptName = ""
    }

    if (($Logfile -eq $null) -or ($Logfile -eq "")) {
        if ($CallingScriptName -eq "") { 
            $LogFileName = "TSUtility"
        } else {
            $LogFileName = $CallingScriptName
        }
        $Logfile = "$(Get-TSLogPath)\$($LogFileName).log"
    }

    $TempMessage = "<![LOG[$($LogMsg)]LOG]!><time=""$(Get-Date -f HH:mm:ss).000+000"" date=""$(Get-date -f MM-dd-yyyy)"" component=""$($CallingScriptName)"" context=""B"" type=""$($iLogType)"" thread="""" file=""$($CallingScriptName)"">" 
    $TempMessage | out-file $Logfile -Append -Encoding ascii 
}

##########################################################################################
function Get-TSLogPath {
    try
    {
        $TempLogpath = $tsenv.Value("_SMSTSLogPath")
        Write-Trace "ConfigMgr Log path is $($TempLogpath)"
        return $TempLogpath
    }
    catch
    {
        Write-trace "Script is not running in a Task Sequence"
        If ($env:SystemDrive -eq "X:") {
            $TempLogpath = "$($env:SystemDrive)\Windows\Temp\SMSTSLog"
        } else {
            $TempLogpath = "$($env:SystemDrive)\MININT\SMSOSD\OSDLOGS"
        }
        If ((Test-Path $TempLogpath) -ne $true) {md $TempLogpath}
        return $TempLogpath
    } 
}

##########################################################################################
function Convert-BooleanToString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [bool]
        [ValidateNotNullOrEmpty()]
        $Value
    )

    if ($Value -eq $true)
    { 
        return "True"
    }
    elseif ($Value -eq $false)
    {
        return "False"
    }
    else
    {
        return ""
    }

}

##########################################################################################
function Test-WMIClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Class,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $NameSpace = "root/cimv2",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $ComputerName = "."
    )
    try {
        $cimClassTemp = (Get-WmiObject -Class $Class -NameSpace $NameSpace -ComputerName $ComputerName -ErrorAction Stop)
        return $true
    } catch {
        return $false
    }
}

##########################################################################################
function Wait-WMIClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Class,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $NameSpace = "root/cimv2",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $ComputerName = ".",
        [Parameter(Mandatory = $false)] [int] $Timeout = 60
    )

    $StartTime = (Get-Date)
    do {
        $CurrentTime = (Get-Date)
        $timespan = [int]((New-Timespan –Start $StartTime –End $CurrentTime).TotalSeconds)
        Out-TSLogEntry -LogMsg "Wait-WMIClass Elapsed time (seconds): $timespan." -LogType LogTypeInfo
        if ($timespan -gt $Timeout)
        {
            $false
            break
        }
        Start-Sleep -Seconds 5 | Out-Null
        $wmiClassExists = (Test-WMIClass -Class $Class -NameSpace $NameSpace -ComputerName $ComputerName)
        if ($wmiClassExists)
        {
            $true
        }
    } until ($wmiClassExists)
    
}


##########################################################################################
function Convert-WMIClassPropertiesToIniFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $File,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Section,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $ComputerName = ".",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $NameSpace = "root/cimv2",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $Class,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $KeyProperty = "Name",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true,ParameterSetName='ByValueName')][string] $ValueProperty = "",
        [Parameter(Mandatory = $false, ValueFromPipeline = $true,ParameterSetName='ByValueIndex')][int] $ValuePropertyIndex = 1
    )

    try {
        $wmiClassTemp = (Get-WMIObject -ComputerName $ComputerName -NameSpace $NameSpace -Class $Class -ErrorAction Stop)
        
        if (($ValueProperty -ne $null) -and ($ValueProperty -ne ""))
        {
            $wmiClassTemp | Where-Object { ($_."$KeyProperty".length -ne 0)} | ForEach-Object { 
                Write-Info "$($_.`"$KeyProperty`")=$($_.`"$ValueProperty`")"
                $returnVal = (Set-IniValue -File $File -Section $Section -Key "$($_.`"$KeyProperty`")" -Value "$($_.`"$ValueProperty`")")
            }
        }
        else
        {
            $wmiClassTemp | Where-Object { ($_."$KeyProperty".length -ne 0)} | ForEach-Object { 
                $arrSetting = ($_."$KeyProperty").split(",")
                Write-Info "$($arrSetting[0])=$($arrSetting[$ValuePropertyIndex])"
                $returnVal = (Set-IniValue -File $File -Section $Section -Key "$($arrSetting[0])" -Value "$($arrSetting[$ValuePropertyIndex])")
            }
        }

        return $true
    } catch {
        return $false
    }
}

##########################################################################################
function ConvertFrom-Base64String
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string][ValidateNotNullOrEmpty()]
        $EncodedString
    )

    [System.Text.Encoding]::Default.GetString([System.Convert]::FromBase64String($EncodedString))
}

##########################################################################################
Function Get-StandardNetworkConnectCredentials
{
    $Creds = @()

    if ($tsenv -ne $null)
    {
        # See if MDT network account variables are set.  This will be the case if Lite Touch or a Network Access Account was used previously.
        if (($tsenv.Value("UserID") -ne "") -and ($tsenv.Value("UserDomain") -ne "") -and ($tsenv.Value("UserPassword") -ne ""))
        {
            Out-TSLogEntry "MDT network connect credentials detected" -LogType LogTypeInfo

            $userName = ConvertFrom-Base64String -EncodedString $tsenv.Value("UserID")
            $domainName = ConvertFrom-Base64String -EncodedString $tsenv.Value("UserDomain")
            $ntAccountName = "$domainName\$userName"
            $password = ConvertFrom-Base64String -EncodedString $tsenv.Value("UserPassword")

            $mdtUser = New-Object PSObject
            Add-Member -inputObject $mdtUser -MemberType NoteProperty -Name "NTAccountName" -Value $ntAccountName
            Add-Member -inputObject $mdtUser -MemberType NoteProperty -Name "Password" -Value $password
            Add-Member -inputObject $mdtUser -MemberType NoteProperty -Name "Description" -Value "MDT UserID"
            Add-Member -inputObject $mdtUser -MemberType NoteProperty -Name "DomainName" -Value $domainName
            Add-Member -inputObject $mdtUser -MemberType NoteProperty -Name "UserName" -Value $userName
            $Creds += ,$mdtUser

        }

        # Add any Network Access Account(s)
        Get-AllNAACredentials | % { $Creds += ,$_ }
    }

    # See if any credentials are in the array
    if ($Creds -eq 0)
    {
        Out-TSLogEntry "No standard credentials available to connect" -LogType LogTypeWarning
    }

    return $Creds
}

##########################################################################################
function Get-NAANameByIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [int][ValidateNotNullOrEmpty()]
        $Index
    )

    $maxNumLength = 3
    $NAAName = "_SMSTSReserved1-"
    $NAAPass = "_SMSTSReserved2-"
    
    if ($Index -le 0)
    {
        $numberAsString = "000"
    }
    else
    {
        $numberAsString = "0" * ($maxNumLength - [math]::truncate([math]::log([math]::truncate($Index)) / [math]::log(10)) - 1) + "$([math]::truncate($Index))"
    }
    
    $NAAName = $NAAName + $numberAsString
    $NAAPass = $NAAPass + $numberAsString
    
    if ($tsenv -ne $null)
    {
        if (($tsenv.Value($NAAName) -ne "") -and ($tsenv.Value($NAAPass) -ne ""))
        {
            return $NAAName
        }
        else
        {
            return ""
        }
    }
}

##########################################################################################
Function Get-AllNAACredentials
{
    $NAACreds = @()

    Out-TSLogEntry "Looking for Network Access Account(s)" -LogType LogTypeInfo

    if ($tsenv -ne $null)
    {
        # Add ConfigMgr 2012 R2 and higher Network Access Account(s)
        if (($tsenv.Value("_SMSTSReserved1-000") -ne "") -and ($tsenv.Value("_SMSTSReserved2-000") -ne ""))
        {
            $TryIteration = 0
            $NAAName = Get-NAANameByIndex -Index $TryIteration

            While (($TryIteration -eq 0) -or ($NAAName -ne ""))
            {
                Out-TSLogEntry "ConfigMgr 2012 R2 and higher Network Access Account(s) detected" -LogType LogTypeInfo

                $ntAccountName = $tsenv.Value($NAAName)
                $password = $tsenv.Value($NAAName.Replace("_SMSTSReserved1", "_SMSTSReserved2"))
                $countPadded = "000$($TryIteration)"
                $descriptionPadded = "Network Access Account " + $countPadded.substring($countPadded.length - 3, 3)

                $naaObject = New-Object PSObject
                Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "NTAccountName" -Value $ntAccountName
                Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "Password" -Value $password
                Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "Description" -Value $descriptionPadded
                if ($ntAccountName -match "\\")
                {
                    $arrAcctNameParts = $ntAccountName.split("\")
                    Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "DomainName" -Value $arrAcctNameParts[0]
                    Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "UserName" -Value $arrAcctNameParts[1]
                }
                $NAACreds += ,$naaObject

                $TryIteration++
                $NAAName = Get-NAANameByIndex -Index $TryIteration
            }
        }

        # Add "classic" ConfigMgr Network Access Account
        if (($tsenv.Value("_SMSTSReserved1") -ne "") -and ($tsenv.Value("_SMSTSReserved2") -ne ""))
        {
            Out-TSLogEntry "Pre-ConfigMgr 2012 R2 single Network Access Account detected" -LogType LogTypeInfo
            $ntAccountName = $tsenv.Value("_SMSTSReserved1")
            $password = $tsenv.Value("_SMSTSReserved2")

            $naaObject = New-Object PSObject
            Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "NTAccountName" -Value $ntAccountName
            Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "Password" -Value $password
            Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "Description" -Value "Network Access Account"
            if ($ntAccountName -match "\\")
            {
                $arrAcctNameParts = $ntAccountName.split("\")
                Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "DomainName" -Value $arrAcctNameParts[0]
                Add-Member -inputObject $naaObject -MemberType NoteProperty -Name "UserName" -Value $arrAcctNameParts[1]
            }
            $NAACreds += ,$naaObject
        }
    }

    # See if any credentials are in the array
    if ($NAACreds -eq 0)
    {
        Out-TSLogEntry "No Network Access Account credentials found" -LogType LogTypeWarning
    }

    return $NAACreds
}


##########################################################################################
# TSUtility Gather Functions
##########################################################################################
##########################################################################################
function Get-AssetInfo {

    Out-TSLogEntry -LogMsg "Getting asset info" -LogType LogTypeInfo
    
    $assetInfo = @{}
    $sMake = ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_ComputerSystem').Manufacturer).Trim()
    $assetInfo.Add("Make", $sMake)

	$foundMakeAlias = $false
    $makeAliasCheckList = @("Dell","Lenovo","Hewlett-Packard","Microsoft","VMware","Samsung")
    foreach ($makeTest in $makeAliasCheckList)
    { 
        if ($sMake -match $makeTest)
        {
            $assetInfo.Add("MakeAlias", $makeTest)
            $foundMakeAlias = $true
        }
    }
	if (($sMake -match "HP") -and (-not $foundMakeAlias))
	{
		$assetInfo.Add("MakeAlias", "Hewlett-Packard")
		$foundMakeAlias = $true
	}
    if (-not $foundMakeAlias) { $assetInfo.Add("MakeAlias", $sMake) }

    $sModel = ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_ComputerSystem').Model).Trim()
    $assetInfo.Add("Model", $sModel)
    
    $assetInfo.Add("Product", ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_BaseBoard').Product).Trim())
    $assetInfo.Add("CSPVersion", ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_ComputerSystemProduct').Version).Trim())
    
    if ($sMake -match "Lenovo")
    {
        $assetInfo.Add("ModelAlias", ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_ComputerSystemProduct').Version).Trim())
    }
    else
    {
        $assetInfo.Add("ModelAlias", $sModel)
    }

    $assetInfo.Add("SerialNumber", ((Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_BIOS').SerialNumber).Trim())


    $bIsLaptop = $false
    $bIsDesktop = $false
    $bIsServer = $false

    (Get-WmiObject -Namespace 'ROOT\cimv2' -Class 'Win32_SystemEnclosure') | foreach-object {
        
        if (($_.ChassisTypes[0] -eq 12) -or (($_.ChassisTypes[0]) -eq 21))
        {
            # Ignore docking stations
        }
        else
        {
            $assetInfo.Add("AssetTag", ($_.SMBIOSAssetTag))
            switch -regex ("$($_.ChassisTypes[0])") 
            { 
                "8|9|10|11|12|14|18|21"
                {
                    $bIsLaptop = $true
                }
                "3|4|5|6|7|15|16"
                {
                    $bIsDesktop = $true
                }
                "23" 
                {
                    $bIsServer = $true
                }
                default 
                {
                    #Do nothing
                }
            }
        }
    }

    $assetInfo.Add("IsLaptop", (Convert-BooleanToString -Value $bIsLaptop))
    $assetInfo.Add("IsDesktop", (Convert-BooleanToString -Value $bIsDesktop))
    $assetInfo.Add("IsServer", (Convert-BooleanToString -Value $bIsServer))
 
    $assetInfo

}


##########################################################################################
function Get-OSInfo {

    Out-TSLogEntry -LogMsg "Getting OS info" -LogType LogTypeInfo
    
    $osInfo = @{}

    # Look up OS details
    $IsServerCoreOS = "False"
    $IsServerOS = "False"

    Get-WmiObject Win32_OperatingSystem | % {
		$osInfo.Add("OSCurrentVersion", ($_.Version))
		$osInfo.Add("OSCurrentBuild", ($_.BuildNumber))
    }

    if (Test-Path HKLM:System\CurrentControlSet\Control\MiniNT) {
		$osInfo.Add("OSVersion", "WinPE")
    }
    else
    {
		$osInfo.Add("OSVersion", "Other")
		if ((Test-Path "$env:WINDIR\Explorer.exe") -eq $false) {
			$IsServerCoreOS = "True"
		}

		if (Test-Path HKLM:\System\CurrentControlSet\Control\ProductOptions\ProductType)
		{
			$productType = Get-Item HKLM:System\CurrentControlSet\Control\ProductOptions\ProductType
			if ($productType -eq "ServerNT" -or $productType -eq "LanmanNT") {
				$IsServerOS = "True"
			}
		}
	}

	$osInfo.Add("IsServerCoreOS", $IsServerCoreOS)
	$osInfo.Add("IsServerOS", $IsServerOS)

    $osInfo
}


##########################################################################################
function Set-TSPartitionVariables {
        [CmdletBinding()]
        param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][int][ValidateNotNullOrEmpty()] $DiskNumber = 0,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $OSVolumeLabel = 'OSDisk',
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)][string][ValidateNotNullOrEmpty()] $BDEVolumeLabel = 'BDEDrive'
    )

    $partitionVars = @{}

    $Disk = Get-Disk -Number $DiskNumber
    $Partitions = Get-Partition -DiskNumber $DiskNumber

    if ($Disk.PartitionStyle -eq 'MBR')
    {
        foreach ($partition in $Partitions)
        {
            $partition | Get-Volume | % {
                $volume = $_

                switch ($_.FileSystemLabel) {
                    $OSVolumeLabel
                    {
                        $partitionVars.Add("OSPartLetter", [String]($volume.DriveLetter) + ':')
                        $partitionVars.Add("OSPartNumber", [String]($partition.PartitionNumber))
                        $partitionVars.Add("OSDisk", [String]($volume.DriveLetter) + ':')
                        $partitionVars.Add("OSPart", [String]($volume.DriveLetter) + ':')
                    }
                    $BDEVolumeLabel
                    {
                        $partitionVars.Add("BDEPartLetter", [String]($volume.DriveLetter) + ':')
                        $partitionVars.Add("BDEPartNumber", [String]($partition.PartitionNumber))
                        $partitionVars.Add("BootDisk", [String]($volume.DriveLetter) + ':')
                        $partitionVars.Add("BootPart", [String]($volume.DriveLetter) + ':')
                    }
                }
            }
        }
    }
    elseif ($Disk.PartitionStyle -eq 'GPT')
    {
        # See if there is more than one Basic partition.  If there is, find by volume label
        $basicPartitions = $Partitions | where { ($_.Type -eq 'Basic') }
        if ($basicPartitions.count -eq $null)
        {
            $hasMultipleBasicDisks = $false
        }
        else
        {
            $hasMultipleBasicDisks = $true
        }

        foreach ($partition in $Partitions)
        {
            switch ($partition.Type) {
                'Basic'
                {
                    if ($hasMultipleBasicDisks -eq $true) {
                        $partition | Get-Volume | % {
                            if ($_.FileSystemLabel -eq $OSVolumeLabel) {
                                $partitionVars.Add("OSPartLetter", [String]($partition.DriveLetter) + ':')
                                $partitionVars.Add("OSPartNumber", [String]($partition.PartitionNumber))
                                $partitionVars.Add("OSDisk", [String]($partition.DriveLetter) + ':')
                                $partitionVars.Add("OSPart", [String]($partition.DriveLetter) + ':')
                            }
                        }
                    }
                    else
                    {
                        $partitionVars.Add("OSPartLetter", [String]($partition.DriveLetter) + ':')
                        $partitionVars.Add("OSPartNumber", [String]($partition.PartitionNumber))
                        $partitionVars.Add("OSDisk", [String]($partition.DriveLetter) + ':')
                        $partitionVars.Add("OSPart", [String]($partition.DriveLetter) + ':')
                    }
                }

                'Recovery'
                {
                    $partitionVars.Add("RecoveryPartLetter", [String]($partition.DriveLetter) + ':')
                    $partitionVars.Add("RecoveryPartNumber", [String]($partition.PartitionNumber))
                }

                'Reserved'
                {
                    $partitionVars.Add("MSRPartLetter", [String]($partition.DriveLetter) + ':')
                    $partitionVars.Add("MSRPartNumber", [String]($partition.PartitionNumber))
                }

                'System'
                {
                    $partitionVars.Add("EFIPartLetter", [String]($partition.DriveLetter) + ':')
                    $partitionVars.Add("EFIPartNumber", [String]($partition.PartitionNumber))
                    $partitionVars.Add("BootDisk", [String]($partition.DriveLetter) + ':')
                    $partitionVars.Add("BootPart", [String]($partition.DriveLetter) + ':')
                }
            }
        }
    }
    else
    {
        Out-TSLogEntry -LogMsg "Unsupported Disk type: $($partition.Type)." -LogType LogTypeError
    }
    
    Set-TSVariables -Variables $partitionVars -PSVariables
}


##########################################################################################
# Initialize Module
##########################################################################################


$TSEnv = (Get-TSEnvironmentObject)
$TSLogPath = (Get-TSLogPath)

If ($MyInvocation.PSCommandPath -ne $null)
{
    $CallingScriptPath = $MyInvocation.PSCommandPath
    $CallingScriptFolder = Split-Path -parent $CallingScriptPath
    $iniFileModule = Join-Path $CallingScriptFolder "IniFile.psm1"
}
ElseIf ($MyInvocation.MyCommand.Path -ne $null)
{
    $CallingScriptPath = $MyInvocation.MyCommand.Path
    $CallingScriptFolder = Split-Path -parent $CallingScriptPath
    $iniFileModule = Join-Path $CallingScriptFolder "IniFile.psm1"
}
Else
{
    $iniFileModule = ".\IniFile.psm1"
}
Import-Module $iniFileModule -Force

Set-TSVariables -Variables $(Get-AssetInfo) -PSVariables
Set-TSVariables -Variables $(Get-OSInfo) -PSVariables

Export-ModuleMember -Function * -Alias * -Cmdlet * -Variable *