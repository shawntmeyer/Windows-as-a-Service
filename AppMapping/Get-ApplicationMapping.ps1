<#

	.SYNOPSIS

		Function to create a SCCM Task Sequence Dynamic Application Variable based on Application Mapping against Add/Remove Programs Display Name.

	.PARAMETER BaseVariableName

		Specifies the "Base Variable Name" present in the task "Install Application" of the Task Sequence.

		(In the 'Install application according to dynamic variable list' section)

	.PARAMETER ApplicationList

		Specifies the full path to a CSV file with Application Display Names in Add/Remove Programs and the corresponding
        Application Name in SCCM. This can be a relative path (i.e., .\ApplicationMapping.csv) or a literal path (i.e., http://webserver.domain.com/applicationmapping.csv)

    .PARAMETER Exact
	    
        Specifies that the named application must be matched using the exact name. Performs a contains match on the application display name by default.
    
    .PARAMETER WildCard
	    
        Specifies that the named application must be matched using a wildcard search. Performs a contains match on the application display name by default.
    
    .PARAMETER RegEx
	
        Specifies that the named application must be matched using a regular expression search. Performs a contains match on the application display name by default.
	
	.EXAMPLE

		Get-ApplicationMapping -BaseVariableName "Applications" -ApplicationList "ApplicationMapping.csv"

    .EXAMPLE

        Get-ApplicationMapping -BaseVariableName "Applications" -ApplicationList "http://webserver.contoso.com/osd/applicationmapping.csv")

	.NOTES

		Shawn Meyer, Microsoft PFE
        12/17/2018 - Added the logging of unmatched apps to a new text file called unmatchedapps.txt in the resolved log directory.
#>


PARAM
    (
        [String]$BaseVariableName='Applications',		
        $ApplicationList=".\ApplicationMapping.csv",
        [switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false
	)


#region Global Variables
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path $scriptPath
$callingScript =[io.path]::GetFileNameWithoutExtension($myInvocation.MyCommand.Name)
$logFile = "$callingScript.log"
#endregion

#region Functions

#region Function Get-LogDir
function Get-LogDir
{
  try
  {
    $TSEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction 'Stop'
    if ($tsenv.Value("LogPath") -ne "")
    {
      $logDir = $tsenv.Value("LogPath")
    }
    else
    {
      $logDir = $tsenv.Value("_SMSTSLogPath")
    }
  }
  catch
  {
    $logDir = $env:TEMP
  }
  return $logDir
}
#endregion

#region Function Write-FunctionHeaderOrFooter
Function Write-FunctionHeaderOrFooter
{
    <#
    .SYNOPSIS
	    Write the function header or footer to the log upon first entering or exiting a function.
    .DESCRIPTION
	    Write the "Function Start" message, the bound parameters the function was invoked with, or the "Function End" message when entering or exiting a function.
	    Messages are debug messages so will only be logged if LogDebugMessage option is enabled in XML config file.
    .PARAMETER CmdletName
	    The name of the function this function is invoked from.
    .PARAMETER CmdletBoundParameters
	    The bound parameters of the function this function is invoked from.
    .PARAMETER Header
	    Write the function header.
    .PARAMETER Footer
	    Write the function footer.
    .EXAMPLE
	    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    .EXAMPLE
	    Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    .NOTES
	    This is an internal script function and should typically not be called directly.
    .LINK

    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$CmdletName,
		[Parameter(Mandatory=$true,ParameterSetName='Header')]
		[AllowEmptyCollection()]
		[hashtable]$CmdletBoundParameters,
		[Parameter(Mandatory=$true,ParameterSetName='Header')]
		[switch]$Header,
		[Parameter(Mandatory=$true,ParameterSetName='Footer')]
		[switch]$Footer
	)
	
	If ($Header) {
		Write-Log -Message 'Function Start' -Source ${CmdletName} -DebugMessage
		
		## Get the parameters that the calling function was invoked with
		[string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
		If ($CmdletBoundParameters) {
			Write-Log -Message "Function invoked with bound parameter(s): `n$CmdletBoundParameters" -Source ${CmdletName} -DebugMessage
		}
		Else {
			Write-Log -Message 'Function invoked without any bound parameters.' -Source ${CmdletName} -DebugMessage
		}
	}
	ElseIf ($Footer) {
		Write-Log -Message 'Function End' -Source ${CmdletName} -DebugMessage
	}
}
#endregion

#region Function Write-Log
Function Write-Log
{
    <#
    .SYNOPSIS
	    Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
    .DESCRIPTION
	    Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
    .PARAMETER Message
	    The message to write to the log file or output to the console.
    .PARAMETER Severity
	    Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
	    Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
    .PARAMETER Source
	    The source of the message being logged.
    .PARAMETER ScriptSection
	    The heading for the portion of the script that is being executed. Default is: $script:installPhase.
    .PARAMETER LogType
	    Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.
    .PARAMETER LogFileDirectory
	    Set the directory where the log file will be saved.
    .PARAMETER LogFileName
	    Set the name of the log file.
    .PARAMETER MaxLogFileSizeMB
	    Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
    .PARAMETER WriteHost
	    Write the log message to the console.
    .PARAMETER ContinueOnError
	    Suppress writing log message to console on failure to write message to log file. Default is: $true.
    .PARAMETER PassThru
	    Return the message that was passed to the function
    .PARAMETER DebugMessage
	    Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
    .PARAMETER LogDebugMessage
	    Debug messages only get logged if this parameter is set to $true in the config XML file.
    .EXAMPLE
	    Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
    .EXAMPLE
	    Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
    .NOTES
    .LINK

    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[AllowEmptyCollection()]
		[Alias('Text')]
		[string[]]$Message,
		[Parameter(Mandatory=$false,Position=1)]
		[ValidateRange(1,3)]
		[int16]$Severity = 1,
		[Parameter(Mandatory=$false,Position=2)]
		[ValidateNotNull()]
		[string]$Source = '',
		[Parameter(Mandatory=$false,Position=3)]
		[ValidateNotNullorEmpty()]
		[string]$ScriptSection=$Script:Phase,
		[Parameter(Mandatory=$false,Position=4)]
		[ValidateSet('CMTrace','Legacy')]
		[string]$LogType = 'CMTrace',
		[Parameter(Mandatory=$false,Position=5)]
		[ValidateNotNullorEmpty()]
		[string]$LogFileDirectory = $LogDirectory,
		[Parameter(Mandatory=$false,Position=6)]
		[ValidateNotNullorEmpty()]
		[string]$LogFileName = $logFile,
		[Parameter(Mandatory=$false,Position=7)]
		[ValidateNotNullorEmpty()]
		[decimal]$MaxLogFileSizeMB = 10,
		[Parameter(Mandatory=$false,Position=8)]
		[ValidateNotNullorEmpty()]
		[boolean]$WriteHost,
		[Parameter(Mandatory=$false,Position=9)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true,
		[Parameter(Mandatory=$false,Position=10)]
		[switch]$PassThru = $false,
		[Parameter(Mandatory=$false,Position=11)]
		[switch]$DebugMessage = $false,
		[Parameter(Mandatory=$false,Position=12)]
		[boolean]$LogDebugMessage        
	)
	
	Begin {
		## Get the name of this function
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		
		## Logging Variables
		#  Log file date/time
		[string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
		[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
		If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) { [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes }
		[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
		#  Initialize variables
		[boolean]$ExitLoggingFunction = $false
		If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) { $DisableLogging = $false }
		#  Check if the script section is defined
		[boolean]$ScriptSectionDefined = [boolean](-not [string]::IsNullOrEmpty($ScriptSection))
		#  Get the file name of the source script
		Try {
			If ($script:MyInvocation.Value.ScriptName) {
				[string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
			}
			Else {
				[string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
			}
		}
		Catch {
			$ScriptSource = ''
		}
		
		## Create script block for generating CMTrace.exe compatible log entry
		[scriptblock]$CMTraceLogString = {
			Param (
				[string]$lMessage,
				[string]$lSource,
				[int16]$lSeverity
			)
			"<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
		}
		
		## Create script block for writing log entry to the console
		[scriptblock]$WriteLogLineToHost = {
			Param (
				[string]$lTextLogLine,
				[int16]$lSeverity
			)
			If ($WriteHost) {
				#  Only output using color options if running in a host which supports colors.
				If ($Host.UI.RawUI.ForegroundColor) {
					Switch ($lSeverity) {
						3 { Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black' }
						2 { Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
						1 { Write-Host -Object $lTextLogLine }
					}
				}
				#  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
				Else {
					Write-Output -InputObject $lTextLogLine
				}
			}
		}
		
		## Create the directory where the log file will be saved
		If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
			Try {
				$null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
			}
			Catch {
				[boolean]$ExitLoggingFunction = $true
				#  If error creating directory, write message to console
				If (-not $ContinueOnError) {
					Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
				}
				Return
			}
		}
		
		## Assemble the fully qualified path to the log file
		[string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
	}
	Process {
	
		ForEach ($Msg in $Message) {
			## If the message is not $null or empty, create the log entry for the different logging methods
			[string]$CMTraceMsg = ''
			[string]$ConsoleLogLine = ''
			[string]$LegacyTextLogLine = ''
			If ($Msg) {
				#  Create the CMTrace log message
				If ($ScriptSectionDefined) { [string]$CMTraceMsg = "[$ScriptSection] :: $Msg" }
				
				#  Create a Console and Legacy "text" log entry
				[string]$LegacyMsg = "[$LogDate $LogTime]"
				If ($ScriptSectionDefined) { [string]$LegacyMsg += " [$ScriptSection]" }
				If ($Source) {
					[string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
					Switch ($Severity) {
						3 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg" }
						2 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg" }
						1 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg" }
					}
				}
				Else {
					[string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
					Switch ($Severity) {
						3 { [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg" }
						2 { [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg" }
						1 { [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg" }
					}
				}
			}
			
			## Execute script block to create the CMTrace.exe compatible log entry
			[string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity
			
			## Choose which log type to write to file
			If ($LogType -ieq 'CMTrace') {
				[string]$LogLine = $CMTraceLogLine
			}
			Else {
				[string]$LogLine = $LegacyTextLogLine
			}
			
			## Write the log entry to the log file if logging is not currently disabled
            Try {
				$LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
			}
			Catch {
				If (-not $ContinueOnError) {
					Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
				}
			}
						
			## Execute script block to write the log entry to the console if $WriteHost is $true
			& $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
		}
	}
	End {
		## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
		Try {
			If (-not $ExitLoggingFunction) {
				[IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
				[decimal]$LogFileSizeMB = $LogFile.Length/1MB
				If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
					## Change the file extension to "lo_"
					[string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
					[hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
					
					## Log message about archiving the log file
					$ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
					Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
					
					## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
					Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'
					
					## Start new log file and Log message about archiving the old log file
					$NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
					Write-Log -Message $NewLogMessage @ArchiveLogParams
				}
			}
		}
		Catch {
			## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
		}
		Finally {
			If ($PassThru) { Write-Output -InputObject $Message }
		}
	}
}
#endregion Function Write-Log

#region Function Resolve-Error
Function Resolve-Error {
<#
.SYNOPSIS
	Enumerate error record details.
.DESCRIPTION
	Enumerate an error record, or a collection of error record, properties. By default, the details for the last error will be enumerated.
.PARAMETER ErrorRecord
	The error record to resolve. The default error record is the latest one: $global:Error[0]. This parameter will also accept an array of error records.
.PARAMETER Property
	The list of properties to display from the error record. Use "*" to display all properties.
	Default list of error properties is: Message, FullyQualifiedErrorId, ScriptStackTrace, PositionMessage, InnerException
.PARAMETER GetErrorRecord
	Get error record details as represented by $_.
.PARAMETER GetErrorInvocation
	Get error record invocation information as represented by $_.InvocationInfo.
.PARAMETER GetErrorException
	Get error record exception details as represented by $_.Exception.
.PARAMETER GetErrorInnerException
	Get error record inner exception details as represented by $_.Exception.InnerException. Will retrieve all inner exceptions if there is more than one.
.EXAMPLE
	Resolve-Error
.EXAMPLE
	Resolve-Error -Property *
.EXAMPLE
	Resolve-Error -Property InnerException
.EXAMPLE
	Resolve-Error -GetErrorInvocation:$false
.NOTES
.LINK
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[AllowEmptyCollection()]
		[array]$ErrorRecord,
		[Parameter(Mandatory=$false,Position=1)]
		[ValidateNotNullorEmpty()]
		[string[]]$Property = ('Message','InnerException','FullyQualifiedErrorId','ScriptStackTrace','PositionMessage'),
		[Parameter(Mandatory=$false,Position=2)]
		[switch]$GetErrorRecord = $true,
		[Parameter(Mandatory=$false,Position=3)]
		[switch]$GetErrorInvocation = $true,
		[Parameter(Mandatory=$false,Position=4)]
		[switch]$GetErrorException = $true,
		[Parameter(Mandatory=$false,Position=5)]
		[switch]$GetErrorInnerException = $true
	)
	
	Begin {
		## If function was called without specifying an error record, then choose the latest error that occurred
		If (-not $ErrorRecord) {
			If ($global:Error.Count -eq 0) {
				#Write-Warning -Message "The `$Error collection is empty"
				Return
			}
			Else {
				[array]$ErrorRecord = $global:Error[0]
			}
		}
		
		## Allows selecting and filtering the properties on the error object if they exist
		[scriptblock]$SelectProperty = {
			Param (
				[Parameter(Mandatory=$true)]
				[ValidateNotNullorEmpty()]
				$InputObject,
				[Parameter(Mandatory=$true)]
				[ValidateNotNullorEmpty()]
				[string[]]$Property
			)
			
			[string[]]$ObjectProperty = $InputObject | Get-Member -MemberType '*Property' | Select-Object -ExpandProperty 'Name'
			ForEach ($Prop in $Property) {
				If ($Prop -eq '*') {
					[string[]]$PropertySelection = $ObjectProperty
					Break
				}
				ElseIf ($ObjectProperty -contains $Prop) {
					[string[]]$PropertySelection += $Prop
				}
			}
			Write-Output -InputObject $PropertySelection
		}
		
		#  Initialize variables to avoid error if 'Set-StrictMode' is set
		$LogErrorRecordMsg = $null
		$LogErrorInvocationMsg = $null
		$LogErrorExceptionMsg = $null
		$LogErrorMessageTmp = $null
		$LogInnerMessage = $null
	}
	Process {
		If (-not $ErrorRecord) { Return }
		ForEach ($ErrRecord in $ErrorRecord) {
			## Capture Error Record
			If ($GetErrorRecord) {
				[string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord -Property $Property
				$LogErrorRecordMsg = $ErrRecord | Select-Object -Property $SelectedProperties
			}
			
			## Error Invocation Information
			If ($GetErrorInvocation) {
				If ($ErrRecord.InvocationInfo) {
					[string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.InvocationInfo -Property $Property
					$LogErrorInvocationMsg = $ErrRecord.InvocationInfo | Select-Object -Property $SelectedProperties
				}
			}
			
			## Capture Error Exception
			If ($GetErrorException) {
				If ($ErrRecord.Exception) {
					[string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrRecord.Exception -Property $Property
					$LogErrorExceptionMsg = $ErrRecord.Exception | Select-Object -Property $SelectedProperties
				}
			}
			
			## Display properties in the correct order
			If ($Property -eq '*') {
				#  If all properties were chosen for display, then arrange them in the order the error object displays them by default.
				If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
				If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
				If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
			}
			Else {
				#  Display selected properties in our custom order
				If ($LogErrorExceptionMsg) { [array]$LogErrorMessageTmp += $LogErrorExceptionMsg }
				If ($LogErrorRecordMsg) { [array]$LogErrorMessageTmp += $LogErrorRecordMsg }
				If ($LogErrorInvocationMsg) { [array]$LogErrorMessageTmp += $LogErrorInvocationMsg }
			}
			
			If ($LogErrorMessageTmp) {
				$LogErrorMessage = 'Error Record:'
				$LogErrorMessage += "`n-------------"
				$LogErrorMsg = $LogErrorMessageTmp | Format-List | Out-String
				$LogErrorMessage += $LogErrorMsg
			}
			
			## Capture Error Inner Exception(s)
			If ($GetErrorInnerException) {
				If ($ErrRecord.Exception -and $ErrRecord.Exception.InnerException) {
					$LogInnerMessage = 'Error Inner Exception(s):'
					$LogInnerMessage += "`n-------------------------"
					
					$ErrorInnerException = $ErrRecord.Exception.InnerException
					$Count = 0
					
					While ($ErrorInnerException) {
						[string]$InnerExceptionSeperator = '~' * 40
						
						[string[]]$SelectedProperties = & $SelectProperty -InputObject $ErrorInnerException -Property $Property
						$LogErrorInnerExceptionMsg = $ErrorInnerException | Select-Object -Property $SelectedProperties | Format-List | Out-String
						
						If ($Count -gt 0) { $LogInnerMessage += $InnerExceptionSeperator }
						$LogInnerMessage += $LogErrorInnerExceptionMsg
						
						$Count++
						$ErrorInnerException = $ErrorInnerException.InnerException
					}
				}
			}
			
			If ($LogErrorMessage) { $Output = $LogErrorMessage }
			If ($LogInnerMessage) { $Output += $LogInnerMessage }
			
			Write-Output -InputObject $Output
			
			If (Test-Path -LiteralPath 'variable:Output') { Clear-Variable -Name 'Output' }
			If (Test-Path -LiteralPath 'variable:LogErrorMessage') { Clear-Variable -Name 'LogErrorMessage' }
			If (Test-Path -LiteralPath 'variable:LogInnerMessage') { Clear-Variable -Name 'LogInnerMessage' }
			If (Test-Path -LiteralPath 'variable:LogErrorMessageTmp') { Clear-Variable -Name 'LogErrorMessageTmp' }
		}
	}
	End {
	}
}
#endregion

#endregion Functions

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------#
#region main

$LogDirectory = Get-LogDir

$Script:Phase='Online or Offline?'

# Determine if Offline or Online

if ($env:SYSTEMDRIVE -eq "X:")
{
    $script:Offline = $true
    Write-Log "Script is running in WinPE. Now searching for Offline Windows Drive." -source 'Main()'

    # Find Windows
    $drives = get-volume | ? {-not [String]::IsNullOrWhiteSpace($_.DriveLetter) } | ? {$_.DriveType -eq 'Fixed'} | ? {$_.DriveLetter -ne 'X'}
    $drives | ? { Test-Path "$($_.DriveLetter):\Windows\System32"} | % { $script:OfflinePath = "$($_.DriveLetter):\" }
    Write-Log "Eligible offline drive found: $script:OfflinePath" -ScriptSection $Script:Phase -Source Main
    
    $SoftwareHiveFile = $Script:OfflinePath + "Windows\System32\config\SOFTWARE"

    If (-not (Test-Path $SoftwareHiveFile) )
    {
        Write-Log "Not able to find offline Software Hive File. Exiting Script." -Severity 2 -Source 'Main()'
        Exit(0)
    }
    
    Write-Log "Loading Software Hive File to WINPE registry." -Source 'Main()'

    Reg Load "HKLM\Offline" "$SoftwareHiveFile"
    [string[]]$regKeyApplications = 'HKLM:Offline\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:Offline\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
}
else
{
    Write-Log "Running in the full OS." -ScriptSection $Script:Phase -Source Main
    $script:Offline = $false
    [string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
}

## Check if script is running from a SCCM Task Sequence
$Script:Phase = 'Is Task Sequence?'
Try
{
	$TSEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction 'Stop'
	Write-Log -Message "Script is currently running from a SCCM Task Sequence." -Source Main
	$runningTaskSequence = $true
}
Catch
{
	Write-Log -Message "Script is not currently running from a Task Sequence." -Source Main
	$runningTaskSequence = $false
}

$Script:Phase = 'Get Installed Applications'
 ## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
 ## Add them to an array list for searching later.

[psobject[]]$regKeyApplication = @()

ForEach ($regKey in $regKeyApplications)
{
    If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath')
    {
        Write-Log "Now Enumerating the installed applications in $regKey" -Source 'Main()'
        # create a Powershell Object containing all the child keys of the 'Uninstall' Registry Paths.
		[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
		ForEach ($UninstallKeyApp in $UninstallKeyApps)
        {
			Try
            {
				[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
                # Add current registry object to $RegKeyApplication Object
				If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
			}
			Catch
            {
				Write-Output "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]"
				Continue
			}
		}
    }
}

If ($ErrorUninstallKeyPath)
{
    Write-Log -Message "The following error(s) took place while enumerating installed applications from the registry. `n$(Resolve-Error -ErrorRecord $ErrorUninstallKeyPath)" -Severity 2 -Source 'Main()'
}

## Create an array to hold the sanitized displaynames of all installed apps.

[string[]]$InstalledApps = @()

ForEach ($regKeyApp in $regKeyApplication)
{
    Try
    {
	    [string]$appDisplayName = ''
				
	    ## Bypass any updates or hotfixes
	    If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
	    If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
	    If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
	    If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
				
		## Remove any control characters which may interfere with logging and creating file path names from these variables
		$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''	
        $InstalledApps += $appDisplayName
    }
    Catch
    {
        Write-Log -Message "Failed to resolve application details from registry for [$appDisplayName]. `n$(Resolve-Error)" -Severity 3 -Source 'Main()'
		Continue
    }
}

Write-Log -message "Found a total of $($installedApps.count) on System" -Source 'Main()'

$Script:Phase = 'Load Mapping List'

If ($ApplicationList.ToUpper().Contains("HTTP"))
{
    Write-Log "Downloading Application Mapping CSV from $ApplicationList" -Source 'Main()'
    $webclient=New-Object Net.WebClient
    $WebClient.DownloadFile("$ApplicationList", "$logDirectory\ApplicationMapping.csv")
    # Invoke-WebRequest -Uri $ApplicationList -Outfile "$logDirectory\ApplicationMapping.csv"     ## Requires PS 3.0+
    $ApplicationList = "$logDirectory\ApplicationMapping.csv"
}

Write-Log "Importing AppMappingList from `"$ApplicationList`"." -Source 'Main()'

$appMappingList = Import-CSV -Path $ApplicationList

$Script:Phase = 'Match Apps'

# Build ArrayList to store matched Apps from Get-InstalledApplication Function
$matchedApps = New-Object System.Collections.ArrayList
# Create Unmatched apps file.
$unmatchedApps="$LogDirectory\UnmappedApps.txt"
New-Item -Path $unmatchedApps -ItemType File -Force

ForEach($application in $appMappingList)
{   
    Write-Log -Message "Application searh term = $($application.arpname)" -Source 'Main()'
    ForEach($InstalledApp in $InstalledApps)
    {
        $applicationMatched = $false 
        Write-Log -Message "Installed App Display Name = $installedApp" -Source 'Main()'
        If ($exact)
        {
            #  Check for an exact application name match
		    If ($InstalledApp -eq $application.ArpName)
            {
                $applicationMatched = $true
			    Write-Log -Message "$installedApp is an exact match for search term [$($application.arpname)]." -Source 'Main()'
		    }
	    }
	    ElseIf ($WildCard)
        {
	        #  Check for wildcard application name match
	        If ($InstalledApp -like $application.ArpName)
            {
                $applicationMatched = $true
			    Write-Log -Message "$InstalledApp is a wildcard match for search term [$($application.arpname)]." -Source 'Main()'
		    }
	    }
	    ElseIf ($RegEx)
        {
	        #  Check for a regex application name match
		    If ($InstalledApp -match $application.ArpName)
            {
		        $applicationMatched = $true
			    Write-Log -Message "$InstalledApp is a regex match for search term [$($application.arpname)]." -Source 'Main()'
		    }
	    }
	    #  Check for a contains application name match
	    ElseIf ($InstalledApp -match [regex]::Escape($application.ArpName))
        {
			$applicationMatched = $true
			Write-Log -Message "$InstalledApp is contains the search term [$($application.arpname)]." -Source 'Main()'
        }

        If ($ApplicationMatched -eq $True)
        {
            Write-Log "Adding Configuration Manager App `"$($Application.Application)`" to list of Apps to be installed." -Source 'Main()'
            $matchedApps.Add($Application.Application)
        }
        Else
        {
            Add-Content $unmatchedapps "$InstalledApp`r"
        }
    }
}

Write-Log "Matched $($MatchedApps.Count) Apps from CSV to installed apps" -Source Main
If ($matchedApps.Count -ge 1)
{

    $Counter = 1

    ForEach ($App in $MatchedApps)
    {
        $Variable = "$BaseVariableName{0:00}" -f $Counter
        If ($runningTaskSequence)
        {
            $TSEnv.value("$Variable") = "$App"
            Write-Log "Set Task Sequence Variable `"$Variable`" = to `"$App`"." -Source Main
        }
        Else
        {
            Write-Host "$Variable = $App"
        }
    
        [void]$Counter++
    }
}
Else
{
    Write-Log "No Matching Applications found on system." -Source Main
}

#Cleanup
$regKeyApplications = $null
$regKey = $null
$regKeyApp = $null
$regKeyApplication = $null
$regKeyApplicationProps = $null
$UninstallKeyApps  = $null
$UninstallKeyApp = $null
$softwareHiveFile = $null

If ($script:Offline)
{
    [GC]::collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -s 5
    Reg Unload HKLM\Offline
}

Write-Log "Exiting Script." -Source Main

#endregion main