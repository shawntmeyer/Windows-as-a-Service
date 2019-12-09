<#
Name:  Windows 10 User Interface Branding Script 

Version:  1.4 (Apr 2017)

Purpose:  This script is designed to apply system branding based upon settings defined in the MDT customsettings.ini file

Author(s):  Microsoft Services

Change Log:
1.0

Instructions/Notes:  

LockScreenImage: Defines lockscreen image (e.g. Lockscreen.jpg)
WallpaperImage: Defines wallpaper image (e.g. Wallpaper.jpg)
Manufacturer: Name of Manufacturer in system properties GUI
OEMImage: Name of oemlogo icon in system properties GUI
InstallModel: Model in system properties GUI
SupportURL: Support website in system properties GUI
SupportHours: Support Hours in system properties GUI
SupportPhone: Suport Phone in system properties GUI
myLogPath: Defines log path
myLogName: Defines log name

#>

param(
[parameter(Mandatory=$false)][boolean]$userLogos=$false,
[parameter(Mandatory=$false)][boolean]$LockScreen=$true,
[parameter(Mandatory=$false)][boolean]$Wallpaper=$true,
[parameter(Mandatory=$false)][boolean]$StartMenu=$true,
[parameter(Mandatory=$false)][string]$OEMImage="NOVALUE",
[parameter(Mandatory=$false)][string]$Manufacturer="NOVALUE",
[parameter(Mandatory=$false)][string]$SupportURL="NOVALUE",
[parameter(Mandatory=$false)][string]$SupportPhone="NOVALUE",
[parameter(Mandatory=$false)][string]$SupportHours="NOVALUE",
[parameter(Mandatory=$false)][string]$InstallModel="NOVALUE"

)

#Set Variables
$scriptPath = $MyInvocation.MyCommand.Path
$scriptDir = Split-Path $scriptPath
$callingScript = [string]$myInvocation.MyCommand.Name
$LogFile = [io.path]::GetFileNameWithoutExtension($callingScript) + ".log"

# Temporarily change to the script folder
Push-Location $scriptDir

#region Functions
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
    $logDir = $env:TEMP
  }
  return $logDir
}

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
		[string]$ScriptSection=$Phase,
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
		## Exit function if logging is disabled
		If ($ExitLoggingFunction) { Return }
		
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
			If (-not $DisableLogging) {
				Try {
					$LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
				}
				Catch {
					If (-not $ContinueOnError) {
						Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
					}
				}
			}
			
			## Execute script block to write the log entry to the console if $WriteHost is $true
			& $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
		}
	}
	End {
		## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
		Try {
			If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
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

Function Resolve-Error
{
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
	http://psappdeploytoolkit.com
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

Function Execute-Process
{
    <#
    .SYNOPSIS
	    Execute a process with optional arguments, working directory, window style.
    .DESCRIPTION
	    Executes a process, e.g. a file included in the Files directory of the App Deploy Toolkit, or a file on the local machine.
	    Provides various options for handling the return codes (see Parameters).
    .PARAMETER Path
	    Path to the file to be executed. If the file is located directly in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
	    Otherwise, the full path of the file must be specified. If the files is in a subdirectory of "Files", use the "$dirFiles" variable as shown in the example.
    .PARAMETER Parameters
	    Arguments to be passed to the executable
    .PARAMETER WindowStyle
	    Style of the window of the process executed. Options: Normal, Hidden, Maximized, Minimized. Default: Normal.
	    Note: Not all processes honor the "Hidden" flag. If it it not working, then check the command line options for the process being executed to see it has a silent option.
    .PARAMETER CreateNoWindow
	    Specifies whether the process should be started with a new window to contain it. Default is false.
    .PARAMETER WorkingDirectory
	    The working directory used for executing the process. Defaults to the directory of the file being executed.
    .PARAMETER NoWait
	    Immediately continue after executing the process.
    .PARAMETER PassThru
	    Returns ExitCode, STDOut, and STDErr output from the process.
    .PARAMETER WaitForMsiExec
	    Sometimes an EXE bootstrapper will launch an MSI install. In such cases, this variable will ensure that
	    that this function waits for the msiexec engine to become available before starting the install.
    .PARAMETER MsiExecWaitTime
	    Specify the length of time in seconds to wait for the msiexec engine to become available. Default: 600 seconds (10 minutes).
    .PARAMETER IgnoreExitCodes
	    List the exit codes to ignore.
    .PARAMETER ContinueOnError
	    Continue if an exit code is returned by the process that is not recognized by the App Deploy Toolkit. Default: $false.
    .EXAMPLE
	    Execute-Process -Path 'uninstall_flash_player_64bit.exe' -Parameters '/uninstall' -WindowStyle 'Hidden'
	    If the file is in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
    .EXAMPLE
	    Execute-Process -Path "$dirFiles\Bin\setup.exe" -Parameters '/S' -WindowStyle 'Hidden'
    .EXAMPLE
	    Execute-Process -Path 'setup.exe' -Parameters '/S' -IgnoreExitCodes '1,2'
    .EXAMPLE
	    Execute-Process -Path 'setup.exe' -Parameters "-s -f2`"$configToolkitLogDir\$installName.log`""
	    Launch InstallShield "setup.exe" from the ".\Files" sub-directory and force log files to the logging folder.
    .EXAMPLE
	    Execute-Process -Path 'setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$configToolkitLogDir\$installName.log`""
	    Launch InstallShield "setup.exe" with embedded MSI and force log files to the logging folder.
    .NOTES
    .LINK
	    
    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[Alias('FilePath')]
		[ValidateNotNullorEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$false)]
		[Alias('Arguments')]
		[ValidateNotNullorEmpty()]
		[string[]]$Parameters,
		[Parameter(Mandatory=$false)]
		[ValidateSet('Normal','Hidden','Maximized','Minimized')]
		[Diagnostics.ProcessWindowStyle]$WindowStyle = 'Normal',
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$CreateNoWindow = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$WorkingDirectory,
		[Parameter(Mandatory=$false)]
		[switch]$NoWait = $false,
		[Parameter(Mandatory=$false)]
		[switch]$PassThru = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WaitForMsiExec = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds 600),
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$IgnoreExitCodes,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $false
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			$private:returnCode = $null
			
			## Validate and find the fully qualified path for the $Path variable.
			If (([IO.Path]::IsPathRooted($Path)) -and ([IO.Path]::HasExtension($Path))) {
				Write-Log -Message "[$Path] is a valid fully qualified path, continue." -Source ${CmdletName}
				If (-not (Test-Path -LiteralPath $Path -PathType 'Leaf' -ErrorAction 'Stop')) {
					Throw "File [$Path] not found."
				}
			}
			Else {
				#  The first directory to search will be the 'Files' subdirectory of the script directory
				[string]$PathFolders = $dirFiles
				#  Add the current location of the console (Windows always searches this location first)
				[string]$PathFolders = $PathFolders + ';' + (Get-Location -PSProvider 'FileSystem').Path
				#  Add the new path locations to the PATH environment variable
				$env:PATH = $PathFolders + ';' + $env:PATH
				
				#  Get the fully qualified path for the file. Get-Command searches PATH environment variable to find this value.
				[string]$FullyQualifiedPath = Get-Command -Name $Path -CommandType 'Application' -TotalCount 1 -Syntax -ErrorAction 'Stop'
				
				#  Revert the PATH environment variable to it's original value
				$env:PATH = $env:PATH -replace [regex]::Escape($PathFolders + ';'), ''
				
				If ($FullyQualifiedPath) {
					Write-Log -Message "[$Path] successfully resolved to fully qualified path [$FullyQualifiedPath]." -Source ${CmdletName}
					$Path = $FullyQualifiedPath
				}
				Else {
					Throw "[$Path] contains an invalid path or file name."
				}
			}
			
			## Set the Working directory (if not specified)
			If (-not $WorkingDirectory) { $WorkingDirectory = Split-Path -Path $Path -Parent -ErrorAction 'Stop' }
			
			## If MSI install, check to see if the MSI installer service is available or if another MSI install is already underway.
			## Please note that a race condition is possible after this check where another process waiting for the MSI installer
			##  to become available grabs the MSI Installer mutex before we do. Not too concerned about this possible race condition.
			If (($Path -match 'msiexec') -or ($WaitForMsiExec)) {
				[boolean]$MsiExecAvailable = Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds $MsiExecWaitTime.TotalMilliseconds
				Start-Sleep -Seconds 1
				If (-not $MsiExecAvailable) {
					#  Default MSI exit code for install already in progress
					[int32]$returnCode = 1618
					Throw 'Please complete in progress MSI installation before proceeding with this install.'
				}
			}
			
			Try {
				## Disable Zone checking to prevent warnings when running executables
				$env:SEE_MASK_NOZONECHECKS = 1
				
				## Using this variable allows capture of exceptions from .NET methods. Private scope only changes value for current function.
				$private:previousErrorActionPreference = $ErrorActionPreference
				$ErrorActionPreference = 'Stop'
				
				## Define process
				$processStartInfo = New-Object -TypeName 'System.Diagnostics.ProcessStartInfo' -ErrorAction 'Stop'
				$processStartInfo.FileName = $Path
				$processStartInfo.WorkingDirectory = $WorkingDirectory
				$processStartInfo.UseShellExecute = $false
				$processStartInfo.ErrorDialog = $false
				$processStartInfo.RedirectStandardOutput = $true
				$processStartInfo.RedirectStandardError = $true
				$processStartInfo.CreateNoWindow = $CreateNoWindow
				If ($Parameters) { $processStartInfo.Arguments = $Parameters }
				If ($windowStyle) { $processStartInfo.WindowStyle = $WindowStyle }
				$process = New-Object -TypeName 'System.Diagnostics.Process' -ErrorAction 'Stop'
				$process.StartInfo = $processStartInfo
				
				## Add event handler to capture process's standard output redirection
				[scriptblock]$processEventHandler = { If (-not [string]::IsNullOrEmpty($EventArgs.Data)) { $Event.MessageData.AppendLine($EventArgs.Data) } }
				$stdOutBuilder = New-Object -TypeName 'System.Text.StringBuilder' -ArgumentList ''
				$stdOutEvent = Register-ObjectEvent -InputObject $process -Action $processEventHandler -EventName 'OutputDataReceived' -MessageData $stdOutBuilder -ErrorAction 'Stop'
				
				## Start Process
				Write-Log -Message "Working Directory is [$WorkingDirectory]." -Source ${CmdletName}
				If ($Parameters) {
					If ($Parameters -match '-Command \&') {
						Write-Log -Message "Executing [$Path [PowerShell ScriptBlock]]..." -Source ${CmdletName}
					}
					Else{
						Write-Log -Message "Executing [$Path $Parameters]..." -Source ${CmdletName}
					}
				}
				Else {
					Write-Log -Message "Executing [$Path]..." -Source ${CmdletName}
				}
				[boolean]$processStarted = $process.Start()
				
				If ($NoWait) {
					Write-Log -Message 'NoWait parameter specified. Continuing without waiting for exit code...' -Source ${CmdletName}
				}
				Else {
					$process.BeginOutputReadLine()
					$stdErr = $($process.StandardError.ReadToEnd()).ToString() -replace $null,''
					
					## Instructs the Process component to wait indefinitely for the associated process to exit.
					$process.WaitForExit()
					
					## HasExited indicates that the associated process has terminated, either normally or abnormally. Wait until HasExited returns $true.
					While (-not ($process.HasExited)) { $process.Refresh(); Start-Sleep -Seconds 1 }
					
					## Get the exit code for the process
					[int32]$returnCode = $process.ExitCode
					
					## Unregister standard output event to retrieve process output
					If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'; $stdOutEvent = $null }
					$stdOut = $stdOutBuilder.ToString() -replace $null,''
					
					If ($stdErr.Length -gt 0) {
						Write-Log -Message "Standard error output from the process: $stdErr" -Severity 3 -Source ${CmdletName}
					}
				}
			}
			Finally {
				## Make sure the standard output event is unregistered
				If ($stdOutEvent) { Unregister-Event -SourceIdentifier $stdOutEvent.Name -ErrorAction 'Stop'}
				
				## Free resources associated with the process, this does not cause process to exit
				If ($process) { $process.Close() }
				
				## Re-enable Zone checking
				Remove-Item -LiteralPath 'env:SEE_MASK_NOZONECHECKS' -ErrorAction 'SilentlyContinue'
				
				If ($private:previousErrorActionPreference) { $ErrorActionPreference = $private:previousErrorActionPreference }
			}
			
			If (-not $NoWait) {
				## Check to see whether we should ignore exit codes
				$ignoreExitCodeMatch = $false
				If ($ignoreExitCodes) {
					#  Split the processes on a comma
					[int32[]]$ignoreExitCodesArray = $ignoreExitCodes -split ','
					ForEach ($ignoreCode in $ignoreExitCodesArray) {
						If ($returnCode -eq $ignoreCode) { $ignoreExitCodeMatch = $true }
					}
				}
				#  Or always ignore exit codes
				If ($ContinueOnError) { $ignoreExitCodeMatch = $true }
				
				## If the passthru switch is specified, return the exit code and any output from process
				If ($PassThru) {
					Write-Log -Message "Execution completed with exit code [$returnCode]." -Source ${CmdletName}
					[psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = $stdOut; StdErr = $stdErr }
					Write-Output -InputObject $ExecutionResults
				}
				ElseIf ($ignoreExitCodeMatch) {
					Write-Log -Message "Execution complete and the exit code [$returncode] is being ignored." -Source ${CmdletName}
				}
				ElseIf (($returnCode -eq 3010) -or ($returnCode -eq 1641)) {
					Write-Log -Message "Execution completed successfully with exit code [$returnCode]. A reboot is required." -Severity 2 -Source ${CmdletName}
					Set-Variable -Name 'msiRebootDetected' -Value $true -Scope 'Script'
				}
				ElseIf (($returnCode -eq 1605) -and ($Path -match 'msiexec')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the product is not currently installed." -Severity 3 -Source ${CmdletName}
				}
				ElseIf (($returnCode -eq -2145124329) -and ($Path -match 'wusa')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the Windows Update is not applicable to this system." -Severity 3 -Source ${CmdletName}
				}
				ElseIf (($returnCode -eq 17025) -and ($Path -match 'fullfile')) {
					Write-Log -Message "Execution failed with exit code [$returnCode] because the Office Update is not applicable to this system." -Severity 3 -Source ${CmdletName}
				}
				ElseIf ($returnCode -eq 0) {
					Write-Log -Message "Execution completed successfully with exit code [$returnCode]." -Source ${CmdletName}
				}
				Else {
					[string]$MsiExitCodeMessage = ''
					If ($Path -match 'msiexec') {
						[string]$MsiExitCodeMessage = Get-MsiExitCodeMessage -MsiExitCode $returnCode
					}
					
					If ($MsiExitCodeMessage) {
						Write-Log -Message "Execution failed with exit code [$returnCode]: $MsiExitCodeMessage" -Severity 3 -Source ${CmdletName}
					}
					Else {
						Write-Log -Message "Execution failed with exit code [$returnCode]." -Severity 3 -Source ${CmdletName}
					}
					Exit($returnCode)
				}
			}
		}
		Catch {
			If ([string]::IsNullOrEmpty([string]$returnCode)) {
				[int32]$returnCode = 60002
				Write-Log -Message "Function failed, setting exit code to [$returnCode]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
			Else {
				Write-Log -Message "Execution completed with exit code [$returnCode]. Function failed. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
			If ($PassThru) {
				[psobject]$ExecutionResults = New-Object -TypeName 'PSObject' -Property @{ ExitCode = $returnCode; StdOut = If ($stdOut) { $stdOut } Else { '' }; StdErr = If ($stdErr) { $stdErr } Else { '' } }
				Write-Output -InputObject $ExecutionResults
			}
			Else {
				Exit($returnCode)
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

Function Copy-File
{
    <#
    .SYNOPSIS
	    Copy a file or group of files to a destination path.
    .DESCRIPTION
	    Copy a file or group of files to a destination path.
    .PARAMETER Path
	    Path of the file to copy.
    .PARAMETER Destination
	    Destination Path of the file to copy.
    .PARAMETER Recurse
	    Copy files in subdirectories.
    .PARAMETER ContinueOnError
	    Continue if an error is encountered. Default is: $true.
    .EXAMPLE
	    Copy-File -Path "$dirSupportFiles\MyApp.ini" -Destination "$envWindir\MyApp.ini"
    .EXAMPLE
	    Copy-File -Path "$dirSupportFiles\*.*" -Destination "$envTemp\tempfiles"
	    Copy all of the files in a folder to a destination folder.
    .NOTES
    .LINK

    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Destination,
		[Parameter(Mandatory=$false)]
		[switch]$Recurse = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			If ((-not ([IO.Path]::HasExtension($Destination))) -and (-not (Test-Path -LiteralPath $Destination -PathType 'Container'))) {
				$null = New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop'
			}
			
			If ($Recurse) {
				Write-Log -Message "Copy file(s) recursively in path [$path] to destination [$destination]." -Source ${CmdletName}
				$null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
			}
			Else {
				Write-Log -Message "Copy file in path [$path] to destination [$destination]." -Source ${CmdletName}
				$null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'Stop'
			}
		}
		Catch {
			Write-Log -Message "Failed to copy file(s) in path [$path] to destination [$destination]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to copy file(s) in path [$path] to destination [$destination]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}

#endregion functions

$LogDirectory = Get-LogDir
$Phase = "Initialization"

Write-Log -message "Begin Step Branding Windows"

# Setup User/Guest Logos

If ($userLogos)
{
    $Phase = "User Logos"
    Write-Log -message "Copying User Icons to $env:ProgramData\Microsoft\User Account Pictures" -WriteHost $true
    Copy-File -Path "$ScriptDir\UserLogos\*.png" "$env:ProgramData\Microsoft\User Account Pictures"
    Copy-File -Path "$ScriptDir\UserLogos\*.bmp" "$env:ProgramData\Microsoft\User Account Pictures"
    Write-Log -message "Applying Local GPO for user icons." -WriteHost $true

    Execute-Process -Path "$ScriptDir\lgpo\lgpo.exe" -Parameters "/t `"$ScriptDir\userlogos\registry.txt`""
}

#Stage Lockscreen images
If ($LockScreen)
{
    $Phase = "Lock Screen"
    Write-Log -Message "Copying Lockscreen image to c:\windows\web\screen" -WriteHost $true
    Copy-File -Path "$ScriptDir\LockScreen\lockscreen.jpg" -Destination "$env:SystemRoot\Web\Screen"
    Write-Log -Message "Configuring Local GPO to set lockscreen image." -WriteHost $true
    Execute-Process -Path "$ScriptDir\LGPO\lgpo.exe" -Parameters "/t `"$ScriptDir\LockScreen\registry.txt`""
}

#Stage Wallpaper images
If ($Wallpaper)
{
    $Phase = "Desktop Wallpaper" 
    Write-Log -Message "Copying default desktop wallpaper images" -WriteHost $true
    Copy-File "$ScriptDir\WallPaper\wallpaper.jpg" -Destination "$env:SystemRoot\Web\Wallpaper\Windows"
    Copy-File "$ScriptDir\Wallpaper\Wallpaper_*.jpg" -Destination "$env:SystemRoot\Web\4K\Wallpaper\Windows"
    Try
    {
        $TSEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment'
        If ($TSEnv.Value("_SMSTSOSUpgradeActionReturnCode") -ne $null)
        {
            Copy-File "$ScriptDir\Wallpaper\OEM.theme" -Destination "$env:SystemRoot\Resources\Themes"
        }
    
    }
    Catch
    {
    }
}

If ($StartMenu -eq $True)
{
    $Phase = "Start Menu"
    Write-Log -Message "Now Updating the default start menu" -WriteHost $true
    Copy-File -Path "$ScriptDir\StartMenu\Internet Explorer.lnk" -Destination "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk"
    Copy-File -Path "$ScriptDir\StartMenu\LayoutModification.xml" -Destination "$env:SystemDrive\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
}

If ($OEMImage -ne "NOVALUE" -or $Manufacturer -ne "NOVALUE" -or $SupportURL -ne "NOVALUE" -or $SupportPhone -ne "NOVALUE" -or $SupportHours -ne "NOVALUE" -or $InstallModel -ne "NOVALUE")
{
    $Phase = "System Properties"

    Write-Log -Message "Update System Properties GUI"

    if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation) -ne $true)
    {
        Write-Log "Creating OEM Registry Key" -WriteHost $true
        New-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Type Directory -force -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Creating Help Customized Registry Key" -WriteHost $true
    Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name HelpCustomized -Type DWORD -Value 0 -ErrorAction SilentlyContinue

    If ($OEMImage -ne "NOVALUE")
    {
        Write-Log -Message "Copying OEM Logo file to $env:SystemRoot\System32" -WriteHost $true
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name Logo -Type String -Value $env:SystemRoot\System32\$OEMImage -ErrorVariable myErr -ErrorAction SilentlyContinue
        Copy-File -Path "$ScriptDir\OEMLogo\$OEMImage" "$env:SystemRoot\System32"
    }

    If ($Manufacturer -ne "NOVALUE")
    {
        Write-Log -Message "Creating Manufacturer Key ($Manufacturer)" 
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name Manufacturer -Type String -Value $Manufacturer -ErrorVariable myErr -ErrorAction SilentlyContinue
    }

    if ($SupportURL -ne "NOVALUE")
    {
        Write-Log -Message "Create Support URL Key ($SupportURL)" 
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name SupportURL -Type String -Value $SupportURL -ErrorVariable myErr -ErrorAction SilentlyContinue
    }

    if ($SupportPhone -ne "NOVALUE")
    {
        Write-Log -Message "Create Support Phone Key ($SupportPhone)" 
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name SupportPhone -Type String -Value $SupportPhone -ErrorVariable myErr -ErrorAction SilentlyContinue
    }

    if ($SupportHours -ne "NOVALUE")
    {
        Write-Log -Message "Create Support Hours Key ($SupportHours)" 
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name SupportHours -Type String -Value $SupportHours -ErrorVariable myErr -ErrorAction SilentlyContinue
    }
    If ($InstallModel -ne "NOVALUE")
    { 
        Write-Log -Message "Create Model Information Key ($InstallModel)" 
        Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation -Name Model -Type String -Value ($InstallModel) -ErrorVariable myErr -ErrorAction SilentlyContinue
    }
}
$Phase = "Finalization"
Write-Log -message "Completed System GUI Configuration" -WriteHost $true