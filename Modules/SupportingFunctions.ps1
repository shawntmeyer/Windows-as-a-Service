##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration

## Variables: Datetime and Culture
[datetime]$currentDateTime = Get-Date
[string]$currentTime = Get-Date -Date $currentDateTime -UFormat '%T'
[string]$currentDate = Get-Date -Date $currentDateTime -UFormat '%d-%m-%Y'
[timespan]$currentTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now)

## Variables: Environment Variables
[psobject]$envHost = $Host
[psobject]$envShellFolders = Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction 'SilentlyContinue'
[string]$envAllUsersProfile = $env:ALLUSERSPROFILE
[string]$envAppData = [Environment]::GetFolderPath('ApplicationData')
[string]$envArchitecture = $env:PROCESSOR_ARCHITECTURE
[string]$envCommonProgramFiles = [Environment]::GetFolderPath('CommonProgramFiles')
[string]$envCommonProgramFilesX86 = ${env:CommonProgramFiles(x86)}
[string]$envCommonDesktop   = $envShellFolders | Select-Object -ExpandProperty 'Common Desktop' -ErrorAction 'SilentlyContinue'
[string]$envCommonDocuments = $envShellFolders | Select-Object -ExpandProperty 'Common Documents' -ErrorAction 'SilentlyContinue'
[string]$envCommonStartMenuPrograms  = $envShellFolders | Select-Object -ExpandProperty 'Common Programs' -ErrorAction 'SilentlyContinue'
[string]$envCommonStartMenu = $envShellFolders | Select-Object -ExpandProperty 'Common Start Menu' -ErrorAction 'SilentlyContinue'
[string]$envCommonStartUp   = $envShellFolders | Select-Object -ExpandProperty 'Common Startup' -ErrorAction 'SilentlyContinue'
[string]$envCommonTemplates = $envShellFolders | Select-Object -ExpandProperty 'Common Templates' -ErrorAction 'SilentlyContinue'
[string]$envComputerName = [Environment]::MachineName.ToUpper()
[string]$envComputerNameFQDN = ([Net.Dns]::GetHostEntry('localhost')).HostName
[string]$envHomeDrive = $env:HOMEDRIVE
[string]$envHomePath = $env:HOMEPATH
[string]$envHomeShare = $env:HOMESHARE
[string]$envLocalAppData = [Environment]::GetFolderPath('LocalApplicationData')
[string[]]$envLogicalDrives = [Environment]::GetLogicalDrives()
[string]$envProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
[string]$envProgramFilesX86 = ${env:ProgramFiles(x86)}
[string]$envProgramData = [Environment]::GetFolderPath('CommonApplicationData')
[string]$envPublic = $env:PUBLIC
[string]$envSystemDrive = $env:SYSTEMDRIVE
[string]$envSystemRoot = $env:SYSTEMROOT
[string]$envTemp = [IO.Path]::GetTempPath()
[string]$envUserCookies = [Environment]::GetFolderPath('Cookies')
[string]$envUserDesktop = [Environment]::GetFolderPath('DesktopDirectory')
[string]$envUserFavorites = [Environment]::GetFolderPath('Favorites')
[string]$envUserInternetCache = [Environment]::GetFolderPath('InternetCache')
[string]$envUserInternetHistory = [Environment]::GetFolderPath('History')
[string]$envUserMyDocuments = [Environment]::GetFolderPath('MyDocuments')
[string]$envUserName = [Environment]::UserName
[string]$envUserPictures = [Environment]::GetFolderPath('MyPictures')
[string]$envUserProfile = $env:USERPROFILE
[string]$envUserSendTo = [Environment]::GetFolderPath('SendTo')
[string]$envUserStartMenu = [Environment]::GetFolderPath('StartMenu')
[string]$envUserStartMenuPrograms = [Environment]::GetFolderPath('Programs')
[string]$envUserStartUp = [Environment]::GetFolderPath('StartUp')
[string]$envUserTemplates = [Environment]::GetFolderPath('Templates')
[string]$envSystem32Directory = [Environment]::SystemDirectory
[string]$envWinDir = $env:WINDIR
#  Handle X86 environment variables so they are never empty
If (-not $envCommonProgramFilesX86) { [string]$envCommonProgramFilesX86 = $envCommonProgramFiles }
If (-not $envProgramFilesX86) { [string]$envProgramFilesX86 = $envProgramFiles }

## Variables: Domain Membership
[boolean]$IsMachinePartOfDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
[string]$envMachineWorkgroup = ''
[string]$envMachineADDomain = ''
[string]$envLogonServer = ''
[string]$MachineDomainController = ''
If ($IsMachinePartOfDomain) {
	[string]$envMachineADDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
	Try {
		[string]$envLogonServer = $env:LOGONSERVER | Where-Object { (($_) -and (-not $_.Contains('\\MicrosoftAccount'))) } | ForEach-Object { $_.TrimStart('\') } | ForEach-Object { ([Net.Dns]::GetHostEntry($_)).HostName }
		# If running in system context, fall back on the logonserver value stored in the registry
		If (-not $envLogonServer) { [string]$envLogonServer = Get-ItemProperty -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DCName' -ErrorAction 'SilentlyContinue' }
		[string]$MachineDomainController = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
	}
	Catch { }
}
Else {
	[string]$envMachineWorkgroup = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
}
[string]$envMachineDNSDomain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
[string]$envUserDNSDomain = $env:USERDNSDOMAIN | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
Try {
	[string]$envUserDomain = [Environment]::UserDomainName.ToUpper()
}
Catch { }

## Variables: Operating System
[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = $envOS.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
If ($envOSVersionMajor -eq 10) {$envOSVersionRevision = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR' -ErrorAction SilentlyContinue).UBR}
Else { [string]$envOSVersionRevision = ,((Get-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'BuildLabEx' -ErrorAction 'SilentlyContinue').BuildLabEx -split '\.') | ForEach-Object { $_[1] } }
If ($envOSVersionRevision -notmatch '^[\d\.]+$') { $envOSVersionRevision = '' }
If ($envOSVersionRevision) { [string]$envOSVersion = "$($envOSVersion.ToString()).$envOSVersionRevision" } Else { "$($envOSVersion.ToString())" }
#  Get the operating system type
[int32]$envOSProductType = $envOS.ProductType
[boolean]$IsServerOS = [boolean]($envOSProductType -eq 3)
[boolean]$IsDomainControllerOS = [boolean]($envOSProductType -eq 2)
[boolean]$IsWorkStationOS = [boolean]($envOSProductType -eq 1)
Switch ($envOSProductType) {
	3 { [string]$envOSProductTypeName = 'Server' }
	2 { [string]$envOSProductTypeName = 'Domain Controller' }
	1 { [string]$envOSProductTypeName = 'Workstation' }
	Default { [string]$envOSProductTypeName = 'Unknown' }
}
#  Get the OS Architecture
[boolean]$Is64Bit = [boolean]((Get-WmiObject -Class 'Win32_Processor' -ErrorAction 'SilentlyContinue' | Where-Object { $_.DeviceID -eq 'CPU0' } | Select-Object -ExpandProperty 'AddressWidth') -eq 64)
If ($Is64Bit) { [string]$envOSArchitecture = '64-bit' } Else { [string]$envOSArchitecture = '32-bit' }

## Variables: Permissions/Accounts
[Security.Principal.WindowsIdentity]$CurrentProcessToken = [Security.Principal.WindowsIdentity]::GetCurrent()
[Security.Principal.SecurityIdentifier]$CurrentProcessSID = $CurrentProcessToken.User
[string]$ProcessNTAccount = $CurrentProcessToken.Name
[string]$ProcessNTAccountSID = $CurrentProcessSID.Value
[boolean]$IsAdmin = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-32-544')
[boolean]$IsLocalSystemAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalSystemSid')
[boolean]$IsLocalServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'LocalServiceSid')
[boolean]$IsNetworkServiceAccount = $CurrentProcessSID.IsWellKnown([Security.Principal.WellKnownSidType]'NetworkServiceSid')
[boolean]$IsServiceAccount = [boolean]($CurrentProcessToken.Groups -contains [Security.Principal.SecurityIdentifier]'S-1-5-6')
[boolean]$IsProcessUserInteractive = [Environment]::UserInteractive
[string]$LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value
#  Check if script is running in session zero
If ($IsLocalSystemAccount -or $IsLocalServiceAccount -or $IsNetworkServiceAccount -or $IsServiceAccount) { $SessionZero = $true } Else { $SessionZero = $false }

## Variables: Script Name and Script Paths
[string]$scriptPath = $MyInvocation.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[string]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent
[string]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory and logname
If ($invokingScript) {
	#  If this script was invoked by another script
	[string]$scriptParentPath = Split-Path -Path $invokingScript -Parent    
    [string]$LogName = [IO.Path]::GetFileNameWithoutExtension($invokingScript) + ".log"
}
Else {
	#  If this script was not invoked by another script, fall back to the directory one level above this script
	[string]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
    [string]$LogName = "$ScriptName.log"
}

## Variables: Registry Keys
#  Registry keys for native and WOW64 applications
[string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'

[string]$regKeyAppExecution = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

## COM Objects: Initialize
[__comobject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'SilentlyContinue'
[__comobject]$ShellApp = New-Object -ComObject 'Shell.Application' -ErrorAction 'SilentlyContinue'

## Check if script is running from a SCCM Task Sequence
Try {
	[__comobject]$TSEnv = New-Object -ComObject 'Microsoft.SMS.TSEnvironment' -ErrorAction 'Stop'
	$runningTaskSequence = $true
}
Catch {
	$runningTaskSequence = $false
}

#endregion
##*=============================================
##* END VARIABLE DECLARATION
##*=============================================

##*=============================================
##* FUNCTION LISTINGS
##*=============================================
#region FunctionListings

#region Function Get-LogDir
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
    $logDir = "$($env:Systemroot)\logs"
  }
  return $logDir
}
#endregion

#region Function Write-FunctionHeaderOrFooter
Function Write-FunctionHeaderOrFooter {
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
		Write-Log -Message 'Function Start' -Source ${CmdletName}
		
		## Get the parameters that the calling function was invoked with
		[string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' }, @{ Label = 'Type'; Expression = { $_.Value.GetType().Name }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
		If ($CmdletBoundParameters) {
			Write-Log -Message "Function invoked with bound parameter(s): `n$CmdletBoundParameters" -Source ${CmdletName}
		}
		Else {
			Write-Log -Message 'Function invoked without any bound parameters.' -Source ${CmdletName}
		}
	}
	ElseIf ($Footer) {
		Write-Log -Message 'Function End' -Source ${CmdletName}
	}
}
#endregion

#region Function Write-Log
Function Write-Log {
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
		[string]$ScriptSection = "$Script:Phase",
		[Parameter(Mandatory=$false,Position=4)]
		[ValidateSet('CMTrace','Legacy')]
		[string]$LogType = 'CMTrace',
		[Parameter(Mandatory=$false,Position=5)]
		[ValidateNotNullorEmpty()]
		[string]$LogFileDirectory = $LogDir,
		[Parameter(Mandatory=$false,Position=6)]
		[ValidateNotNullorEmpty()]
		[string]$LogFileName = $logName,
		[Parameter(Mandatory=$false,Position=7)]
		[ValidateNotNullorEmpty()]
		[decimal]$MaxLogFileSizeMB = 10,
		[Parameter(Mandatory=$false,Position=8)]
		[ValidateNotNullorEmpty()]
		[boolean]$WriteHost = $true,
		[Parameter(Mandatory=$false,Position=9)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true,
		[Parameter(Mandatory=$false,Position=10)]
		[switch]$PassThru = $false,
		[Parameter(Mandatory=$false,Position=11)]
		[switch]$DebugMessage = $false,
		[Parameter(Mandatory=$false,Position=12)]
		[boolean]$LogDebugMessage = $false
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
		
		## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
		If (($DebugMessage) -and (-not $LogDebugMessage)) { [boolean]$ExitLoggingFunction = $true; Return }
		## Exit function if logging to file is disabled and logging to console host is disabled
		If (($DisableLogging) -and (-not $WriteHost)) { [boolean]$ExitLoggingFunction = $true; Return }
		## Exit Begin block if logging is disabled
		If ($DisableLogging) { Return }
		## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
		If (($AsyncToolkitLaunch) -and ($ScriptSection -eq 'Initialization')) { [boolean]$ExitLoggingFunction = $true; Return }
		
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
#endregion

#region Function Exit-Script
Function Exit-Script {
<#
.SYNOPSIS
	Exit the script, perform cleanup actions, and pass an exit code to the parent process.
.DESCRIPTION
	Always use when exiting the script to ensure cleanup actions are performed.
.PARAMETER ExitCode
	The exit code to be passed from the script to the parent process, e.g. SCCM
.EXAMPLE
	Exit-Script -ExitCode 0
.EXAMPLE
	Exit-Script -ExitCode 1618
.NOTES
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[int32]$ExitCode = 0
	)
	
	## Get the name of this function
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	## Determine action based on exit code
	Switch ($exitCode) {
		3010 { $installSuccess = $true }
		1641 { $installSuccess = $true }
		0 { $installSuccess = $true }
		Default { $installSuccess = $false }
	}
	
	If ($installSuccess) {


		Write-Log -Message "$InvokingScript completed with exit code [$exitcode]." -Source ${CmdletName}
	}
	ElseIf (-not $installSuccess) {
		Write-Log -Message "$invokingScript completed with exit code [$exitcode]." -Source ${CmdletName}
	}
	
	[string]$LogDash = '-' * 79
	Write-Log -Message $LogDash -Source ${CmdletName}
	
	## Exit the script, returning the exit code to SCCM
	If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $exitCode; Exit } Else { Exit $exitCode }
}
#endregion

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

#region Function Get-FreeDiskSpace
Function Get-FreeDiskSpace {
<#
.SYNOPSIS
	Retrieves the free disk space in MB on a particular drive (defaults to system drive)
.DESCRIPTION
	Retrieves the free disk space in MB on a particular drive (defaults to system drive)
.PARAMETER Drive
	Drive to check free disk space on
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Get-FreeDiskSpace -Drive 'C:'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Drive = $envSystemDrive,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Retrieve free disk space for drive [$Drive]." -Source ${CmdletName}
			$disk = Get-WmiObject -Class 'Win32_LogicalDisk' -Filter "DeviceID='$Drive'" -ErrorAction 'Stop'
			[double]$freeDiskSpace = [math]::Round($disk.FreeSpace / 1MB)
			
			Write-Log -Message "Free disk space for drive [$Drive]: [$freeDiskSpace MB]." -Source ${CmdletName}
			Write-Output -InputObject $freeDiskSpace
		}
		Catch {
			Write-Log -Message "Failed to retrieve free disk space for drive [$Drive]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to retrieve free disk space for drive [$Drive]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-InstalledApplication
Function Get-InstalledApplication {
<#
.SYNOPSIS
	Retrieves information about installed applications.
.DESCRIPTION
	Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
	Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
.PARAMETER Name
	The name of the application to retrieve information for. Performs a contains match on the application display name by default.
.PARAMETER Exact
	Specifies that the named application must be matched using the exact name.
.PARAMETER WildCard
	Specifies that the named application must be matched using a wildcard search.
.PARAMETER RegEx
	Specifies that the named application must be matched using a regular expression search.
.PARAMETER ProductCode
	The product code of the application to retrieve information for.
.PARAMETER IncludeUpdatesAndHotfixes
	Include matches against updates and hotfixes in results.
.EXAMPLE
	Get-InstalledApplication -Name 'Adobe Flash'
.EXAMPLE
	Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string[]]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		If ($name) {
			Write-Log -Message "Get information for installed Application Name(s) [$($name -join ', ')]..." -Source ${CmdletName}
		}
		If ($productCode) {
			Write-Log -Message "Get information for installed Product Code [$ProductCode]..." -Source ${CmdletName}
		}
		
		## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
		[psobject[]]$regKeyApplication = @()
		ForEach ($regKey in $regKeyApplications) {
			If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
				[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
				ForEach ($UninstallKeyApp in $UninstallKeyApps) {
					Try {
						[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
						If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
					}
					Catch{
						Write-Log -Message "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
						Continue
					}
				}
			}
		}
		If ($ErrorUninstallKeyPath) {
			Write-Log -Message "The following error(s) took place while enumerating installed applications from the registry. `n$(Resolve-Error -ErrorRecord $ErrorUninstallKeyPath)" -Severity 2 -Source ${CmdletName}
		}
		
		## Create a custom object with the desired properties for the installed applications and sanitize property details
		[psobject[]]$installedApplication = @()
		ForEach ($regKeyApp in $regKeyApplication) {
			Try {
				[string]$appDisplayName = ''
				[string]$appDisplayVersion = ''
				[string]$appPublisher = ''
				
				## Bypass any updates or hotfixes
				If (-not $IncludeUpdatesAndHotfixes) {
					If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
					If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
				}
				
				## Remove any control characters which may interfere with logging and creating file path names from these variables
				$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
				$appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
				$appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''
				
				## Determine if application is a 64-bit application
				[boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }
				
				If ($ProductCode) {
					## Verify if there is a match with the product code passed to the script
					If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
						Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]." -Source ${CmdletName}
						$installedApplication += New-Object -TypeName 'PSObject' -Property @{
							UninstallSubkey = $regKeyApp.PSChildName
							ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
							DisplayName = $appDisplayName
							DisplayVersion = $appDisplayVersion
							UninstallString = $regKeyApp.UninstallString
							InstallSource = $regKeyApp.InstallSource
							InstallLocation = $regKeyApp.InstallLocation
							InstallDate = $regKeyApp.InstallDate
							Publisher = $appPublisher
							Is64BitApplication = $Is64BitApp
						}
					}
				}
				
				If ($name) {
					## Verify if there is a match with the application name(s) passed to the script
					ForEach ($application in $Name) {
						$applicationMatched = $false
						If ($exact) {
							#  Check for an exact application name match
							If ($regKeyApp.DisplayName -eq $application) {
								$applicationMatched = $true
								Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]." -Source ${CmdletName}
							}
						}
						ElseIf ($WildCard) {
							#  Check for wildcard application name match
							If ($regKeyApp.DisplayName -like $application) {
								$applicationMatched = $true
								Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]." -Source ${CmdletName}
							}
						}
						ElseIf ($RegEx) {
							#  Check for a regex application name match
							If ($regKeyApp.DisplayName -match $application) {
								$applicationMatched = $true
								Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]." -Source ${CmdletName}
							}
						}
						#  Check for a contains application name match
						ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
							$applicationMatched = $true
							Write-Log -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]." -Source ${CmdletName}
						}
						
						If ($applicationMatched) {
							$installedApplication += New-Object -TypeName 'PSObject' -Property @{
								UninstallSubkey = $regKeyApp.PSChildName
								ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
								DisplayName = $appDisplayName
								DisplayVersion = $appDisplayVersion
								UninstallString = $regKeyApp.UninstallString
								InstallSource = $regKeyApp.InstallSource
								InstallLocation = $regKeyApp.InstallLocation
								InstallDate = $regKeyApp.InstallDate
								Publisher = $appPublisher
								Is64BitApplication = $Is64BitApp
							}
						}
					}
				}
			}
			Catch {
				Write-Log -Message "Failed to resolve application details from registry for [$appDisplayName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				Continue
			}
		}
		
		Write-Output -InputObject $installedApplication
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Execute-Process
Function Execute-Process {
<#
.SYNOPSIS
	Execute a process with optional arguments, working directory, window style.
.DESCRIPTION
	Executes a process, e.g. a file included in the Files directory of the App Deploy Toolkit, or a file on the local machine.
	Provides various options for handling the return codes (see Parameters).
.PARAMETER Path
	Path to the file to be executed. If the file is located directly in the "Files" directory of the App Deploy Toolkit, only the file name needs to be specified.
	Otherwise, the full path of the file must be specified. If the files is in a subdirectory of "Files", use the "$dirInstallers" variable as shown in the example.
.PARAMETER Parameters
	Arguments to be passed to the executable
.PARAMETER SecureParameters
	Hides all parameters passed to the executable from the Toolkit log file
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
	this function waits for the msiexec engine to become available before starting the install.
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
	Execute-Process -Path "$dirInstallers\Bin\setup.exe" -Parameters '/S' -WindowStyle 'Hidden'
.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters '/S' -IgnoreExitCodes '1,2'
.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters "-s -f2`"$configToolkitLogDir\$installName.log`""
	Launch InstallShield "setup.exe" from the ".\Files" sub-directory and force log files to the logging folder.
.EXAMPLE
	Execute-Process -Path 'setup.exe' -Parameters "/s /v`"ALLUSERS=1 /qn /L* \`"$configToolkitLogDir\$installName.log`"`""
	Launch InstallShield "setup.exe" with embedded MSI and force log files to the logging folder.
.NOTES

	
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
		[switch]$SecureParameters = $false,
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
		[timespan]$MsiExecWaitTime = $(New-TimeSpan -Seconds 120),
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
				[string]$PathFolders = $dirInstallers
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
					Else {
						If ($SecureParameters) {
							Write-Log -Message "Executing [$Path (Parameters Hidden)]..." -Source ${CmdletName}
						}
						Else {							
							Write-Log -Message "Executing [$Path $Parameters]..." -Source ${CmdletName}
						}
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
					Try {
						[int32]$returnCode = $process.ExitCode
					}
					Catch [System.Management.Automation.PSInvalidCastException] {
						#  Catch exit codes that are out of int32 range
						[int32]$returnCode = 60013
					}
					
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
					Exit-Script -ExitCode $returnCode
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
				Exit-Script -ExitCode $returnCode
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-MsiExitCodeMessage
Function Get-MsiExitCodeMessage {
<#
.SYNOPSIS
	Get message for MSI error code
.DESCRIPTION
	Get message for MSI error code by reading it from msimsg.dll
.PARAMETER MsiErrorCode
	MSI error code
.EXAMPLE
	Get-MsiExitCodeMessage -MsiErrorCode 1618
.NOTES
	This is an internal script function and should typically not be called directly.

	http://msdn.microsoft.com/en-us/library/aa368542(v=vs.85).aspx
	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[int32]$MsiExitCode
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Get message for exit code [$MsiExitCode]." -Source ${CmdletName}
			[string]$MsiExitCodeMsg = [PSADT.Msi]::GetMessageFromMsiExitCode($MsiExitCode)
			Write-Output -InputObject $MsiExitCodeMsg
		}
		Catch {
			Write-Log -Message "Failed to get message for exit code [$MsiExitCode]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Test-IsMutexAvailable
Function Test-IsMutexAvailable {
<#
.SYNOPSIS
	Wait, up to a timeout value, to check if current thread is able to acquire an exclusive lock on a system mutex.
.DESCRIPTION
	A mutex can be used to serialize applications and prevent multiple instances from being opened at the same time.
	Wait, up to a timeout (default is 1 millisecond), for the mutex to become available for an exclusive lock.
.PARAMETER MutexName
	The name of the system mutex.
.PARAMETER MutexWaitTime
	The number of milliseconds the current thread should wait to acquire an exclusive lock of a named mutex. Default is: 1 millisecond.
	A wait time of -1 milliseconds means to wait indefinitely. A wait time of zero does not acquire an exclusive lock but instead tests the state of the wait handle and returns immediately.
.EXAMPLE
	Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds 500
.EXAMPLE
	Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds (New-TimeSpan -Minutes 5).TotalMilliseconds
.EXAMPLE
	Test-IsMutexAvailable -MutexName 'Global\_MSIExecute' -MutexWaitTimeInMilliseconds (New-TimeSpan -Seconds 60).TotalMilliseconds
.NOTES
	This is an internal script function and should typically not be called directly.

	http://msdn.microsoft.com/en-us/library/aa372909(VS.85).asp
	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateLength(1,260)]
		[string]$MutexName,
		[Parameter(Mandatory=$false)]
		[ValidateScript({($_ -ge -1) -and ($_ -le [int32]::MaxValue)})]
		[int32]$MutexWaitTimeInMilliseconds = 1
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		## Initialize Variables
		[timespan]$MutexWaitTime = [timespan]::FromMilliseconds($MutexWaitTimeInMilliseconds)
		If ($MutexWaitTime.TotalMinutes -ge 1) {
			[string]$WaitLogMsg = "$($MutexWaitTime.TotalMinutes) minute(s)"
		}
		ElseIf ($MutexWaitTime.TotalSeconds -ge 1) {
			[string]$WaitLogMsg = "$($MutexWaitTime.TotalSeconds) second(s)"
		}
		Else {
			[string]$WaitLogMsg = "$($MutexWaitTime.Milliseconds) millisecond(s)"
		}
		[boolean]$IsUnhandledException = $false
		[boolean]$IsMutexFree = $false
		[Threading.Mutex]$OpenExistingMutex = $null
	}
	Process {
		Write-Log -Message "Check to see if mutex [$MutexName] is available. Wait up to [$WaitLogMsg] for the mutex to become available." -Source ${CmdletName}
		Try {
			## Using this variable allows capture of exceptions from .NET methods. Private scope only changes value for current function.
			$private:previousErrorActionPreference = $ErrorActionPreference
			$ErrorActionPreference = 'Stop'
			
			## Open the specified named mutex, if it already exists, without acquiring an exclusive lock on it. If the system mutex does not exist, this method throws an exception instead of creating the system object.
			[Threading.Mutex]$OpenExistingMutex = [Threading.Mutex]::OpenExisting($MutexName)
			## Attempt to acquire an exclusive lock on the mutex. Use a Timespan to specify a timeout value after which no further attempt is made to acquire a lock on the mutex.
			$IsMutexFree = $OpenExistingMutex.WaitOne($MutexWaitTime, $false)
		}
		Catch [Threading.WaitHandleCannotBeOpenedException] {
			## The named mutex does not exist
			$IsMutexFree = $true
		}
		Catch [ObjectDisposedException] {
			## Mutex was disposed between opening it and attempting to wait on it
			$IsMutexFree = $true
		}
		Catch [UnauthorizedAccessException] {
			## The named mutex exists, but the user does not have the security access required to use it
			$IsMutexFree = $false
		}
		Catch [Threading.AbandonedMutexException] {
			## The wait completed because a thread exited without releasing a mutex. This exception is thrown when one thread acquires a mutex object that another thread has abandoned by exiting without releasing it.
			$IsMutexFree = $true
		}
		Catch {
			$IsUnhandledException = $true
			## Return $true, to signify that mutex is available, because function was unable to successfully complete a check due to an unhandled exception. Default is to err on the side of the mutex being available on a hard failure.
			Write-Log -Message "Unable to check if mutex [$MutexName] is available due to an unhandled exception. Will default to return value of [$true]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			$IsMutexFree = $true
		}
		Finally {
			If ($IsMutexFree) {
				If (-not $IsUnhandledException) {
					Write-Log -Message "Mutex [$MutexName] is available for an exclusive lock." -Source ${CmdletName}
				}
			}
			Else {
				If ($MutexName -eq 'Global\_MSIExecute') {
					## Get the command line for the MSI installation in progress
					Try {
						[string]$msiInProgressCmdLine = Get-WmiObject -Class 'Win32_Process' -Filter "name = 'msiexec.exe'" -ErrorAction 'Stop' | Where-Object { $_.CommandLine } | Select-Object -ExpandProperty 'CommandLine' | Where-Object { $_ -match '\.msi' } | ForEach-Object { $_.Trim() }
					}
					Catch { }
					Write-Log -Message "Mutex [$MutexName] is not available for an exclusive lock because the following MSI installation is in progress [$msiInProgressCmdLine]." -Severity 2 -Source ${CmdletName}
				}
				Else {
					Write-Log -Message "Mutex [$MutexName] is not available because another thread already has an exclusive lock on it." -Source ${CmdletName}
				}
			}
			
			If (($null -ne $OpenExistingMutex) -and ($IsMutexFree)) {
				## Release exclusive lock on the mutex
				$null = $OpenExistingMutex.ReleaseMutex()
				$OpenExistingMutex.Close()
			}
			If ($private:previousErrorActionPreference) { $ErrorActionPreference = $private:previousErrorActionPreference }
		}
	}
	End {
		Write-Output -InputObject $IsMutexFree
		
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function New-Folder
Function New-Folder {
<#
.SYNOPSIS
	Create a new folder.
.DESCRIPTION
	Create a new folder if it does not exist.
.PARAMETER Path
	Path to the new folder to create.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	New-Folder -Path "$envWinDir\System32"
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Path,
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
			If (-not (Test-Path -LiteralPath $Path -PathType 'Container')) {
				Write-Log -Message "Create folder [$Path]." -Source ${CmdletName}
				$null = New-Item -Path $Path -ItemType 'Directory' -ErrorAction 'Stop'
			}
			Else {
				Write-Log -Message "Folder [$Path] already exists." -Source ${CmdletName}
			}
		}
		Catch {
			Write-Log -Message "Failed to create folder [$Path]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to create folder [$Path]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Remove-Folder
Function Remove-Folder {
<#
.SYNOPSIS
	Remove folder and files if they exist.
.DESCRIPTION
	Remove folder and all files recursively in a given path.
.PARAMETER Path
	Path to the folder to remove.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Remove-Folder -Path "$envWinDir\Downloaded Program Files"
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Path,
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
			If (Test-Path -LiteralPath $Path -PathType 'Container') {
				Try {
					Remove-Item -LiteralPath $Path -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorRemoveFolder'
					If ($ErrorRemoveFolder) {
						Write-Log -Message "The following error(s) took place while deleting folder(s) and file(s) recursively from path [$path]. `n$(Resolve-Error -ErrorRecord $ErrorRemoveFolder)" -Severity 2 -Source ${CmdletName}
					}		
				}
				Catch {
					Write-Log -Message "Failed to delete folder(s) and file(s) recursively from path [$path]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					If (-not $ContinueOnError) {
						Throw "Failed to delete folder(s) and file(s) recursively from path [$path]: $($_.Exception.Message)"
					}
				}
			}
			Else {
				Write-Log -Message "Folder [$Path] does not exists..." -Source ${CmdletName}
			}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Copy-File
Function Copy-File {
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
	Continue if an error is encountered. This will continue the deployment script, but will not continue copying files if an error is encountered. Default is: $true.
.PARAMETER ContinueFileCopyOnError
	Continue copying files if an error is encountered. This will continue the deployment script and will warn about files that failed to be copied. Default is: $false.
.EXAMPLE
	Copy-File -Path "$dirSupportFiles\MyApp.ini" -Destination "$envWindir\MyApp.ini"
.EXAMPLE
	Copy-File -Path "$dirSupportFiles\*.*" -Destination "$envTemp\tempfiles"
	Copy all of the files in a folder to a destination folder.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string[]]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Destination,
		[Parameter(Mandatory=$false)]
		[switch]$Recurse = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true,
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueFileCopyOnError = $false
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			$null = $fileCopyError
			If ((-not ([IO.Path]::HasExtension($Destination))) -and (-not (Test-Path -LiteralPath $Destination -PathType 'Container'))) {
				Write-Log -Message "Destination folder does not exist, creating destination folder [$destination]." -Source ${CmdletName}
				$null = New-Item -Path $Destination -Type 'Directory' -Force -ErrorAction 'Stop'
			}
			
			$null = $FileCopyError
			If ($Recurse) {
				Write-Log -Message "Copy file(s) recursively in path [$path] to destination [$destination]." -Source ${CmdletName}
				If (-not $ContinueFileCopyOnError) {
					$null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'Stop'
				}
				Else {
					$null = Copy-Item -Path $Path -Destination $Destination -Force -Recurse -ErrorAction 'SilentlyContinue' -ErrorVariable FileCopyError
				}
			}
			Else {
				Write-Log -Message "Copy file in path [$path] to destination [$destination]." -Source ${CmdletName}
				If (-not $ContinueFileCopyOnError) {
					$null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'Stop'
				}
				Else {
					$null = Copy-Item -Path $Path -Destination $Destination -Force -ErrorAction 'SilentlyContinue' -ErrorVariable FileCopyError
				}
			}

			If ($fileCopyError) { 
				Write-Log -Message "The following warnings were detected while copying file(s) in path [$path] to destination [$destination]. `n$FileCopyError" -Severity 2 -Source ${CmdletName}
			}
			Else {
				Write-Log -Message "File copy completed successfully." -Source ${CmdletName}            
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
#endregion

#region Function Remove-File
Function Remove-File {
<#
.SYNOPSIS
	Removes one or more items from a given path on the filesystem.
.DESCRIPTION
	Removes one or more items from a given path on the filesystem.
.PARAMETER Path
	Specifies the path on the filesystem to be resolved. The value of Path will accept wildcards. Will accept an array of values.
.PARAMETER LiteralPath
	Specifies the path on the filesystem to be resolved. The value of LiteralPath is used exactly as it is typed; no characters are interpreted as wildcards. Will accept an array of values.
.PARAMETER Recurse
	Deletes the files in the specified location(s) and in all child items of the location(s).
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Remove-File -Path 'C:\Windows\Downloaded Program Files\Temp.inf'
.EXAMPLE
	Remove-File -LiteralPath 'C:\Windows\Downloaded Program Files' -Recurse
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,ParameterSetName='Path')]
		[ValidateNotNullorEmpty()]
		[string[]]$Path,
		[Parameter(Mandatory=$true,ParameterSetName='LiteralPath')]
		[ValidateNotNullorEmpty()]
		[string[]]$LiteralPath,
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
		## Build hashtable of parameters/value pairs to be passed to Remove-Item cmdlet
		[hashtable]$RemoveFileSplat =  @{ 'Recurse' = $Recurse
										  'Force' = $true
										  'ErrorVariable' = '+ErrorRemoveItem'
										}
		If ($ContinueOnError) {
			$RemoveFileSplat.Add('ErrorAction', 'SilentlyContinue')
		}
		Else {
			$RemoveFileSplat.Add('ErrorAction', 'Stop')
		}
		
		## Resolve the specified path, if the path does not exist, display a warning instead of an error
		If ($PSCmdlet.ParameterSetName -eq 'Path') { [string[]]$SpecifiedPath = $Path } Else { [string[]]$SpecifiedPath = $LiteralPath }
		ForEach ($Item in $SpecifiedPath) {
			Try {
				If ($PSCmdlet.ParameterSetName -eq 'Path') {
					[string[]]$ResolvedPath += Resolve-Path -Path $Item -ErrorAction 'Stop' | Where-Object { $_.Path } | Select-Object -ExpandProperty 'Path' -ErrorAction 'Stop'
				}
				Else {
					[string[]]$ResolvedPath += Resolve-Path -LiteralPath $Item -ErrorAction 'Stop' | Where-Object { $_.Path } | Select-Object -ExpandProperty 'Path' -ErrorAction 'Stop'
				}
			}
			Catch [System.Management.Automation.ItemNotFoundException] {
				Write-Log -Message "Unable to resolve file(s) for deletion in path [$Item] because path does not exist." -Severity 2 -Source ${CmdletName}
			}
			Catch {
				Write-Log -Message "Failed to resolve file(s) for deletion in path [$Item]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to resolve file(s) for deletion in path [$Item]: $($_.Exception.Message)"
				}
			}
		}
		
		## Delete specified path if it was successfully resolved
		If ($ResolvedPath) {
			ForEach ($Item in $ResolvedPath) {
				Try {
					If (($Recurse) -and (Test-Path -LiteralPath $Item -PathType 'Container')) {
						Write-Log -Message "Delete file(s) recursively in path [$Item]..." -Source ${CmdletName}
					}
					ElseIf ((-not $Recurse) -and (Test-Path -LiteralPath $Item -PathType 'Container')) {
						Write-Log -Message "Skipping folder [$Item] because the Recurse switch was not specified"
					Continue
					}
					Else {
						Write-Log -Message "Delete file in path [$Item]..." -Source ${CmdletName}
					}
					$null = Remove-Item @RemoveFileSplat -LiteralPath $Item
				}
				Catch {
					Write-Log -Message "Failed to delete file(s) in path [$Item]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					If (-not $ContinueOnError) {
						Throw "Failed to delete file(s) in path [$Item]: $($_.Exception.Message)"
					}
				}
			}
		}
		
		If ($ErrorRemoveItem) {
			Write-Log -Message "The following error(s) took place while removing file(s) in path [$SpecifiedPath]. `n$(Resolve-Error -ErrorRecord $ErrorRemoveItem)" -Severity 2 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Convert-RegistryPath
Function Convert-RegistryPath {
<#
.SYNOPSIS
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
.DESCRIPTION
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
	Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE".
.PARAMETER Key
	Path to the registry key to convert (can be a registry hive or fully qualified path)
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.EXAMPLE
	Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.EXAMPLE
	Convert-RegistryPath -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		## Convert the registry key hive to the full path, only match if at the beginning of the line
		If ($Key -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') {
			#  Converts registry paths that start with, e.g.: HKLM:\
			$key = $key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU:\\', 'HKEY_USERS\'
			$key = $key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
		}
		ElseIf ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
			#  Converts registry paths that start with, e.g.: HKLM:
			$key = $key -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU:', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU:', 'HKEY_USERS\'
			$key = $key -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
		}
		ElseIf ($Key -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') {
			#  Converts registry paths that start with, e.g.: HKLM\
			$key = $key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU\\', 'HKEY_USERS\'
			$key = $key -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
		}
		
		If ($PSBoundParameters.ContainsKey('SID')) {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID				
			If ($key -match '^HKEY_CURRENT_USER\\') { $key = $key -replace '^HKEY_CURRENT_USER\\', "HKEY_USERS\$SID\" }
		}
		
		## Append the PowerShell drive to the registry key path
		If ($key -notmatch '^Registry::') {[string]$key = "Registry::$key" }
		
		If($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
			## Check for expected key string format
			Write-Log -Message "Return fully qualified registry key path [$key]." -Source ${CmdletName}
			Write-Output -InputObject $key
		}
		Else{
			#  If key string is not properly formatted, throw an error
			Throw "Unable to detect target registry hive in string [$key]."
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Test-RegistryValue
Function Test-RegistryValue {
<#
.SYNOPSIS
	Test if a registry value exists.
.DESCRIPTION
	Checks a registry key path to see if it has a value with a given name. Can correctly handle cases where a value simply has an empty or null value.
.PARAMETER Key
	Path of the registry key.
.PARAMETER Value
	Specify the registry key value to check the existence of.
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.EXAMPLE
	Test-RegistryValue -Key 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations'
.NOTES
	To test if registry key exists, use Test-Path function like so:
	Test-Path -Path $Key -PathType 'Container'

	
#>
	Param (
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]$Key,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullOrEmpty()]$Value,
		[Parameter(Mandatory=$false,Position=2)]
		[ValidateNotNullorEmpty()]
		[string]$SID
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
		Try {
			If ($PSBoundParameters.ContainsKey('SID')) {
				[string]$Key = Convert-RegistryPath -Key $Key -SID $SID
			}
			Else {
				[string]$Key = Convert-RegistryPath -Key $Key
			}
		}
		Catch {
			Throw
		}
		[boolean]$IsRegistryValueExists = $false
		Try {
			If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
				[string[]]$PathProperties = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'
				If ($PathProperties -contains $Value) { $IsRegistryValueExists = $true }
			}
		}
		Catch { }
		
		If ($IsRegistryValueExists) {
			Write-Log -Message "Registry key value [$Key] [$Value] does exist." -Source ${CmdletName}
		}
		Else {
			Write-Log -Message "Registry key value [$Key] [$Value] does not exist." -Source ${CmdletName}
		}
		Write-Output -InputObject $IsRegistryValueExists
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-RegistryKey
Function Get-RegistryKey {
<#
.SYNOPSIS
	Retrieves value names and value data for a specified registry key or optionally, a specific value.
.DESCRIPTION
	Retrieves value names and value data for a specified registry key or optionally, a specific value.
	If the registry key does not exist or contain any values, the function will return $null by default. To test for existence of a registry key path, use built-in Test-Path cmdlet.
.PARAMETER Key
	Path of the registry key.
.PARAMETER Value
	Value to retrieve (optional).
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.PARAMETER ReturnEmptyKeyIfExists
	Return the registry key if it exists but it has no property/value pairs underneath it. Default is: $false.
.PARAMETER DoNotExpandEnvironmentNames
	Return unexpanded REG_EXPAND_SZ values. Default is: $false.	
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Get-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe'
.EXAMPLE
	Get-RegistryKey -Key 'HKLM:Software\Wow6432Node\Microsoft\Microsoft SQL Server Compact Edition\v3.5' -Value 'Version'
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'Path' -DoNotExpandEnvironmentNames 
	Returns %ProgramFiles%\Java instead of C:\Program Files\Java
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Value '(Default)'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$ReturnEmptyKeyIfExists = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$DoNotExpandEnvironmentNames = $false,
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
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[string]$key = Convert-RegistryPath -Key $key -SID $SID
			}
			Else {
				[string]$key = Convert-RegistryPath -Key $key
			}
			
			## Check if the registry key exists
			If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
				Write-Log -Message "Registry key [$key] does not exist. Return `$null." -Severity 2 -Source ${CmdletName}
				$regKeyValue = $null
			}
			Else {
				If ($PSBoundParameters.ContainsKey('Value')) {
					Write-Log -Message "Get registry key [$key] value [$value]." -Source ${CmdletName}
				}
				Else {
					Write-Log -Message "Get registry key [$key] and all property values." -Source ${CmdletName}
				}
				
				## Get all property values for registry key
				$regKeyValue = Get-ItemProperty -LiteralPath $key -ErrorAction 'Stop'
				[int32]$regKeyValuePropertyCount = $regKeyValue | Measure-Object | Select-Object -ExpandProperty 'Count'
				
				## Select requested property
				If ($PSBoundParameters.ContainsKey('Value')) {
					#  Check if registry value exists
					[boolean]$IsRegistryValueExists = $false
					If ($regKeyValuePropertyCount -gt 0) {
						Try {
							[string[]]$PathProperties = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'
							If ($PathProperties -contains $Value) { $IsRegistryValueExists = $true }
						}
						Catch { }
					}
					
					#  Get the Value (do not make a strongly typed variable because it depends entirely on what kind of value is being read)
					If ($IsRegistryValueExists) {
						If ($DoNotExpandEnvironmentNames) { #Only useful on 'ExpandString' values
							If ($Value -like '(Default)') {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
							}
							Else {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($Value,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)	
							}							
						}
						ElseIf ($Value -like '(Default)') {
							$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null)
						}
						Else {
							$regKeyValue = $regKeyValue | Select-Object -ExpandProperty $Value -ErrorAction 'SilentlyContinue'
						}
					}
					Else {
						Write-Log -Message "Registry key value [$Key] [$Value] does not exist. Return `$null." -Source ${CmdletName}
						$regKeyValue = $null
					}
				}
				## Select all properties or return empty key object
				Else {
					If ($regKeyValuePropertyCount -eq 0) {
						If ($ReturnEmptyKeyIfExists) {
							Write-Log -Message "No property values found for registry key. Return empty registry key object [$key]." -Source ${CmdletName}
							$regKeyValue = Get-Item -LiteralPath $key -Force -ErrorAction 'Stop'
						}
						Else {
							Write-Log -Message "No property values found for registry key. Return `$null." -Source ${CmdletName}
							$regKeyValue = $null
						}
					}
				}
			}
			Write-Output -InputObject ($regKeyValue)
		}
		Catch {
			If (-not $Value) {
				Write-Log -Message "Failed to read registry key [$key]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key]: $($_.Exception.Message)"
				}
			}
			Else {
				Write-Log -Message "Failed to read registry key [$key] value [$value]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key] value [$value]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Set-RegistryKey
Function Set-RegistryKey {
<#
.SYNOPSIS
	Creates a registry key name, value, and value data; it sets the same if it already exists.
.DESCRIPTION
	Creates a registry key name, value, and value data; it sets the same if it already exists.
.PARAMETER Key
	The registry key path.
.PARAMETER Name
	The value name.
.PARAMETER Value
	The value data.
.PARAMETER Type
	The type of registry value to create or set. Options: 'Binary','DWord','ExpandString','MultiString','None','QWord','String','Unknown'. Default: String.
	Dword should be specified as a decimal.
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Set-RegistryKey -Key $blockedAppPath -Name 'Debugger' -Value $blockedAppDebuggerValue
.EXAMPLE
	Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE' -Name 'Application' -Type 'Dword' -Value '1'
.EXAMPLE
	Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'Debugger' -Value $blockedAppDebuggerValue -Type String
.EXAMPLE
	Set-RegistryKey -Key 'HKCU\Software\Microsoft\Example' -Name 'Data' -Value (0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x02,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x01,0x01,0x01,0x02,0x02,0x02) -Type 'Binary'
.EXAMPLE
    Set-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Value '(Default)'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		$Value,
		[Parameter(Mandatory=$false)]
		[ValidateSet('Binary','DWord','ExpandString','MultiString','None','QWord','String','Unknown')]
		[Microsoft.Win32.RegistryValueKind]$Type = 'String',
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID,
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
			[string]$RegistryValueWriteAction = 'set'
			
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[string]$key = Convert-RegistryPath -Key $key -SID $SID
			}
			Else {
				[string]$key = Convert-RegistryPath -Key $key
			}
			
			## Create registry key if it doesn't exist
			If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
				Try {
					Write-Log -Message "Create registry key [$key]." -Source ${CmdletName}
					# No forward slash found in Key. Use New-Item cmdlet to create registry key
					If ((($Key -split '/').Count - 1) -eq 0)
					{
						$null = New-Item -Path $key -ItemType 'Registry' -Force -ErrorAction 'Stop'
					}
					# Forward slash was found in Key. Use REG.exe ADD to create registry key 
					Else
					{
						[string]$CreateRegkeyResult = & reg.exe Add "$($Key.Substring($Key.IndexOf('::') + 2))"
						If ($global:LastExitCode -ne 0)
						{
							Throw "Failed to create registry key [$Key]"
						}
					}
				}
				Catch {
					Throw
				}
			}
			
			If ($Name) {
				## Set registry value if it doesn't exist
				If (-not (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction 'SilentlyContinue')) {
					Write-Log -Message "Set registry key value: [$key] [$name = $value]." -Source ${CmdletName}
					$null = New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType $Type -ErrorAction 'Stop'
				}
				## Update registry value if it does exist
				Else {
					[string]$RegistryValueWriteAction = 'update'
					If ($Name -eq '(Default)') {
						## Set Default registry key value with the following workaround, because Set-ItemProperty contains a bug and cannot set Default registry key value
						$null = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').OpenSubKey('','ReadWriteSubTree').SetValue($null,$value)
					} 
					Else {
						Write-Log -Message "Update registry key value: [$key] [$name = $value]." -Source ${CmdletName}
						$null = Set-ItemProperty -LiteralPath $key -Name $name -Value $value -ErrorAction 'Stop'
					}
				}
			}
		}
		Catch {
			If ($Name) {
				Write-Log -Message "Failed to $RegistryValueWriteAction value [$value] for registry key [$key] [$name]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to $RegistryValueWriteAction value [$value] for registry key [$key] [$name]: $($_.Exception.Message)"
				}
			}
			Else {
				Write-Log -Message "Failed to set registry key [$key]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to set registry key [$key]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Remove-RegistryKey
Function Remove-RegistryKey {
<#
.SYNOPSIS
	Deletes the specified registry key or value.
.DESCRIPTION
	Deletes the specified registry key or value.
.PARAMETER Key
	Path of the registry key to delete.
.PARAMETER Name
	Name of the registry value to delete.
.PARAMETER Recurse
	Delete registry key recursively.
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Remove-RegistryKey -Key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
.EXAMPLE
	Remove-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'RunAppInstall'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Recurse,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID,
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
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[string]$Key = Convert-RegistryPath -Key $Key -SID $SID
			}
			Else {
				[string]$Key = Convert-RegistryPath -Key $Key
			}
			
			If (-not ($Name)) {
				If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
					If ($Recurse) {
						Write-Log -Message "Delete registry key recursively [$Key]." -Source ${CmdletName}
						$null = Remove-Item -LiteralPath $Key -Force -Recurse -ErrorAction 'Stop'
					}
					Else {
						If ($null -eq (Get-ChildItem -LiteralPath $Key -ErrorAction 'Stop')){
							## Check if there are subkeys of $Key, if so, executing Remove-Item will hang. Avoiding this with Get-ChildItem.
							Write-Log -Message "Delete registry key [$Key]." -Source ${CmdletName}
							$null = Remove-Item -LiteralPath $Key -Force -ErrorAction 'Stop'
						}
						Else {
							Throw "Unable to delete child key(s) of [$Key] without [-Recurse] switch."
						}
					}
				}
				Else {
					Write-Log -Message "Unable to delete registry key [$Key] because it does not exist." -Severity 2 -Source ${CmdletName}
				}
			}
			Else {
				If (Test-Path -LiteralPath $Key -ErrorAction 'Stop') {
					Write-Log -Message "Delete registry value [$Key] [$Name]." -Source ${CmdletName}
					
					If ($Name -eq '(Default)') {
						## Remove (Default) registry key value with the following workaround because Remove-ItemProperty cannot remove the (Default) registry key value
						$null = (Get-Item -LiteralPath $Key -ErrorAction 'Stop').OpenSubKey('','ReadWriteSubTree').DeleteValue('')
					}
					Else {
						$null = Remove-ItemProperty -LiteralPath $Key -Name $Name -Force -ErrorAction 'Stop'
					}
				}
				Else {
					Write-Log -Message "Unable to delete registry value [$Key] [$Name] because registry key does not exist." -Severity 2 -Source ${CmdletName}
				}
			}
		}
		Catch [System.Management.Automation.PSArgumentException] {
			Write-Log -Message "Unable to delete registry value [$Key] [$Name] because it does not exist." -Severity 2 -Source ${CmdletName}
		}
		Catch {
			If (-not ($Name)) {
				Write-Log -Message "Failed to delete registry key [$Key]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to delete registry key [$Key]: $($_.Exception.Message)"
				}
			}
			Else {
				Write-Log -Message "Failed to delete registry value [$Key] [$Name]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to delete registry value [$Key] [$Name]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Invoke-HKCURegistrySettingsForAllUsers
Function Invoke-HKCURegistrySettingsForAllUsers {
<#
.SYNOPSIS
	Set current user registry settings for all current users and any new users in the future.
.DESCRIPTION
	Set HKCU registry settings for all current and future users by loading their NTUSER.dat registry hive file, and making the modifications.
	This function will modify HKCU settings for all users even when executed under the SYSTEM account.
	To ensure new users in the future get the registry edits, the Default User registry hive used to provision the registry for new users is modified.
	This function can be used as an alternative to using ActiveSetup for registry settings.
	The advantage of using this function over ActiveSetup is that a user does not have to log off and log back on before the changes take effect.
.PARAMETER RegistrySettings
	Script block which contains HKCU registry settings which should be modified for all users on the system. Must specify the -SID parameter for all HKCU settings.
.PARAMETER UserProfiles
	Specify the user profiles to modify HKCU registry settings for. Default is all user profiles except for system profiles.
.EXAMPLE
	[scriptblock]$HKCURegistrySettings = {
		Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'qmenable' -Value 0 -Type DWord -SID $UserProfile.SID
		Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'updatereliabilitydata' -Value 1 -Type DWord -SID $UserProfile.SID
	}
	Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $HKCURegistrySettings
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[scriptblock]$RegistrySettings,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[psobject[]]$UserProfiles = (Get-UserProfiles)
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		ForEach ($UserProfile in $UserProfiles) {
			Try {
				#  Set the path to the user's registry hive when it is loaded
				[string]$UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
				
				#  Set the path to the user's registry hive file
				[string]$UserRegistryHiveFile = Join-Path -Path $UserProfile.ProfilePath -ChildPath 'NTUSER.DAT'
				
				#  Load the User profile registry hive if it is not already loaded because the User is logged in
				[boolean]$ManuallyLoadedRegHive = $false
				If (-not (Test-Path -LiteralPath $UserRegistryPath)) {
					#  Load the User registry hive if the registry hive file exists
					If (Test-Path -LiteralPath $UserRegistryHiveFile -PathType 'Leaf') {
						Write-Log -Message "Load the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
						[string]$HiveLoadResult = & reg.exe load "`"HKEY_USERS\$($UserProfile.SID)`"" "`"$UserRegistryHiveFile`""
						
						If ($global:LastExitCode -ne 0) {
							Throw "Failed to load the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Failure message [$HiveLoadResult]. Continue..."
						}
						
						[boolean]$ManuallyLoadedRegHive = $true
					}
					Else {
						Throw "Failed to find the registry hive file [$UserRegistryHiveFile] for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. Continue..."
					}
				}
				Else {
					Write-Log -Message "The User [$($UserProfile.NTAccount)] registry hive is already loaded in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
				}
				
				## Execute ScriptBlock which contains code to manipulate HKCU registry.
				#  Make sure read/write calls to the HKCU registry hive specify the -SID parameter or settings will not be changed for all users.
				#  Example: Set-RegistryKey -Key 'HKCU\Software\Microsoft\Office\14.0\Common' -Name 'qmenable' -Value 0 -Type DWord -SID $UserProfile.SID
				Write-Log -Message 'Execute ScriptBlock to modify HKCU registry settings for all users.' -Source ${CmdletName}
				& $RegistrySettings
			}
			Catch {
				Write-Log -Message "Failed to modify the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)] `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
			Finally {
				If ($ManuallyLoadedRegHive) {
					Try {
						Write-Log -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
						[string]$HiveLoadResult = & reg.exe unload "`"HKEY_USERS\$($UserProfile.SID)`""
						
						If ($global:LastExitCode -ne 0) {
							Write-Log -Message "REG.exe failed to unload the registry hive and exited with exit code [$($global:LastExitCode)]. Performing manual garbage collection to ensure successful unloading of registry hive." -Severity 2 -Source ${CmdletName}
							[GC]::Collect()
							[GC]::WaitForPendingFinalizers()
							Start-Sleep -Seconds 5
							
							Write-Log -Message "Unload the User [$($UserProfile.NTAccount)] registry hive in path [HKEY_USERS\$($UserProfile.SID)]." -Source ${CmdletName}
							[string]$HiveLoadResult = & reg.exe unload "`"HKEY_USERS\$($UserProfile.SID)`""
							If ($global:LastExitCode -ne 0) { Throw "REG.exe failed with exit code [$($global:LastExitCode)] and result [$HiveLoadResult]." }
						}
					}
					Catch {
						Write-Log -Message "Failed to unload the registry hive for User [$($UserProfile.NTAccount)] with SID [$($UserProfile.SID)]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
					}
				}
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function ConvertTo-NTAccountOrSID
Function ConvertTo-NTAccountOrSID {
<#
.SYNOPSIS
	Convert between NT Account names and their security identifiers (SIDs).
.DESCRIPTION
	Specify either the NT Account name or the SID and get the other. Can also convert well known sid types.
.PARAMETER AccountName
	The Windows NT Account name specified in <domain>\<username> format.
	Use fully qualified account names (e.g., <domain>\<username>) instead of isolated names (e.g, <username>) because they are unambiguous and provide better performance.
.PARAMETER SID
	The Windows NT Account SID.
.PARAMETER WellKnownSIDName
	Specify the Well Known SID name translate to the actual SID (e.g., LocalServiceSid).
	To get all well known SIDs available on system: [enum]::GetNames([Security.Principal.WellKnownSidType])
.PARAMETER WellKnownToNTAccount
	Convert the Well Known SID to an NTAccount name
.EXAMPLE
	ConvertTo-NTAccountOrSID -AccountName 'CONTOSO\User1'
	Converts a Windows NT Account name to the corresponding SID
.EXAMPLE
	ConvertTo-NTAccountOrSID -SID 'S-1-5-21-1220945662-2111687655-725345543-14012660'
	Converts a Windows NT Account SID to the corresponding NT Account Name
.EXAMPLE
	ConvertTo-NTAccountOrSID -WellKnownSIDName 'NetworkServiceSid'
	Converts a Well Known SID name to a SID
.NOTES
	This is an internal script function and should typically not be called directly.
	The conversion can return an empty result if the user account does not exist anymore or if translation fails.
	http://blogs.technet.com/b/askds/archive/2011/07/28/troubleshooting-sid-translation-failures-from-the-obvious-to-the-not-so-obvious.aspx

	
	List of Well Known SIDs: http://msdn.microsoft.com/en-us/library/system.security.principal.wellknownsidtype(v=vs.110).aspx
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,ParameterSetName='NTAccountToSID',ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$AccountName,
		[Parameter(Mandatory=$true,ParameterSetName='SIDToNTAccount',ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$SID,
		[Parameter(Mandatory=$true,ParameterSetName='WellKnownName',ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$WellKnownSIDName,
		[Parameter(Mandatory=$false,ParameterSetName='WellKnownName')]
		[ValidateNotNullOrEmpty()]
		[switch]$WellKnownToNTAccount
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Switch ($PSCmdlet.ParameterSetName) {
				'SIDToNTAccount' {
					[string]$msg = "the SID [$SID] to an NT Account name"
					Write-Log -Message "Convert $msg." -Source ${CmdletName}
					
					$NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $SID
					$NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
					Write-Output -InputObject $NTAccount
				}
				'NTAccountToSID' {
					[string]$msg = "the NT Account [$AccountName] to a SID"
					Write-Log -Message "Convert $msg." -Source ${CmdletName}
					
					$NTAccount = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList $AccountName
					$NTAccountSID = $NTAccount.Translate([Security.Principal.SecurityIdentifier])
					Write-Output -InputObject $NTAccountSID
				}
				'WellKnownName' {
					If ($WellKnownToNTAccount) {
						[string]$ConversionType = 'NTAccount'
					}
					Else {
						[string]$ConversionType = 'SID'
					}
					[string]$msg = "the Well Known SID Name [$WellKnownSIDName] to a $ConversionType"
					Write-Log -Message "Convert $msg." -Source ${CmdletName}
					
					#  Get the SID for the root domain
					Try {
						$MachineRootDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'Stop').Domain.ToLower()
						$ADDomainObj = New-Object -TypeName 'System.DirectoryServices.DirectoryEntry' -ArgumentList "LDAP://$MachineRootDomain"
						$DomainSidInBinary = $ADDomainObj.ObjectSid
						$DomainSid = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($DomainSidInBinary[0], 0)
					}
					Catch {
						Write-Log -Message 'Unable to get Domain SID from Active Directory. Setting Domain SID to $null.' -Severity 2 -Source ${CmdletName}
						$DomainSid = $null
					}
					
					#  Get the SID for the well known SID name
					$WellKnownSidType = [Security.Principal.WellKnownSidType]::$WellKnownSIDName
					$NTAccountSID = New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ($WellKnownSidType, $DomainSid)
					
					If ($WellKnownToNTAccount) {
						$NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
						Write-Output -InputObject $NTAccount
					}
					Else {
						Write-Output -InputObject $NTAccountSID
					}
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to convert $msg. It may not be a valid account anymore or there is some other problem. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-UserProfiles
Function Get-UserProfiles {
<#
.SYNOPSIS
	Get the User Profile Path, User Account Sid, and the User Account Name for all users that log onto the machine and also the Default User (which does not log on).
.DESCRIPTION
	Get the User Profile Path, User Account Sid, and the User Account Name for all users that log onto the machine and also the Default User (which does  not log on).
	Please note that the NTAccount property may be empty for some user profiles but the SID and ProfilePath properties will always be populated.
.PARAMETER ExcludeNTAccount
	Specify NT account names in Domain\Username format to exclude from the list of user profiles.
.PARAMETER ExcludeSystemProfiles
	Exclude system profiles: SYSTEM, LOCAL SERVICE, NETWORK SERVICE. Default is: $true.
.PARAMETER ExcludeDefaultUser
	Exclude the Default User. Default is: $false.
.EXAMPLE
	Get-UserProfiles
	Returns the following properties for each user profile on the system: NTAccount, SID, ProfilePath
.EXAMPLE
	Get-UserProfiles -ExcludeNTAccount 'CONTOSO\Robot','CONTOSO\ntadmin'
.EXAMPLE
	[string[]]$ProfilePaths = Get-UserProfiles | Select-Object -ExpandProperty 'ProfilePath'
	Returns the user profile path for each user on the system. This information can then be used to make modifications under the user profile on the filesystem.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string[]]$ExcludeNTAccount,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ExcludeSystemProfiles = $true,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$ExcludeDefaultUser = $false
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Get the User Profile Path, User Account SID, and the User Account Name for all users that log onto the machine.' -Source ${CmdletName}
			
			## Get the User Profile Path, User Account Sid, and the User Account Name for all users that log onto the machine
			[string]$UserProfileListRegKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
			[psobject[]]$UserProfiles = Get-ChildItem -LiteralPath $UserProfileListRegKey -ErrorAction 'Stop' |
			ForEach-Object {
				Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction 'Stop' | Where-Object { ($_.ProfileImagePath) } |
				Select-Object @{ Label = 'NTAccount'; Expression = { $(ConvertTo-NTAccountOrSID -SID $_.PSChildName).Value } }, @{ Label = 'SID'; Expression = { $_.PSChildName } }, @{ Label = 'ProfilePath'; Expression = { $_.ProfileImagePath } }
			}
			If ($ExcludeSystemProfiles) {
				[string[]]$SystemProfiles = 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
				[psobject[]]$UserProfiles = $UserProfiles | Where-Object { $SystemProfiles -notcontains $_.SID }
			}
			If ($ExcludeNTAccount) {
				[psobject[]]$UserProfiles = $UserProfiles | Where-Object { $ExcludeNTAccount -notcontains $_.NTAccount }
			}
			
			## Find the path to the Default User profile
			If (-not $ExcludeDefaultUser) {
				[string]$UserProfilesDirectory = Get-ItemProperty -LiteralPath $UserProfileListRegKey -Name 'ProfilesDirectory' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'ProfilesDirectory'
				
				#  On Windows Vista or higher
				If (([version]$envOSVersion).Major -gt 5) {
					# Path to Default User Profile directory on Windows Vista or higher: By default, C:\Users\Default
					[string]$DefaultUserProfileDirectory = Get-ItemProperty -LiteralPath $UserProfileListRegKey -Name 'Default' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Default'
				}
				#  On Windows XP or lower
				Else {
					#  Default User Profile Name: By default, 'Default User'
					[string]$DefaultUserProfileName = Get-ItemProperty -LiteralPath $UserProfileListRegKey -Name 'DefaultUserProfile' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'DefaultUserProfile'
					
					#  Path to Default User Profile directory: By default, C:\Documents and Settings\Default User
					[string]$DefaultUserProfileDirectory = Join-Path -Path $UserProfilesDirectory -ChildPath $DefaultUserProfileName
				}
				
				## Create a custom object for the Default User profile.
				#  Since the Default User is not an actual User account, it does not have a username or a SID.
				#  We will make up a SID and add it to the custom object so that we have a location to load the default registry hive into later on.
				[psobject]$DefaultUserProfile = New-Object -TypeName 'PSObject' -Property @{
					NTAccount = 'Default User'
					SID = 'S-1-5-21-Default-User'
					ProfilePath = $DefaultUserProfileDirectory
				}
				
				## Add the Default User custom object to the User Profile list.
				$UserProfiles += $DefaultUserProfile
			}
			
			Write-Output -InputObject $UserProfiles
		}
		Catch {
			Write-Log -Message "Failed to create a custom object representing all user profiles on the machine. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-FileVersion
Function Get-FileVersion {
<#
.SYNOPSIS
	Gets the version of the specified file
.DESCRIPTION
	Gets the version of the specified file
.PARAMETER File
	Path of the file
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Get-FileVersion -File "$envProgramFilesX86\Adobe\Reader 11.0\Reader\AcroRd32.exe"
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$File,
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
			Write-Log -Message "Get file version info for file [$file]." -Source ${CmdletName}
			
			If (Test-Path -LiteralPath $File -PathType 'Leaf') {
				$fileVersion = (Get-Command -Name $file -ErrorAction 'Stop').FileVersionInfo.FileVersion
				If ($fileVersion) {
					## Remove product information to leave only the file version
					$fileVersion = ($fileVersion -split ' ' | Select-Object -First 1)
					
					Write-Log -Message "File version is [$fileVersion]." -Source ${CmdletName}
					Write-Output -InputObject $fileVersion
				}
				Else {
					Write-Log -Message 'No file version information found.' -Source ${CmdletName}
				}
			}
			Else {
				Throw "File path [$file] does not exist."
			}
		}
		Catch {
			Write-Log -Message "Failed to get file version info. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to get file version info: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function New-Shortcut
Function New-Shortcut {
<#
.SYNOPSIS
	Creates a new .lnk or .url type shortcut
.DESCRIPTION
	Creates a new shortcut .lnk or .url file, with configurable options
.PARAMETER Path
	Path to save the shortcut
.PARAMETER TargetPath
	Target path or URL that the shortcut launches
.PARAMETER Arguments
	Arguments to be passed to the target path
.PARAMETER IconLocation
	Location of the icon used for the shortcut
.PARAMETER IconIndex
	Executables, DLLs, ICO files with multiple icons need the icon index to be specified
.PARAMETER Description
	Description of the shortcut
.PARAMETER WorkingDirectory
	Working Directory to be used for the target path
.PARAMETER WindowStyle
	Windows style of the application. Options: Normal, Maximized, Minimized. Default is: Normal.
.PARAMETER RunAsAdmin
	Set shortcut to run program as administrator. This option will prompt user to elevate when executing shortcut.
.PARAMETER Hotkey
    Create a Hotkey to launch the shortcut, e.g. "CTRL+SHIFT+F"
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	New-Shortcut -Path "$envProgramData\Microsoft\Windows\Start Menu\My Shortcut.lnk" -TargetPath "$envWinDir\system32\notepad.exe" -IconLocation "$envWinDir\system32\notepad.exe" -Description 'Notepad' -WorkingDirectory "$envHomeDrive\$envHomePath"
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$TargetPath,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Arguments,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$IconLocation,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$IconIndex,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Description,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$WorkingDirectory,
		[Parameter(Mandatory=$false)]
		[ValidateSet('Normal','Maximized','Minimized')]
		[string]$WindowStyle,
		[Parameter(Mandatory=$false)]
		[switch]$RunAsAdmin,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Hotkey,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		If (-not $Shell) { [__comobject]$Shell = New-Object -ComObject 'WScript.Shell' -ErrorAction 'Stop' }
	}
	Process {
		Try {
			Try {
				[IO.FileInfo]$Path = [IO.FileInfo]$Path
				[string]$PathDirectory = $Path.DirectoryName
				
				If (-not (Test-Path -LiteralPath $PathDirectory -PathType 'Container' -ErrorAction 'Stop')) {
					Write-Log -Message "Create shortcut directory [$PathDirectory]." -Source ${CmdletName}
					$null = New-Item -Path $PathDirectory -ItemType 'Directory' -Force -ErrorAction 'Stop'
				}
			}
			Catch {
				Write-Log -Message "Failed to create shortcut directory [$PathDirectory]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				Throw
			}
			
			Write-Log -Message "Create shortcut [$($path.FullName)]." -Source ${CmdletName}
			If (($path.FullName).ToLower().EndsWith('.url')) {
				[string[]]$URLFile = '[InternetShortcut]'
				$URLFile += "URL=$targetPath"
				If ($iconIndex) { $URLFile += "IconIndex=$iconIndex" }
				If ($IconLocation) { $URLFile += "IconFile=$iconLocation" }
				$URLFile | Out-File -FilePath $path.FullName -Force -Encoding 'default' -ErrorAction 'Stop'
			}
			ElseIf (($path.FullName).ToLower().EndsWith('.lnk')) {
				If (($iconLocation -and $iconIndex) -and (-not ($iconLocation.Contains(',')))) {
					$iconLocation = $iconLocation + ",$iconIndex"
				}
				Switch ($windowStyle) {
					'Normal' { $windowStyleInt = 1 }
					'Maximized' { $windowStyleInt = 3 }
					'Minimized' { $windowStyleInt = 7 }
					Default { $windowStyleInt = 1 }
				}
				$shortcut = $shell.CreateShortcut($path.FullName)
				$shortcut.TargetPath = $targetPath
				$shortcut.Arguments = $arguments
				$shortcut.Description = $description
				$shortcut.WorkingDirectory = $workingDirectory
				$shortcut.WindowStyle = $windowStyleInt
                If ($hotkey) {$shortcut.Hotkey = $hotkey}
				If ($iconLocation) { $shortcut.IconLocation = $iconLocation }
				$shortcut.Save()
				
				## Set shortcut to run program as administrator
				If ($RunAsAdmin) {
					Write-Log -Message 'Set shortcut to run program as administrator.' -Source ${CmdletName}
					$TempFileName = [IO.Path]::GetRandomFileName()
					$TempFile = [IO.FileInfo][IO.Path]::Combine($Path.Directory, $TempFileName)
					$Writer = New-Object -TypeName 'System.IO.FileStream' -ArgumentList ($TempFile, ([IO.FileMode]::Create)) -ErrorAction 'Stop'
					$Reader = $Path.OpenRead()
					While ($Reader.Position -lt $Reader.Length) {
						$Byte = $Reader.ReadByte()
						If ($Reader.Position -eq 22) { $Byte = 34 }
						$Writer.WriteByte($Byte)
					}
					$Reader.Close()
					$Writer.Close()
					$Path.Delete()
					$null = Rename-Item -Path $TempFile -NewName $Path.Name -Force -ErrorAction 'Stop'
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to create shortcut [$($path.FullName)]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to create shortcut [$($path.FullName)]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Execute-ProcessAsUser
Function Execute-ProcessAsUser {
<#
.SYNOPSIS
	Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
.DESCRIPTION
	Execute a process with a logged in user account, by using a scheduled task, to provide interaction with user in the SYSTEM context.
.PARAMETER UserName
	Logged in Username under which to run the process from. Default is: The active console user. If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.
.PARAMETER Path
	Path to the file being executed.
.PARAMETER Parameters
	Arguments to be passed to the file being executed.
.PARAMETER SecureParameters
	Hides all parameters passed to the executable from the Toolkit log file.
.PARAMETER RunLevel
	Specifies the level of user rights that Task Scheduler uses to run the task. The acceptable values for this parameter are:
	- HighestAvailable: Tasks run by using the highest available privileges (Admin privileges for Administrators). Default Value.
	- LeastPrivilege: Tasks run by using the least-privileged user account (LUA) privileges.
.PARAMETER Wait
	Wait for the process, launched by the scheduled task, to complete execution before accepting more input. Default is $false.
.PARAMETER PassThru
	Returns the exit code from this function or the process launched by the scheduled task.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is $true.
.EXAMPLE
	Execute-ProcessAsUser -UserName 'CONTOSO\User' -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
	Execute process under a user account by specifying a username under which to execute it.
.EXAMPLE
	Execute-ProcessAsUser -Path "$PSHOME\powershell.exe" -Parameters "-Command & { & `"C:\Test\Script.ps1`"; Exit `$LastExitCode }" -Wait
	Execute process under a user account by using the default active logged in user that was detected when the toolkit was launched.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$UserName = $RunAsActiveUser.NTAccount,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Path,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Parameters = '',
		[Parameter(Mandatory=$false)]
		[switch]$SecureParameters = $false,
		[Parameter(Mandatory=$false)]
		[ValidateSet('HighestAvailable','LeastPrivilege')]
		[string]$RunLevel = 'HighestAvailable',
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$Wait = $false,
		[Parameter(Mandatory=$false)]
		[switch]$PassThru = $false,
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
		## Initialize exit code variable
		[int32]$executeProcessAsUserExitCode = 0
		
		## Confirm that the username field is not empty
		If (-not $UserName) {
			[int32]$executeProcessAsUserExitCode = 60009
			Write-Log -Message "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched." -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "The function [${CmdletName}] has a -UserName parameter that has an empty default value because no logged in users were detected when the toolkit was launched."
			}
			Else {
				Return
			}
		}
		
		## Confirm if the toolkit is running with administrator privileges
		If (($RunLevel -eq 'HighestAvailable') -and (-not $IsAdmin)) {
			[int32]$executeProcessAsUserExitCode = 60003
			Write-Log -Message "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'." -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "The function [${CmdletName}] requires the toolkit to be running with Administrator privileges if the [-RunLevel] parameter is set to 'HighestAvailable'."
			}
			Else {
				Return
			}
		}
		
		## Build the scheduled task XML name
		[string]$schTaskName = "$PSScriptToolkitName-ExecuteAsUser"
		
		##  Create the temporary App Deploy Toolkit files folder if it doesn't already exist
		If (-not (Test-Path -LiteralPath $dirPSScriptTemp -PathType 'Container')) {
			New-Item -Path $dirPSScriptTemp -ItemType 'Directory' -Force -ErrorAction 'Stop'
		}
		
		## If PowerShell.exe is being launched, then create a VBScript to launch PowerShell so that we can suppress the console window that flashes otherwise
		If (($Path -eq 'PowerShell.exe') -or ((Split-Path -Path $Path -Leaf) -eq 'PowerShell.exe')) {
			# Permit inclusion of double quotes in parameters
			If ($($Parameters.Substring($Parameters.Length - 1)) -eq '"') {
				[string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$', '') + ' & chr(34)' }
			Else {
				[string]$executeProcessAsUserParametersVBS = 'chr(34) & ' + "`"$($Path)`"" + ' & chr(34) & ' + '" ' + ($Parameters -replace '"', "`" & chr(34) & `"" -replace ' & chr\(34\) & "$','') + '"' }
			[string[]]$executeProcessAsUserScript = "strCommand = $executeProcessAsUserParametersVBS"
			$executeProcessAsUserScript += 'set oWShell = CreateObject("WScript.Shell")'
			$executeProcessAsUserScript += 'intReturn = oWShell.Run(strCommand, 0, true)'
			$executeProcessAsUserScript += 'WScript.Quit intReturn'
			$executeProcessAsUserScript | Out-File -FilePath "$dirPSScriptTemp\$($schTaskName).vbs" -Force -Encoding 'default' -ErrorAction 'SilentlyContinue'
			$Path = 'wscript.exe'
			$Parameters = "`"$dirPSScriptTemp\$($schTaskName).vbs`""
		}
		
		## Specify the scheduled task configuration in XML format
		[string]$xmlSchTask = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo />
  <Triggers />
  <Settings>
	<MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
	<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
	<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
	<AllowHardTerminate>true</AllowHardTerminate>
	<StartWhenAvailable>false</StartWhenAvailable>
	<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
	<IdleSettings>
	  <StopOnIdleEnd>false</StopOnIdleEnd>
	  <RestartOnIdle>false</RestartOnIdle>
	</IdleSettings>
	<AllowStartOnDemand>true</AllowStartOnDemand>
	<Enabled>true</Enabled>
	<Hidden>false</Hidden>
	<RunOnlyIfIdle>false</RunOnlyIfIdle>
	<WakeToRun>false</WakeToRun>
	<ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
	<Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
	<Exec>
	  <Command>$Path</Command>
	  <Arguments>$Parameters</Arguments>
	</Exec>
  </Actions>
  <Principals>
	<Principal id="Author">
	  <UserId>$UserName</UserId>
	  <LogonType>InteractiveToken</LogonType>
	  <RunLevel>$RunLevel</RunLevel>
	</Principal>
  </Principals>
</Task>
"@
		## Export the XML to file
		Try {
			#  Specify the filename to export the XML to
			[string]$xmlSchTaskFilePath = "$dirPSScriptTemp\$schTaskName.xml"
			[string]$xmlSchTask | Out-File -FilePath $xmlSchTaskFilePath -Force -ErrorAction 'Stop'
		}
		Catch {
			[int32]$executeProcessAsUserExitCode = 60007
			Write-Log -Message "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to export the scheduled task XML file [$xmlSchTaskFilePath]: $($_.Exception.Message)"
			}
			Else {
				Return
			}
		}
		
		## Create Scheduled Task to run the process with a logged-on user account
		If ($Parameters) {
			If ($SecureParameters) {
				Write-Log -Message "Create scheduled task to run the process [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
			}
			Else {
				Write-Log -Message "Create scheduled task to run the process [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}	
			}			
		}
		Else {
			Write-Log -Message "Create scheduled task to run the process [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
		}
		[psobject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/create /f /tn $schTaskName /xml `"$xmlSchTaskFilePath`"" -WindowStyle 'Hidden' -CreateNoWindow -PassThru
		If ($schTaskResult.ExitCode -ne 0) {
			[int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
			Write-Log -Message "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]." -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to create the scheduled task by importing the scheduled task XML file [$xmlSchTaskFilePath]."
			}
			Else {
				Return
			}
		}
		
		## Trigger the Scheduled Task
		If ($Parameters) {
			If ($SecureParameters) {
				Write-Log -Message "Trigger execution of scheduled task with command [$Path] (Parameters Hidden) as the logged-on user [$userName]..." -Source ${CmdletName}
			}
			Else {
				Write-Log -Message "Trigger execution of scheduled task with command [$Path $Parameters] as the logged-on user [$userName]..." -Source ${CmdletName}
			}
		}
		Else {
			Write-Log -Message "Trigger execution of scheduled task with command [$Path] as the logged-on user [$userName]..." -Source ${CmdletName}
		}
		[psobject]$schTaskResult = Execute-Process -Path $exeSchTasks -Parameters "/run /i /tn $schTaskName" -WindowStyle 'Hidden' -CreateNoWindow -Passthru
		If ($schTaskResult.ExitCode -ne 0) {
			[int32]$executeProcessAsUserExitCode = $schTaskResult.ExitCode
			Write-Log -Message "Failed to trigger scheduled task [$schTaskName]." -Severity 3 -Source ${CmdletName}
			#  Delete Scheduled Task
			Write-Log -Message 'Delete the scheduled task which did not trigger.' -Source ${CmdletName}
			Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ContinueOnError $true
			If (-not $ContinueOnError) {
				Throw "Failed to trigger scheduled task [$schTaskName]."
			}
			Else {
				Return
			}
		}
		
		## Wait for the process launched by the scheduled task to complete execution
		If ($Wait) {
			Write-Log -Message "Waiting for the process launched by the scheduled task [$schTaskName] to complete execution (this may take some time)..." -Source ${CmdletName}
			Start-Sleep -Seconds 1
			#If on Windows Vista or higer, Windows Task Scheduler 2.0 is supported. 'Schedule.Service' ComObject output is UI language independent
			If (([version]$envOSVersion).Major -gt 5) {
				Try {
					[__comobject]$ScheduleService = New-Object -ComObject 'Schedule.Service' -ErrorAction Stop
					$ScheduleService.Connect()
					$RootFolder = $ScheduleService.GetFolder('\')
					$Task = $RootFolder.GetTask("$schTaskName")
					# Task State(Status) 4 = 'Running'
					While ($Task.State -eq 4) {
						Start-Sleep -Seconds 5
					}
					#  Get the exit code from the process launched by the scheduled task
					[int32]$executeProcessAsUserExitCode = $Task.LastTaskResult
				}
				Catch {
					Write-Log -Message "Failed to retrieve information from Task Scheduler. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				}
				Finally {
					Try { $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($ScheduleService) } Catch { }
				}
			}
			#Windows Task Scheduler 1.0
			Else {
				While ((($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Status' | Select-Object -First 1) -eq 'Running') {
					Start-Sleep -Seconds 5
				}
				#  Get the exit code from the process launched by the scheduled task
				[int32]$executeProcessAsUserExitCode = ($exeSchTasksResult = & $exeSchTasks /query /TN $schTaskName /V /FO CSV) | ConvertFrom-CSV | Select-Object -ExpandProperty 'Last Result' | Select-Object -First 1
			}
			Write-Log -Message "Exit code from process launched by scheduled task [$executeProcessAsUserExitCode]." -Source ${CmdletName}
		}
		Else {
			Start-Sleep -Seconds 1
		}
		
		## Delete scheduled task
		Try {
			Write-Log -Message "Delete scheduled task [$schTaskName]." -Source ${CmdletName}
			Execute-Process -Path $exeSchTasks -Parameters "/delete /tn $schTaskName /f" -WindowStyle 'Hidden' -CreateNoWindow -ErrorAction 'Stop'
		}
		Catch {
			Write-Log -Message "Failed to delete scheduled task [$schTaskName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		If ($PassThru) { Write-Output -InputObject $executeProcessAsUserExitCode }
		
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Update-Desktop
Function Update-Desktop {
<#
.SYNOPSIS
	Refresh the Windows Explorer Shell, which causes the desktop icons and the environment variables to be reloaded.
.DESCRIPTION
	Refresh the Windows Explorer Shell, which causes the desktop icons and the environment variables to be reloaded.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Update-Desktop
.NOTES

	
#>
	[CmdletBinding()]
	Param (
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
			Write-Log -Message 'Refresh the Desktop and the Windows Explorer environment process block.' -Source ${CmdletName}
			[PSADT.Explorer]::RefreshDesktopAndEnvironmentVariables()
		}
		Catch {
			Write-Log -Message "Failed to refresh the Desktop and the Windows Explorer environment process block. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to refresh the Desktop and the Windows Explorer environment process block: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
Set-Alias -Name 'Refresh-Desktop' -Value 'Update-Desktop' -Scope 'Script' -Force -ErrorAction 'SilentlyContinue'
#endregion

#region Function Update-SessionEnvironmentVariables
Function Update-SessionEnvironmentVariables {
<#
.SYNOPSIS
	Updates the environment variables for the current PowerShell session with any environment variable changes that may have occurred during script execution.
.DESCRIPTION
	Environment variable changes that take place during script execution are not visible to the current PowerShell session.
	Use this function to refresh the current PowerShell session with all environment variable settings.
.PARAMETER LoadLoggedOnUserEnvironmentVariables
	If script is running in SYSTEM context, this option allows loading environment variables from the active console user. If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Update-SessionEnvironmentVariables
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$LoadLoggedOnUserEnvironmentVariables = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		[scriptblock]$GetEnvironmentVar = {
			Param (
				$Key,
				$Scope
			)
			[Environment]::GetEnvironmentVariable($Key, $Scope)
		}
	}
	Process {
		Try {
			Write-Log -Message 'Refresh the environment variables for this PowerShell session.' -Source ${CmdletName}
			
			If ($LoadLoggedOnUserEnvironmentVariables -and $RunAsActiveUser) {
				[string]$CurrentUserEnvironmentSID = $RunAsActiveUser.SID
			}
			Else {
				[string]$CurrentUserEnvironmentSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
			}
			[string]$MachineEnvironmentVars = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
			[string]$UserEnvironmentVars = "Registry::HKEY_USERS\$CurrentUserEnvironmentSID\Environment"
			
			## Update all session environment variables. Ordering is important here: $UserEnvironmentVars comes second so that we can override $MachineEnvironmentVars.
			$MachineEnvironmentVars, $UserEnvironmentVars | Get-Item | Where-Object { $_ } | ForEach-Object { $envRegPath = $_.PSPath; $_ | Select-Object -ExpandProperty 'Property' | ForEach-Object { Set-Item -LiteralPath "env:$($_)" -Value (Get-ItemProperty -LiteralPath $envRegPath -Name $_).$_ } }
			
			## Set PATH environment variable separately because it is a combination of the user and machine environment variables
			[string[]]$PathFolders = 'Machine', 'User' | ForEach-Object { (& $GetEnvironmentVar -Key 'PATH' -Scope $_) } | Where-Object { $_ } | ForEach-Object { $_.Trim(';') } | ForEach-Object { $_.Split(';') } | ForEach-Object { $_.Trim() } | ForEach-Object { $_.Trim('"') } | Select-Object -Unique
			$env:PATH = $PathFolders -join ';'
		}
		Catch {
			Write-Log -Message "Failed to refresh the environment variables for this PowerShell session. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to refresh the environment variables for this PowerShell session: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
Set-Alias -Name 'Refresh-SessionEnvironmentVariables' -Value 'Update-SessionEnvironmentVariables' -Scope 'Script' -Force -ErrorAction 'SilentlyContinue'
#endregion

#region Function Get-ScheduledTask
Function Get-ScheduledTask {
<#
.SYNOPSIS
	Retrieve all details for scheduled tasks on the local computer.
.DESCRIPTION
	Retrieve all details for scheduled tasks on the local computer using schtasks.exe. All property names have spaces and colons removed.
.PARAMETER TaskName
	Specify the name of the scheduled task to retrieve details for. Uses regex match to find scheduled task.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default: $true.
.EXAMPLE
	Get-ScheduledTask
	To display a list of all scheduled task properties.
.EXAMPLE
	Get-ScheduledTask | Out-GridView
	To display a grid view of all scheduled task properties.
.EXAMPLE
	Get-ScheduledTask | Select-Object -Property TaskName
	To display a list of all scheduled task names.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$TaskName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		If (-not $exeSchTasks) { [string]$exeSchTasks = "$env:WINDIR\system32\schtasks.exe" }
		[psobject[]]$ScheduledTasks = @()
	}
	Process {
		Try {
			Write-Log -Message 'Retrieve Scheduled Tasks...' -Source ${CmdletName}
			[string[]]$exeSchtasksResults = & $exeSchTasks /Query /V /FO CSV
			If ($global:LastExitCode -ne 0) { Throw "Failed to retrieve scheduled tasks using [$exeSchTasks]." }
			[psobject[]]$SchtasksResults = $exeSchtasksResults | ConvertFrom-CSV -Header 'HostName', 'TaskName', 'Next Run Time', 'Status', 'Logon Mode', 'Last Run Time', 'Last Result', 'Author', 'Task To Run', 'Start In', 'Comment', 'Scheduled Task State', 'Idle Time', 'Power Management', 'Run As User', 'Delete Task If Not Rescheduled', 'Stop Task If Runs X Hours and X Mins', 'Schedule', 'Schedule Type', 'Start Time', 'Start Date', 'End Date', 'Days', 'Months', 'Repeat: Every', 'Repeat: Until: Time', 'Repeat: Until: Duration', 'Repeat: Stop If Still Running' -ErrorAction 'Stop'
			
			If ($SchtasksResults) {
				ForEach ($SchtasksResult in $SchtasksResults) {
					If ($SchtasksResult.TaskName -match $TaskName) {
						$SchtasksResult | Get-Member -MemberType 'Properties' |
						ForEach -Begin {
							[hashtable]$Task = @{}
						} -Process {
							## Remove spaces and colons in property names. Do not set property value if line being processed is a column header (this will only work on English language machines).
							($Task.($($_.Name).Replace(' ','').Replace(':',''))) = If ($_.Name -ne $SchtasksResult.($_.Name)) { $SchtasksResult.($_.Name) }
						} -End {
							## Only add task to the custom object if all property values are not empty
							If (($Task.Values | Select-Object -Unique | Measure-Object).Count) {
								$ScheduledTasks += New-Object -TypeName 'PSObject' -Property $Task
							}
						}
					}
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to retrieve scheduled tasks. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to retrieve scheduled tasks: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-Output -InputObject $ScheduledTasks
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-UniversalDate
Function Get-UniversalDate {
<#
.SYNOPSIS
	Returns the date/time for the local culture in a universal sortable date time pattern.
.DESCRIPTION
	Converts the current datetime or a datetime string for the current culture into a universal sortable date time pattern, e.g. 2013-08-22 11:51:52Z
.PARAMETER DateTime
	Specify the DateTime in the current culture.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default: $false.
.EXAMPLE
	Get-UniversalDate
	Returns the current date in a universal sortable date time pattern.
.EXAMPLE
	Get-UniversalDate -DateTime '25/08/2013'
	Returns the date for the current culture in a universal sortable date time pattern.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		#  Get the current date
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$DateTime = ((Get-Date -Format ($culture).DateTimeFormat.FullDateTimePattern).ToString()),
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
			## If a universal sortable date time pattern was provided, remove the Z, otherwise it could get converted to a different time zone.
			If ($DateTime -match 'Z$') { $DateTime = $DateTime -replace 'Z$', '' }
			[datetime]$DateTime = [datetime]::Parse($DateTime, $culture)
			
			## Convert the date to a universal sortable date time pattern based on the current culture
			Write-Log -Message "Convert the date [$DateTime] to a universal sortable date time pattern based on the current culture [$($culture.Name)]." -Source ${CmdletName}
			[string]$universalDateTime = (Get-Date -Date $DateTime -Format ($culture).DateTimeFormat.UniversalSortableDateTimePattern -ErrorAction 'Stop').ToString()
			Write-Output -InputObject $universalDateTime
		}
		Catch {
			Write-Log -Message "The specified date/time [$DateTime] is not in a format recognized by the current culture [$($culture.Name)]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "The specified date/time [$DateTime] is not in a format recognized by the current culture: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-RunningProcesses
Function Get-RunningProcesses {
<#
.SYNOPSIS
	Gets the processes that are running from a custom list of process objects and also adds a property called ProcessDescription.
.DESCRIPTION
	Gets the processes that are running from a custom list of process objects and also adds a property called ProcessDescription.
.PARAMETER ProcessObjects
	Custom object containing the process objects to search for.
.EXAMPLE
	Get-RunningProcesses
.NOTES
	This is an internal script function and should typically not be called directly.

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0)]
		[psobject[]]$ProcessObjects,
		[Parameter(Mandatory=$false,Position=1)]
		[switch]$DisableLogging
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		If ($processObjects) {
			[string]$runningAppsCheck = ($processObjects | ForEach-Object { $_.ProcessName }) -join ','
			If (-not($DisableLogging)) {
				Write-Log -Message "Check for running application(s) [$runningAppsCheck]..." -Source ${CmdletName}
			}
			## Create an array of process names to search for
			[string[]]$processNames = $processObjects | ForEach-Object { $_.ProcessName }
			
			## Get all running processes and escape special characters. Match against the process names to search for to find running processes.
			[Diagnostics.Process[]]$runningProcesses = Get-Process | Where-Object { $processNames -contains $_.ProcessName }
			
			If ($runningProcesses) {
				[string]$runningProcessList = ($runningProcesses | ForEach-Object { $_.ProcessName } | Select-Object -Unique) -join ','
				If (-not($DisableLogging)) {
					Write-Log -Message "The following processes are running: [$runningProcessList]." -Source ${CmdletName}
					Write-Log -Message 'Resolve process descriptions...' -Source ${CmdletName}
				}
				## Resolve the running process names to descriptions
				ForEach ($runningProcess in $runningProcesses) {
					ForEach ($processObject in $processObjects) {
						If ($runningProcess.ProcessName -eq $processObject.ProcessName) {
							If ($processObject.ProcessDescription) {
								#  The description of the process provided as a Parameter to the function, e.g. -ProcessName "winword=Microsoft Office Word".
								$runningProcess | Add-Member -MemberType 'NoteProperty' -Name 'ProcessDescription' -Value $processObject.ProcessDescription -Force -PassThru -ErrorAction 'SilentlyContinue'
							}
							ElseIf ($runningProcess.Description) {
								#  If the process already has a description field specified, then use it
								$runningProcess | Add-Member -MemberType 'NoteProperty' -Name 'ProcessDescription' -Value $runningProcess.Description -Force -PassThru -ErrorAction 'SilentlyContinue'
							}
							Else {
								#  Fall back on the process name if no description is provided by the process or as a parameter to the function
								$runningProcess | Add-Member -MemberType 'NoteProperty' -Name 'ProcessDescription' -Value $runningProcess.ProcessName -Force -PassThru -ErrorAction 'SilentlyContinue'
							}
						}
					}
				}
			}
			Else {
 				If (-not($DisableLogging)) {
					Write-Log -Message 'Application(s) are not running.' -Source ${CmdletName}
				}
			}			
			Write-Output -InputObject $runningProcesses
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Invoke-ObjectMethod
Function Invoke-ObjectMethod {
<#
.SYNOPSIS
	Invoke method on any object.
.DESCRIPTION
	Invoke method on any object with or without using named parameters.
.PARAMETER InputObject
	Specifies an object which has methods that can be invoked.
.PARAMETER MethodName
	Specifies the name of a method to invoke.
.PARAMETER ArgumentList
	Argument to pass to the method being executed. Allows execution of method without specifying named parameters.
.PARAMETER Parameter
	Argument to pass to the method being executed. Allows execution of method by using named parameters.
.EXAMPLE
	$ShellApp = New-Object -ComObject 'Shell.Application'
	$null = Invoke-ObjectMethod -InputObject $ShellApp -MethodName 'MinimizeAll'
	Minimizes all windows.
.EXAMPLE
	$ShellApp = New-Object -ComObject 'Shell.Application'
	$null = Invoke-ObjectMethod -InputObject $ShellApp -MethodName 'Explore' -Parameter @{'vDir'='C:\Windows'}
	Opens the C:\Windows folder in a Windows Explorer window.
.NOTES
	This is an internal script function and should typically not be called directly.

	
#>
	[CmdletBinding(DefaultParameterSetName='Positional')]
	Param (
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNull()]
		[object]$InputObject,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullorEmpty()]
		[string]$MethodName,
		[Parameter(Mandatory=$false,Position=2,ParameterSetName='Positional')]
		[object[]]$ArgumentList,
		[Parameter(Mandatory=$true,Position=2,ParameterSetName='Named')]
		[ValidateNotNull()]
		[hashtable]$Parameter
	)
	
	Begin { }
	Process {
		If ($PSCmdlet.ParameterSetName -eq 'Named') {
			## Invoke method by using parameter names
			Write-Output -InputObject $InputObject.GetType().InvokeMember($MethodName, [Reflection.BindingFlags]::InvokeMethod, $null, $InputObject, ([object[]]($Parameter.Values)), $null, $null, ([string[]]($Parameter.Keys)))
		}
		Else {
			## Invoke method without using parameter names
			Write-Output -InputObject $InputObject.GetType().InvokeMember($MethodName, [Reflection.BindingFlags]::InvokeMethod, $null, $InputObject, $ArgumentList, $null, $null, $null)
		}
	}
	End { }
}
#endregion

#region Function Get-ObjectProperty
Function Get-ObjectProperty {
<#
.SYNOPSIS
	Get a property from any object.
.DESCRIPTION
	Get a property from any object.
.PARAMETER InputObject
	Specifies an object which has properties that can be retrieved.
.PARAMETER PropertyName
	Specifies the name of a property to retrieve.
.PARAMETER ArgumentList
	Argument to pass to the property being retrieved.
.EXAMPLE
	Get-ObjectProperty -InputObject $Record -PropertyName 'StringData' -ArgumentList @(1)
.NOTES
	This is an internal script function and should typically not be called directly.

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateNotNull()]
		[object]$InputObject,
		[Parameter(Mandatory=$true,Position=1)]
		[ValidateNotNullorEmpty()]
		[string]$PropertyName,
		[Parameter(Mandatory=$false,Position=2)]
		[object[]]$ArgumentList
	)
	
	Begin { }
	Process {
		## Retrieve property
		Write-Output -InputObject $InputObject.GetType().InvokeMember($PropertyName, [Reflection.BindingFlags]::GetProperty, $null, $InputObject, $ArgumentList, $null, $null, $null)
	}
	End { }
}
#endregion

#region Function Send-Keys
Function Send-Keys {
<#
.SYNOPSIS
	Send a sequence of keys to one or more application windows.
.DESCRIPTION
	Send a sequence of keys to one or more application window. If window title searched for returns more than one window, then all of them will receive the sent keys.
	Function does not work in SYSTEM context unless launched with "psexec.exe -s -i" to run it as an interactive process under the SYSTEM account.
.PARAMETER WindowTitle
	The title of the application window to search for using regex matching.
.PARAMETER GetAllWindowTitles
	Get titles for all open windows on the system.
.PARAMETER WindowHandle
	Send keys to a specific window where the Window Handle is already known.
.PARAMETER Keys
	The sequence of keys to send. Info on Key input at: http://msdn.microsoft.com/en-us/library/System.Windows.Forms.SendKeys(v=vs.100).aspx
.PARAMETER WaitSeconds
	An optional number of seconds to wait after the sending of the keys.
.EXAMPLE
	Send-Keys -WindowTitle 'foobar - Notepad' -Key 'Hello world'
	Send the sequence of keys "Hello world" to the application titled "foobar - Notepad".
.EXAMPLE
	Send-Keys -WindowTitle 'foobar - Notepad' -Key 'Hello world' -WaitSeconds 5
	Send the sequence of keys "Hello world" to the application titled "foobar - Notepad" and wait 5 seconds.
.EXAMPLE
	Send-Keys -WindowHandle ([IntPtr]17368294) -Key 'Hello world'
	Send the sequence of keys "Hello world" to the application with a Window Handle of '17368294'.
.NOTES

	http://msdn.microsoft.com/en-us/library/System.Windows.Forms.SendKeys(v=vs.100).aspx
	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false,Position=0)]
		[AllowEmptyString()]
		[ValidateNotNull()]
		[string]$WindowTitle,
		[Parameter(Mandatory=$false,Position=1)]
		[ValidateNotNullorEmpty()]
		[switch]$GetAllWindowTitles = $false,
		[Parameter(Mandatory=$false,Position=2)]
		[ValidateNotNullorEmpty()]
		[IntPtr]$WindowHandle,
		[Parameter(Mandatory=$false,Position=3)]
		[ValidateNotNullorEmpty()]
		[string]$Keys,
		[Parameter(Mandatory=$false,Position=4)]
		[ValidateNotNullorEmpty()]
		[int32]$WaitSeconds
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		## Load assembly containing class System.Windows.Forms.SendKeys
		Add-Type -AssemblyName 'System.Windows.Forms' -ErrorAction 'Stop'
		
		[scriptblock]$SendKeys = {
			Param (
				[Parameter(Mandatory=$true)]
				[ValidateNotNullorEmpty()]
				[IntPtr]$WindowHandle
			)
			Try {
				## Bring the window to the foreground
				[boolean]$IsBringWindowToFrontSuccess = [PSADT.UiAutomation]::BringWindowToFront($WindowHandle)
				If (-not $IsBringWindowToFrontSuccess) { Throw 'Failed to bring window to foreground.'}
				
				## Send the Key sequence
				If ($Keys) {
					[boolean]$IsWindowModal = If ([PSADT.UiAutomation]::IsWindowEnabled($WindowHandle)) { $false } Else { $true }
					If ($IsWindowModal) { Throw 'Unable to send keys to window because it may be disabled due to a modal dialog being shown.' }
					[Windows.Forms.SendKeys]::SendWait($Keys)
					Write-Log -Message "Sent key(s) [$Keys] to window title [$($Window.WindowTitle)] with window handle [$WindowHandle]." -Source ${CmdletName}
					
					If ($WaitSeconds) {
						Write-Log -Message "Sleeping for [$WaitSeconds] seconds." -Source ${CmdletName}
						Start-Sleep -Seconds $WaitSeconds
					}
				}
			}
			Catch {
				Write-Log -Message "Failed to send keys to window title [$($Window.WindowTitle)] with window handle [$WindowHandle]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
		}
	}
	Process {
		Try {
			If ($WindowHandle) {
				[psobject]$Window = Get-WindowTitle -GetAllWindowTitles | Where-Object { $_.WindowHandle -eq $WindowHandle }
				If (-not $Window) {
					Write-Log -Message "No windows with Window Handle [$WindowHandle] were discovered." -Severity 2 -Source ${CmdletName}
					Return
				}
				& $SendKeys -WindowHandle $Window.WindowHandle
			}
			Else {
				[hashtable]$GetWindowTitleSplat = @{}
				If ($GetAllWindowTitles) { $GetWindowTitleSplat.Add( 'GetAllWindowTitles', $GetAllWindowTitles) }
				Else { $GetWindowTitleSplat.Add( 'WindowTitle', $WindowTitle) }
				[psobject[]]$AllWindows = Get-WindowTitle @GetWindowTitleSplat
				If (-not $AllWindows) {
					Write-Log -Message 'No windows with the specified details were discovered.' -Severity 2 -Source ${CmdletName}
					Return
				}
				
				ForEach ($Window in $AllWindows) {
					& $SendKeys -WindowHandle $Window.WindowHandle
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to send keys to specified window. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Test-Battery
Function Test-Battery {
<#
.SYNOPSIS
	Tests whether the local machine is running on AC power or not.
.DESCRIPTION
	Tests whether the local machine is running on AC power and returns true/false. For detailed information, use -PassThru option.
.PARAMETER PassThru
	Outputs a hashtable containing the following properties:
	IsLaptop, IsUsingACPower, ACPowerLineStatus, BatteryChargeStatus, BatteryLifePercent, BatteryLifeRemaining, BatteryFullLifetime
.EXAMPLE
	Test-Battery
.EXAMPLE
	(Test-Battery -PassThru).IsLaptop
	Determines if the current system is a laptop or not.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru = $false
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		## PowerStatus class found in this assembly is more reliable than WMI in cases where the battery is failing.
		Add-Type -Assembly 'System.Windows.Forms' -ErrorAction 'SilentlyContinue'
		
		## Initialize a hashtable to store information about system type and power status
		[hashtable]$SystemTypePowerStatus = @{ }
	}
	Process {
		Write-Log -Message 'Check if system is using AC power or if it is running on battery...' -Source ${CmdletName}
		
		[Windows.Forms.PowerStatus]$PowerStatus = [Windows.Forms.SystemInformation]::PowerStatus
		
		## Get the system power status. Indicates whether the system is using AC power or if the status is unknown. Possible values:
		#	Offline : The system is not using AC power.
		#	Online  : The system is using AC power.
		#	Unknown : The power status of the system is unknown.
		[string]$PowerLineStatus = $PowerStatus.PowerLineStatus
		$SystemTypePowerStatus.Add('ACPowerLineStatus', $PowerStatus.PowerLineStatus)
		
		## Get the current battery charge status. Possible values: High, Low, Critical, Charging, NoSystemBattery, Unknown.
		[string]$BatteryChargeStatus = $PowerStatus.BatteryChargeStatus
		$SystemTypePowerStatus.Add('BatteryChargeStatus', $PowerStatus.BatteryChargeStatus)
		
		## Get the approximate amount, from 0.00 to 1.0, of full battery charge remaining.
		#  This property can report 1.0 when the battery is damaged and Windows can't detect a battery.
		#  Therefore, this property is only indicative of battery charge remaining if 'BatteryChargeStatus' property is not reporting 'NoSystemBattery' or 'Unknown'.
		[single]$BatteryLifePercent = $PowerStatus.BatteryLifePercent
		If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
			[single]$BatteryLifePercent = 0.0
		}
		$SystemTypePowerStatus.Add('BatteryLifePercent', $PowerStatus.BatteryLifePercent)
		
		## The reported approximate number of seconds of battery life remaining. It will report –1 if the remaining life is unknown because the system is on AC power.
		[int32]$BatteryLifeRemaining = $PowerStatus.BatteryLifeRemaining
		$SystemTypePowerStatus.Add('BatteryLifeRemaining', $PowerStatus.BatteryLifeRemaining)
		
		## Get the manufacturer reported full charge lifetime of the primary battery power source in seconds.
		#  The reported number of seconds of battery life available when the battery is fully charged, or -1 if it is unknown.
		#  This will only be reported if the battery supports reporting this information. You will most likely get -1, indicating unknown.
		[int32]$BatteryFullLifetime = $PowerStatus.BatteryFullLifetime
		$SystemTypePowerStatus.Add('BatteryFullLifetime', $PowerStatus.BatteryFullLifetime)
		
		## Determine if the system is using AC power
		[boolean]$OnACPower = $false
		If ($PowerLineStatus -eq 'Online') {
			Write-Log -Message 'System is using AC power.' -Source ${CmdletName}
			$OnACPower = $true
		}
		ElseIf ($PowerLineStatus -eq 'Offline') {
			Write-Log -Message 'System is using battery power.' -Source ${CmdletName}
		}
		ElseIf ($PowerLineStatus -eq 'Unknown') {
			If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
				Write-Log -Message "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. This is most likely due to a damaged battery so we will report system is using AC power." -Source ${CmdletName}
				$OnACPower = $true
			}
			Else {
				Write-Log -Message "System power status is [$PowerLineStatus] and battery charge status is [$BatteryChargeStatus]. Therefore, we will report system is using battery power." -Source ${CmdletName}
			}
		}
		$SystemTypePowerStatus.Add('IsUsingACPower', $OnACPower)
		
		## Determine if the system is a laptop
		[boolean]$IsLaptop = $false
		If (($BatteryChargeStatus -eq 'NoSystemBattery') -or ($BatteryChargeStatus -eq 'Unknown')) {
			$IsLaptop = $false
		}
		Else {
			$IsLaptop = $true
		}
		#  Chassis Types
		[int32[]]$ChassisTypes = Get-WmiObject -Class 'Win32_SystemEnclosure' | Where-Object { $_.ChassisTypes } | Select-Object -ExpandProperty 'ChassisTypes'
		Write-Log -Message "The following system chassis types were detected [$($ChassisTypes -join ',')]." -Source ${CmdletName}
		ForEach ($ChassisType in $ChassisTypes) {
			Switch ($ChassisType) {
				{ $_ -eq 9 -or $_ -eq 10 -or $_ -eq 14 } { $IsLaptop = $true } # 9=Laptop, 10=Notebook, 14=Sub Notebook
				{ $_ -eq 3 } { $IsLaptop = $false } # 3=Desktop
			}
		}
		#  Add IsLaptop property to hashtable
		$SystemTypePowerStatus.Add('IsLaptop', $IsLaptop)
		
		If ($PassThru) {
			Write-Output -InputObject $SystemTypePowerStatus
		}
		Else {
			Write-Output -InputObject $OnACPower
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Test-NetworkConnection
Function Test-NetworkConnection {
<#
.SYNOPSIS
	Tests for an active local network connection, excluding wireless and virtual network adapters.
.DESCRIPTION
	Tests for an active local network connection, excluding wireless and virtual network adapters, by querying the Win32_NetworkAdapter WMI class.
.EXAMPLE
	Test-NetworkConnection
.NOTES

	
#>
	[CmdletBinding()]
	Param (
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Write-Log -Message 'Check if system is using a wired network connection...' -Source ${CmdletName}
		
		[psobject[]]$networkConnected = Get-WmiObject -Class 'Win32_NetworkAdapter' | Where-Object { ($_.NetConnectionStatus -eq 2) -and ($_.NetConnectionID -match 'Local') -and ($_.NetConnectionID -notmatch 'Wireless') -and ($_.Name -notmatch 'Virtual') } -ErrorAction 'SilentlyContinue'
		[boolean]$onNetwork = $false
		If ($networkConnected) {
			Write-Log -Message 'Wired network connection found.' -Source ${CmdletName}
			[boolean]$onNetwork = $true
		}
		Else {
			Write-Log -Message 'Wired network connection not found.' -Source ${CmdletName}
		}
		
		Write-Output -InputObject $onNetwork
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Invoke-SCCMTask
Function Invoke-SCCMTask {
<#
.SYNOPSIS
	Triggers SCCM to invoke the requested schedule task id.
.DESCRIPTION
	Triggers SCCM to invoke the requested schedule task id.
.PARAMETER ScheduleId
	Name of the schedule id to trigger.
	Options: HardwareInventory, SoftwareInventory, HeartbeatDiscovery, SoftwareInventoryFileCollection, RequestMachinePolicy, EvaluateMachinePolicy,
	LocationServicesCleanup, SoftwareMeteringReport, SourceUpdate, PolicyAgentCleanup, RequestMachinePolicy2, CertificateMaintenance, PeerDistributionPointStatus,
	PeerDistributionPointProvisioning, ComplianceIntervalEnforcement, SoftwareUpdatesAgentAssignmentEvaluation, UploadStateMessage, StateMessageManager,
	SoftwareUpdatesScan, AMTProvisionCycle, UpdateStorePolicy, StateSystemBulkSend, ApplicationManagerPolicyAction, PowerManagementStartSummarizer
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Invoke-SCCMTask 'SoftwareUpdatesScan'
.EXAMPLE
	Invoke-SCCMTask
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateSet('HardwareInventory','SoftwareInventory','HeartbeatDiscovery','SoftwareInventoryFileCollection','RequestMachinePolicy','EvaluateMachinePolicy','LocationServicesCleanup','SoftwareMeteringReport','SourceUpdate','PolicyAgentCleanup','RequestMachinePolicy2','CertificateMaintenance','PeerDistributionPointStatus','PeerDistributionPointProvisioning','ComplianceIntervalEnforcement','SoftwareUpdatesAgentAssignmentEvaluation','UploadStateMessage','StateMessageManager','SoftwareUpdatesScan','AMTProvisionCycle','UpdateStorePolicy','StateSystemBulkSend','ApplicationManagerPolicyAction','PowerManagementStartSummarizer')]
		[string]$ScheduleID,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Invoke SCCM Schedule Task ID [$ScheduleId]..." -Source ${CmdletName}
				
			## Make sure SCCM client is installed and running
			Write-Log -Message 'Check to see if SCCM Client service [ccmexec] is installed and running.' -Source ${CmdletName}
			If (Test-ServiceExists -Name 'ccmexec') {
				If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
					Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state."
				}
			} Else {
				Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed.'
			}
			
			## Determine the SCCM Client Version
			Try {
				[version]$SCCMClientVersion = Get-WmiObject -Namespace 'ROOT\CCM' -Class 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'
				Write-Log -Message "Installed SCCM Client Version Number [$SCCMClientVersion]." -Source ${CmdletName}
			}
			Catch {
				Write-Log -Message "Failed to determine the SCCM client version number. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to determine the SCCM client version number.'
			}
			
			## Create a hashtable of Schedule IDs compatible with SCCM Client 2007
			[hashtable]$ScheduleIds = @{
				HardwareInventory = '{00000000-0000-0000-0000-000000000001}'; # Hardware Inventory Collection Task
				SoftwareInventory = '{00000000-0000-0000-0000-000000000002}'; # Software Inventory Collection Task
				HeartbeatDiscovery = '{00000000-0000-0000-0000-000000000003}'; # Heartbeat Discovery Cycle
				SoftwareInventoryFileCollection = '{00000000-0000-0000-0000-000000000010}'; # Software Inventory File Collection Task
				RequestMachinePolicy = '{00000000-0000-0000-0000-000000000021}'; # Request Machine Policy Assignments
				EvaluateMachinePolicy = '{00000000-0000-0000-0000-000000000022}'; # Evaluate Machine Policy Assignments
				RefreshDefaultMp = '{00000000-0000-0000-0000-000000000023}'; # Refresh Default MP Task
				RefreshLocationServices = '{00000000-0000-0000-0000-000000000024}'; # Refresh Location Services Task
				LocationServicesCleanup = '{00000000-0000-0000-0000-000000000025}'; # Location Services Cleanup Task
				SoftwareMeteringReport = '{00000000-0000-0000-0000-000000000031}'; # Software Metering Report Cycle
				SourceUpdate = '{00000000-0000-0000-0000-000000000032}'; # Source Update Manage Update Cycle
				PolicyAgentCleanup = '{00000000-0000-0000-0000-000000000040}'; # Policy Agent Cleanup Cycle
				RequestMachinePolicy2 = '{00000000-0000-0000-0000-000000000042}'; # Request Machine Policy Assignments
				CertificateMaintenance = '{00000000-0000-0000-0000-000000000051}'; # Certificate Maintenance Cycle
				PeerDistributionPointStatus = '{00000000-0000-0000-0000-000000000061}'; # Peer Distribution Point Status Task
				PeerDistributionPointProvisioning = '{00000000-0000-0000-0000-000000000062}'; # Peer Distribution Point Provisioning Status Task
				ComplianceIntervalEnforcement = '{00000000-0000-0000-0000-000000000071}'; # Compliance Interval Enforcement
				SoftwareUpdatesAgentAssignmentEvaluation = '{00000000-0000-0000-0000-000000000108}'; # Software Updates Agent Assignment Evaluation Cycle
				UploadStateMessage = '{00000000-0000-0000-0000-000000000111}'; # Send Unsent State Messages
				StateMessageManager = '{00000000-0000-0000-0000-000000000112}'; # State Message Manager Task
				SoftwareUpdatesScan = '{00000000-0000-0000-0000-000000000113}'; # Force Update Scan
				AMTProvisionCycle = '{00000000-0000-0000-0000-000000000120}'; # AMT Provision Cycle
			}
			
			## If SCCM 2012 Client or higher, modify hashtabe containing Schedule IDs so that it only has the ones compatible with this version of the SCCM client
			If ($SCCMClientVersion.Major -ge 5) {
				$ScheduleIds.Remove('PeerDistributionPointStatus')
				$ScheduleIds.Remove('PeerDistributionPointProvisioning')
				$ScheduleIds.Remove('ComplianceIntervalEnforcement')
				$ScheduleIds.Add('UpdateStorePolicy','{00000000-0000-0000-0000-000000000114}') # Update Store Policy
				$ScheduleIds.Add('StateSystemBulkSend','{00000000-0000-0000-0000-000000000116}') # State System Policy Bulk Send Low
				$ScheduleIds.Add('ApplicationManagerPolicyAction','{00000000-0000-0000-0000-000000000121}') # Application Manager Policy Action
				$ScheduleIds.Add('PowerManagementStartSummarizer','{00000000-0000-0000-0000-000000000131}') # Power Management Start Summarizer
			}
			
			## Determine if the requested Schedule ID is available on this version of the SCCM Client
			If (-not ($ScheduleIds.ContainsKey($ScheduleId))) {
				Throw "The requested ScheduleId [$ScheduleId] is not available with this version of the SCCM Client [$SCCMClientVersion]."
			}
			
			## Trigger SCCM task
			Write-Log -Message "Trigger SCCM Task ID [$ScheduleId]." -Source ${CmdletName}
			[Management.ManagementClass]$SmsClient = [WMIClass]'ROOT\CCM:SMS_Client'
			$null = $SmsClient.TriggerSchedule($ScheduleIds.$ScheduleID)
		}
		Catch {
			Write-Log -Message "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to trigger SCCM Schedule Task ID [$($ScheduleIds.$ScheduleId)]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Install-SCCMSoftwareUpdates
Function Install-SCCMSoftwareUpdates {
<#
.SYNOPSIS
	Scans for outstanding SCCM updates to be installed and installs the pending updates.
.DESCRIPTION
	Scans for outstanding SCCM updates to be installed and installs the pending updates.
	Only compatible with SCCM 2012 Client or higher. This function can take several minutes to run.
.PARAMETER SoftwareUpdatesScanWaitInSeconds
	The amount of time to wait in seconds for the software updates scan to complete. Default is: 180 seconds.
.PARAMETER WaitForPendingUpdatesTimeout
	The amount of time to wait for missing and pending updates to install before exiting the function. Default is: 45 minutes.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Install-SCCMSoftwareUpdates
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[int32]$SoftwareUpdatesScanWaitInSeconds = 180,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[timespan]$WaitForPendingUpdatesTimeout = $(New-TimeSpan -Minutes 45),
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Scan for and install pending SCCM software updates.' -Source ${CmdletName}
			
			## Make sure SCCM client is installed and running
			Write-Log -Message 'Check to see if SCCM Client service [ccmexec] is installed and running.' -Source ${CmdletName}
			If (Test-ServiceExists -Name 'ccmexec') {
				If ($(Get-Service -Name 'ccmexec' -ErrorAction 'SilentlyContinue').Status -ne 'Running') {
					Throw "SCCM Client Service [ccmexec] exists but it is not in a 'Running' state."
				}
			} Else {
				Throw 'SCCM Client Service [ccmexec] does not exist. The SCCM Client may not be installed.'
			}
			
			## Determine the SCCM Client Version
			Try {
				[version]$SCCMClientVersion = Get-WmiObject -Namespace 'ROOT\CCM' -Class 'CCM_InstalledComponent' -ErrorAction 'Stop' | Where-Object { $_.Name -eq 'SmsClient' } | Select-Object -ExpandProperty 'Version' -ErrorAction 'Stop'
				Write-Log -Message "Installed SCCM Client Version Number [$SCCMClientVersion]." -Source ${CmdletName}
			}
			Catch {
				Write-Log -Message "Failed to determine the SCCM client version number. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to determine the SCCM client version number.'
			}
			#  If SCCM 2007 Client or lower, exit function
			If ($SCCMClientVersion.Major -le 4) {
				Throw 'SCCM 2007 or lower, which is incompatible with this function, was detected on this system.'
			}
			
			$StartTime = Get-Date
			## Trigger SCCM client scan for Software Updates
			Write-Log -Message 'Trigger SCCM client scan for Software Updates...' -Source ${CmdletName}
			Invoke-SCCMTask -ScheduleId 'SoftwareUpdatesScan'
			
			Write-Log -Message "The SCCM client scan for Software Updates has been triggered. The script is suspended for [$SoftwareUpdatesScanWaitInSeconds] seconds to let the update scan finish." -Source ${CmdletName}
			Start-Sleep -Seconds $SoftwareUpdatesScanWaitInSeconds
			
			## Find the number of missing updates
			Try {
				[Management.ManagementObject[]]$CMMissingUpdates = @(Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -ErrorAction 'Stop')
			}
			Catch {
				Write-Log -Message "Failed to find the number of missing software updates. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName}
				Throw 'Failed to find the number of missing software updates.'
			}
			
			## Install missing updates and wait for pending updates to finish installing
			If ($CMMissingUpdates.Count) {
				#  Install missing updates
				Write-Log -Message "Install missing updates. The number of missing updates is [$($CMMissingUpdates.Count)]." -Source ${CmdletName}
				$CMInstallMissingUpdates = (Get-WmiObject -Namespace 'ROOT\CCM\ClientSDK' -Class 'CCM_SoftwareUpdatesManager' -List).InstallUpdates($CMMissingUpdates)
				
				#  Wait for pending updates to finish installing or the timeout value to expire
				Do {
					Start-Sleep -Seconds 60
					[array]$CMInstallPendingUpdates = @(Get-WmiObject -Namespace "ROOT\CCM\ClientSDK" -Query "SELECT * FROM CCM_SoftwareUpdate WHERE EvaluationState = 6 or EvaluationState = 7")
					Write-Log -Message "The number of updates pending installation is [$($CMInstallPendingUpdates.Count)]." -Source ${CmdletName}
				} While (($CMInstallPendingUpdates.Count -ne 0) -and ((New-TimeSpan -Start $StartTime -End $(Get-Date)) -lt $WaitForPendingUpdatesTimeout))
			}
			Else {
				Write-Log -Message 'There are no missing updates.' -Source ${CmdletName}
			}
		}
		Catch {
			Write-Log -Message "Failed to trigger installation of missing software updates. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to trigger installation of missing software updates: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Update-GroupPolicy
Function Update-GroupPolicy {
<#
.SYNOPSIS
	Performs a gpupdate command to refresh Group Policies on the local machine.
.DESCRIPTION
	Performs a gpupdate command to refresh Group Policies on the local machine.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Update-GroupPolicy
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		[string[]]$GPUpdateCmds = '/C echo N | gpupdate.exe /Target:Computer /Force', '/C echo N | gpupdate.exe /Target:User /Force'
		[int32]$InstallCount = 0
		ForEach ($GPUpdateCmd in $GPUpdateCmds) {
			Try {
				If ($InstallCount -eq 0) {
					[string]$InstallMsg = 'Update Group Policies for the Machine'
					Write-Log -Message "$($InstallMsg)..." -Source ${CmdletName}
				}
				Else {
					[string]$InstallMsg = 'Update Group Policies for the User'
					Write-Log -Message "$($InstallMsg)..." -Source ${CmdletName}
				}
				[psobject]$ExecuteResult = Execute-Process -Path "$envWindir\system32\cmd.exe" -Parameters $GPUpdateCmd -WindowStyle 'Hidden' -PassThru
				
				If ($ExecuteResult.ExitCode -ne 0) {
					If ($ExecuteResult.ExitCode -eq 60002) {
						Throw "Execute-Process function failed with exit code [$($ExecuteResult.ExitCode)]."
					}
					Else {
						Throw "gpupdate.exe failed with exit code [$($ExecuteResult.ExitCode)]."
					}
				}
				$InstallCount++
			}
			Catch {
				Write-Log -Message "Failed to $($InstallMsg). `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to $($InstallMsg): $($_.Exception.Message)"
				}
				Continue
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Set-ActiveSetup
Function Set-ActiveSetup {
<#
.SYNOPSIS
	Creates an Active Setup entry in the registry to execute a file for each user upon login.
.DESCRIPTION
	Active Setup allows handling of per-user changes registry/file changes upon login.
	A registry key is created in the HKLM registry hive which gets replicated to the HKCU hive when a user logs in.
	If the "Version" value of the Active Setup entry in HKLM is higher than the version value in HKCU, the file referenced in "StubPath" is executed.
	This Function:
	- Creates the registry entries in HKLM:SOFTWARE\Microsoft\Active Setup\Installed Components\$installName.
	- Creates StubPath value depending on the file extension of the $StubExePath parameter.
	- Handles Version value with YYYYMMDDHHMMSS granularity to permit re-installs on the same day and still trigger Active Setup after Version increase.
	- Copies/overwrites the StubPath file to $StubExePath destination path if file exists in 'Files' subdirectory of script directory.
	- Executes the StubPath file for the current user as long as not in Session 0 (no need to logout/login to trigger Active Setup).
.PARAMETER StubExePath
	Full destination path to the file that will be executed for each user that logs in.
	If this file exists in the 'Files' subdirectory of the script directory, it will be copied to the destination path.
.PARAMETER Arguments
	Arguments to pass to the file being executed.
.PARAMETER Description
	Description for the Active Setup. Users will see "Setting up personalized settings for: $Description" at logon. Default is: $installName.
.PARAMETER Key
	Name of the registry key for the Active Setup entry. Default is: $installName.
.PARAMETER Version
	Optional. Specify version for Active setup entry. Active Setup is not triggered if Version value has more than 8 consecutive digits. Use commas to get around this limitation.
.PARAMETER Locale
	Optional. Arbitrary string used to specify the installation language of the file being executed. Not replicated to HKCU.
.PARAMETER PurgeActiveSetupKey
	Remove Active Setup entry from HKLM registry hive. Will also load each logon user's HKCU registry hive to remove Active Setup entry.
.PARAMETER DisableActiveSetup
	Disables the Active Setup entry so that the StubPath file will not be executed.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Set-ActiveSetup -StubExePath 'C:\Users\Public\Company\ProgramUserConfig.vbs' -Arguments '/Silent' -Description 'Program User Config' -Key 'ProgramUserConfig' -Locale 'en'
.EXAMPLE
	Set-ActiveSetup -StubExePath "$envWinDir\regedit.exe" -Arguments "/S `"%SystemDrive%\Program Files (x86)\PS App Deploy\PSPSScriptHKCUSettings.reg`"" -Description 'PS App Deploy Config' -Key 'PS_App_Deploy_Config' -ContinueOnError $true
.EXAMPLE
	Set-ActiveSetup -Key 'ProgramUserConfig' -PurgeActiveSetupKey
	Deletes "ProgramUserConfig" active setup entry from all registry hives.
.NOTES
	Original code borrowed from: Denis St-Pierre (Ottawa, Canada), Todd MacNaught (Ottawa, Canada)

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[string]$StubExePath,
		[Parameter(Mandatory=$false,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[string]$Arguments,
		[Parameter(Mandatory=$false,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[string]$Description = $installName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$Key = $installName,
		[Parameter(Mandatory=$false,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[string]$Version = ((Get-Date -Format 'yyMM,ddHH,mmss').ToString()), # Ex: 1405,1515,0522
		[Parameter(Mandatory=$false,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[string]$Locale,
		[Parameter(Mandatory=$false,ParameterSetName='Create')]
		[ValidateNotNullorEmpty()]
		[switch]$DisableActiveSetup = $false,
		[Parameter(Mandatory=$true,ParameterSetName='Purge')]
		[switch]$PurgeActiveSetupKey,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			[string]$ActiveSetupKey = "HKLM:SOFTWARE\Microsoft\Active Setup\Installed Components\$Key"
			[string]$HKCUActiveSetupKey = "HKCU:Software\Microsoft\Active Setup\Installed Components\$Key"
			
			## Delete Active Setup registry entry from the HKLM hive and for all logon user registry hives on the system
			If ($PurgeActiveSetupKey) {
				Write-Log -Message "Remove Active Setup entry [$ActiveSetupKey]." -Source ${CmdletName}
				Remove-RegistryKey -Key $ActiveSetupKey -Recurse
				
				Write-Log -Message "Remove Active Setup entry [$HKCUActiveSetupKey] for all log on user registry hives on the system." -Source ${CmdletName}
				[scriptblock]$RemoveHKCUActiveSetupKey = { Remove-RegistryKey -Key $HKCUActiveSetupKey -SID $UserProfile.SID -Recurse }
				Invoke-HKCURegistrySettingsForAllUsers -RegistrySettings $RemoveHKCUActiveSetupKey -UserProfiles (Get-UserProfiles -ExcludeDefaultUser)
				Return
			}
			
			## Verify a file with a supported file extension was specified in $StubExePath
			[string[]]$StubExePathFileExtensions = '.exe', '.vbs', '.cmd', '.ps1', '.js'
			[string]$StubExeExt = [IO.Path]::GetExtension($StubExePath)
			If ($StubExePathFileExtensions -notcontains $StubExeExt) {
				Throw "Unsupported Active Setup StubPath file extension [$StubExeExt]."
			}
			
			## Copy file to $StubExePath from the 'Files' subdirectory of the script directory (if it exists there)
			[string]$StubExePath = [Environment]::ExpandEnvironmentVariables($StubExePath)
			[string]$ActiveSetupFileName = [IO.Path]::GetFileName($StubExePath)
			[string]$StubExeFile = Join-Path -Path $dirInstallers -ChildPath $ActiveSetupFileName
			If (Test-Path -LiteralPath $StubExeFile -PathType 'Leaf') {
				#  This will overwrite the StubPath file if $StubExePath already exists on target
				Copy-File -Path $StubExeFile -Destination $StubExePath -ContinueOnError $false
			}
			
			## Check if the $StubExePath file exists
			If (-not (Test-Path -LiteralPath $StubExePath -PathType 'Leaf')) { Throw "Active Setup StubPath file [$ActiveSetupFileName] is missing." }
			
			## Define Active Setup StubPath according to file extension of $StubExePath
			Switch ($StubExeExt) {
				'.exe' {
					[string]$CUStubExePath = $StubExePath
					[string]$CUArguments = $Arguments
					[string]$StubPath = "$CUStubExePath"
				}
				{'.vbs','.js' -contains $StubExeExt} {
					[string]$CUStubExePath = "$envWinDir\system32\cscript.exe"
					[string]$CUArguments = "//nologo `"$StubExePath`""
					[string]$StubPath = "$CUStubExePath $CUArguments"
				}
				'.cmd' {
					[string]$CUStubExePath = "$envWinDir\system32\CMD.exe"
					[string]$CUArguments = "/C `"$StubExePath`""
					[string]$StubPath = "$CUStubExePath $CUArguments"
				}
				'.ps1' {
					[string]$CUStubExePath = "$PSHOME\powershell.exe"
					[string]$CUArguments = "-ExecutionPolicy Bypass -NoProfile -NoLogo -WindowStyle Hidden -Command & { & `\`"$StubExePath`\`"}"
					[string]$StubPath = "$CUStubExePath $CUArguments"
				}
			}
			If ($Arguments) {
				[string]$StubPath = "$StubPath $Arguments"
				If ($StubExeExt -ne '.exe') { [string]$CUArguments = "$CUArguments $Arguments" }
			}
			
			## Create the Active Setup entry in the registry
			[scriptblock]$SetActiveSetupRegKeys = {
				Param (
					[Parameter(Mandatory=$true)]
					[ValidateNotNullorEmpty()]
					[string]$ActiveSetupRegKey,
					[Parameter(Mandatory=$false)]
					[ValidateNotNullorEmpty()]
					[string]$SID
				)
				If ($SID) {
					Set-RegistryKey -Key $ActiveSetupRegKey -Name '(Default)' -Value $Description -SID $SID -ContinueOnError $false
					Set-RegistryKey -Key $ActiveSetupRegKey -Name 'StubPath' -Value $StubPath -Type 'String' -SID $SID -ContinueOnError $false
					Set-RegistryKey -Key $ActiveSetupRegKey -Name 'Version' -Value $Version -SID $SID -ContinueOnError $false
					If ($Locale) { Set-RegistryKey -Key $ActiveSetupRegKey -Name 'Locale' -Value $Locale -SID $SID -ContinueOnError $false }
					If ($DisableActiveSetup) {
						Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 0 -Type 'DWord' -SID $SID -ContinueOnError $false
					}
					Else {
						Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 1 -Type 'DWord' -SID $SID -ContinueOnError $false
					}
				}
				Else {
					Set-RegistryKey -Key $ActiveSetupRegKey -Name '(Default)' -Value $Description -ContinueOnError $false
					Set-RegistryKey -Key $ActiveSetupRegKey -Name 'StubPath' -Value $StubPath -Type 'String' -ContinueOnError $false
					Set-RegistryKey -Key $ActiveSetupRegKey -Name 'Version' -Value $Version -ContinueOnError $false
					If ($Locale) { Set-RegistryKey -Key $ActiveSetupRegKey -Name 'Locale' -Value $Locale -ContinueOnError $false }
					If ($DisableActiveSetup) {
						Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 0 -Type 'DWord' -ContinueOnError $false
					}
					Else {
						Set-RegistryKey -Key $ActiveSetupRegKey -Name 'IsInstalled' -Value 1 -Type 'DWord' -ContinueOnError $false
					}
				}
				
			}
			& $SetActiveSetupRegKeys -ActiveSetupRegKey $ActiveSetupKey
			
			## Execute the StubPath file for the current user as long as not in Session 0
			If ($SessionZero) {
				If ($RunAsActiveUser) {
					Write-Log -Message "Session 0 detected: Execute Active Setup StubPath file for currently logged in user [$($RunAsActiveUser.NTAccount)]." -Source ${CmdletName}
					If ($CUArguments) {
						Execute-ProcessAsUser -Path $CUStubExePath -Parameters $CUArguments -Wait -ContinueOnError $true
					}
					Else {
						Execute-ProcessAsUser -Path $CUStubExePath -Wait -ContinueOnError $true
					}
					& $SetActiveSetupRegKeys -ActiveSetupRegKey $HKCUActiveSetupKey -SID $RunAsActiveUser.SID
				}
				Else {
					Write-Log -Message 'Session 0 detected: No logged in users detected. Active Setup StubPath file will execute when users first log into their account.' -Source ${CmdletName}
				}
			}
			Else {
				Write-Log -Message 'Execute Active Setup StubPath file for the current user.' -Source ${CmdletName}
				If ($CUArguments) {
					$ExecuteResults = Execute-Process -FilePath $CUStubExePath -Parameters $CUArguments -PassThru
				}
				Else {
					$ExecuteResults = Execute-Process -FilePath $CUStubExePath -PassThru
				}
				& $SetActiveSetupRegKeys -ActiveSetupRegKey $HKCUActiveSetupKey
			}
		}
		Catch {
			Write-Log -Message "Failed to set Active Setup registry entry. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed to set Active Setup registry entry: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Test-ServiceExists
Function Test-ServiceExists {
<#
.SYNOPSIS
	Check to see if a service exists.
.DESCRIPTION
	Check to see if a service exists (using WMI method because Get-Service will generate ErrorRecord if service doesn't exist).
.PARAMETER Name
	Specify the name of the service.
	Note: Service name can be found by executing "Get-Service | Format-Table -AutoSize -Wrap" or by using the properties screen of a service in services.msc.
.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.
.PARAMETER PassThru
	Return the WMI service object.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Test-ServiceExists -Name 'wuauserv'
.EXAMPLE
	Test-ServiceExists -Name 'testservice' -PassThru | Where-Object { $_ } | ForEach-Object { $_.Delete() }
	Check if a service exists and then delete it by using the -PassThru parameter.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			$ServiceObject = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_Service' -Filter "Name='$Name'" -ErrorAction 'Stop'
			# If nothing is returned from Win32_Service, check Win32_BaseService
			If (-not ($ServiceObject) ) { 
				$ServiceObject = Get-WmiObject -ComputerName $ComputerName -Class 'Win32_BaseService' -Filter "Name='$Name'" -ErrorAction 'Stop' 
			}

			If ($ServiceObject) {
				Write-Log -Message "Service [$Name] exists." -Source ${CmdletName}
				If ($PassThru) { Write-Output -InputObject $ServiceObject } Else { Write-Output -InputObject $true }
			}
			Else {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName}
				If ($PassThru) { Write-Output -InputObject $ServiceObject } Else { Write-Output -InputObject $false }
			}
		}
		Catch {
			Write-Log -Message "Failed check to see if service [$Name] exists." -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed check to see if service [$Name] exists: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Stop-ServiceAndDependencies
Function Stop-ServiceAndDependencies {
<#
.SYNOPSIS
	Stop Windows service and its dependencies.
.DESCRIPTION
	Stop Windows service and its dependencies.
.PARAMETER Name
	Specify the name of the service.
.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.
.PARAMETER SkipServiceExistsTest
	Choose to skip the test to check whether or not the service exists if it was already done outside of this function.
.PARAMETER SkipDependentServices
	Choose to skip checking for and stopping dependent services. Default is: $false.
.PARAMETER PendingStatusWait
	The amount of time to wait for a service to get out of a pending state before continuing. Default is 60 seconds.
.PARAMETER PassThru
	Return the System.ServiceProcess.ServiceController service object.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Stop-ServiceAndDependencies -Name 'wuauserv'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$SkipServiceExistsTest,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$SkipDependentServices,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[timespan]$PendingStatusWait = (New-TimeSpan -Seconds 60),
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## Check to see if the service exists
			If ((-not $SkipServiceExistsTest) -and (-not (Test-ServiceExists -ComputerName $ComputerName -Name $Name -ContinueOnError $false))) {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName} -Severity 2
				Throw "Service [$Name] does not exist."
			}
			
			## Get the service object
			Write-Log -Message "Get the service object for service [$Name]." -Source ${CmdletName}
			[ServiceProcess.ServiceController]$Service = Get-Service -ComputerName $ComputerName -Name $Name -ErrorAction 'Stop'
			## Wait up to 60 seconds if service is in a pending state
			[string[]]$PendingStatus = 'ContinuePending', 'PausePending', 'StartPending', 'StopPending'
			If ($PendingStatus -contains $Service.Status) {
				Switch ($Service.Status) {
					'ContinuePending' { $DesiredStatus = 'Running' }
					'PausePending' { $DesiredStatus = 'Paused' }
					'StartPending' { $DesiredStatus = 'Running' }
					'StopPending' { $DesiredStatus = 'Stopped' }
				}
				Write-Log -Message "Waiting for up to [$($PendingStatusWait.TotalSeconds)] seconds to allow service pending status [$($Service.Status)] to reach desired status [$DesiredStatus]." -Source ${CmdletName}
				$Service.WaitForStatus([ServiceProcess.ServiceControllerStatus]$DesiredStatus, $PendingStatusWait)
				$Service.Refresh()
			}
			## Discover if the service is currently running
			Write-Log -Message "Service [$($Service.ServiceName)] with display name [$($Service.DisplayName)] has a status of [$($Service.Status)]." -Source ${CmdletName}
			If ($Service.Status -ne 'Stopped') {
				#  Discover all dependent services that are running and stop them
				If (-not $SkipDependentServices) {
					Write-Log -Message "Discover all dependent service(s) for service [$Name] which are not 'Stopped'." -Source ${CmdletName}
					[ServiceProcess.ServiceController[]]$DependentServices = Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -DependentServices -ErrorAction 'Stop' | Where-Object { $_.Status -ne 'Stopped' }
					If ($DependentServices) {
						ForEach ($DependentService in $DependentServices) {
							Write-Log -Message "Stop dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]." -Source ${CmdletName}
							Try {
								Stop-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $DependentService.ServiceName -ErrorAction 'Stop') -Force -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
							}
							Catch {
								Write-Log -Message "Failed to start dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]. Continue..." -Severity 2 -Source ${CmdletName}
								Continue
							}
						}
					}
					Else {
						Write-Log -Message "Dependent service(s) were not discovered for service [$Name]." -Source ${CmdletName}
					}
				}
				#  Stop the parent service
				Write-Log -Message "Stop parent service [$($Service.ServiceName)] with display name [$($Service.DisplayName)]." -Source ${CmdletName}
				[ServiceProcess.ServiceController]$Service = Stop-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -ErrorAction 'Stop') -Force -PassThru -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
			}
		}
		Catch {
			Write-Log -Message "Failed to stop the service [$Name]. `n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to stop the service [$Name]: $($_.Exception.Message)"
			}
		}
		Finally {
			#  Return the service object if option selected
			If ($PassThru -and $Service) { Write-Output -InputObject $Service }
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Start-ServiceAndDependencies
Function Start-ServiceAndDependencies {
<#
.SYNOPSIS
	Start Windows service and its dependencies.
.DESCRIPTION
	Start Windows service and its dependencies.
.PARAMETER Name
	Specify the name of the service.
.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.
.PARAMETER SkipServiceExistsTest
	Choose to skip the test to check whether or not the service exists if it was already done outside of this function.
.PARAMETER SkipDependentServices
	Choose to skip checking for and starting dependent services. Default is: $false.
.PARAMETER PendingStatusWait
	The amount of time to wait for a service to get out of a pending state before continuing. Default is 60 seconds.
.PARAMETER PassThru
	Return the System.ServiceProcess.ServiceController service object.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Start-ServiceAndDependencies -Name 'wuauserv'
.NOTES

	
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$SkipServiceExistsTest,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$SkipDependentServices,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[timespan]$PendingStatusWait = (New-TimeSpan -Seconds 60),
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## Check to see if the service exists
			If ((-not $SkipServiceExistsTest) -and (-not (Test-ServiceExists -ComputerName $ComputerName -Name $Name -ContinueOnError $false))) {
				Write-Log -Message "Service [$Name] does not exist." -Source ${CmdletName} -Severity 2
				Throw "Service [$Name] does not exist."
			}
			
			## Get the service object
			Write-Log -Message "Get the service object for service [$Name]." -Source ${CmdletName}
			[ServiceProcess.ServiceController]$Service = Get-Service -ComputerName $ComputerName -Name $Name -ErrorAction 'Stop'
			## Wait up to 60 seconds if service is in a pending state
			[string[]]$PendingStatus = 'ContinuePending', 'PausePending', 'StartPending', 'StopPending'
			If ($PendingStatus -contains $Service.Status) {
				Switch ($Service.Status) {
					'ContinuePending' { $DesiredStatus = 'Running' }
					'PausePending' { $DesiredStatus = 'Paused' }
					'StartPending' { $DesiredStatus = 'Running' }
					'StopPending' { $DesiredStatus = 'Stopped' }
				}
				Write-Log -Message "Waiting for up to [$($PendingStatusWait.TotalSeconds)] seconds to allow service pending status [$($Service.Status)] to reach desired status [$DesiredStatus]." -Source ${CmdletName}
				$Service.WaitForStatus([ServiceProcess.ServiceControllerStatus]$DesiredStatus, $PendingStatusWait)
				$Service.Refresh()
			}
			## Discover if the service is currently stopped
			Write-Log -Message "Service [$($Service.ServiceName)] with display name [$($Service.DisplayName)] has a status of [$($Service.Status)]." -Source ${CmdletName}
			If ($Service.Status -ne 'Running') {
				#  Start the parent service
				Write-Log -Message "Start parent service [$($Service.ServiceName)] with display name [$($Service.DisplayName)]." -Source ${CmdletName}
				[ServiceProcess.ServiceController]$Service = Start-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -ErrorAction 'Stop') -PassThru -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
				
				#  Discover all dependent services that are stopped and start them
				If (-not $SkipDependentServices) {
					Write-Log -Message "Discover all dependent service(s) for service [$Name] which are not 'Running'." -Source ${CmdletName}
					[ServiceProcess.ServiceController[]]$DependentServices = Get-Service -ComputerName $ComputerName -Name $Service.ServiceName -DependentServices -ErrorAction 'Stop' | Where-Object { $_.Status -ne 'Running' }
					If ($DependentServices) {
						ForEach ($DependentService in $DependentServices) {
							Write-Log -Message "Start dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]." -Source ${CmdletName}
							Try {
								Start-Service -InputObject (Get-Service -ComputerName $ComputerName -Name $DependentService.ServiceName -ErrorAction 'Stop') -WarningAction 'SilentlyContinue' -ErrorAction 'Stop'
							}
							Catch {
								Write-Log -Message "Failed to start dependent service [$($DependentService.ServiceName)] with display name [$($DependentService.DisplayName)] and a status of [$($DependentService.Status)]. Continue..." -Severity 2 -Source ${CmdletName}
								Continue
							}
						}
					}
					Else {
						Write-Log -Message "Dependent service(s) were not discovered for service [$Name]." -Source ${CmdletName}
					}
				}
			}
		}
		Catch {
			Write-Log -Message "Failed to start the service [$Name]. `n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to start the service [$Name]: $($_.Exception.Message)"
			}
		}
		Finally {
			#  Return the service object if option selected
			If ($PassThru -and $Service) { Write-Output -InputObject $Service }
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-ServiceStartMode
Function Get-ServiceStartMode
{
<#
.SYNOPSIS
	Get the service startup mode.
.DESCRIPTION
	Get the service startup mode.
.PARAMETER Name
	Specify the name of the service.
.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Get-ServiceStartMode -Name 'wuauserv'
.NOTES

	
#>
	[CmdLetBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message "Get the service [$Name] startup mode." -Source ${CmdletName}
			[string]$ServiceStartMode = (Get-WmiObject -ComputerName $ComputerName -Class 'Win32_Service' -Filter "Name='$Name'" -Property 'StartMode' -ErrorAction 'Stop').StartMode
			## If service start mode is set to 'Auto', change value to 'Automatic' to be consistent with 'Set-ServiceStartMode' function
			If ($ServiceStartMode -eq 'Auto') { $ServiceStartMode = 'Automatic'}
			
			## If on Windows Vista or higher, check to see if service is set to Automatic (Delayed Start)
			If (($ServiceStartMode -eq 'Automatic') -and (([version]$envOSVersion).Major -gt 5)) {
				Try {
					[string]$ServiceRegistryPath = "HKLM:SYSTEM\CurrentControlSet\Services\$Name"
					[int32]$DelayedAutoStart = Get-ItemProperty -LiteralPath $ServiceRegistryPath -ErrorAction 'Stop' | Select-Object -ExpandProperty 'DelayedAutoStart' -ErrorAction 'Stop'
					If ($DelayedAutoStart -eq 1) { $ServiceStartMode = 'Automatic (Delayed Start)' }
				}
				Catch { }
			}
			
			Write-Log -Message "Service [$Name] startup mode is set to [$ServiceStartMode]." -Source ${CmdletName}
			Write-Output -InputObject $ServiceStartMode
		}
		Catch {
			Write-Log -Message "Failed to get the service [$Name] startup mode. `n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to get the service [$Name] startup mode: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Set-ServiceStartMode
Function Set-ServiceStartMode
{
<#
.SYNOPSIS
	Set the service startup mode.
.DESCRIPTION
	Set the service startup mode.
.PARAMETER Name
	Specify the name of the service.
.PARAMETER ComputerName
	Specify the name of the computer. Default is: the local computer.
.PARAMETER StartMode
	Specify startup mode for the service. Options: Automatic, Automatic (Delayed Start), Manual, Disabled, Boot, System.
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Set-ServiceStartMode -Name 'wuauserv' -StartMode 'Automatic (Delayed Start)'
.NOTES

	
#>
	[CmdLetBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$Name,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$ComputerName = $env:ComputerName,
		[Parameter(Mandatory=$true)]
		[ValidateSet('Automatic','Automatic (Delayed Start)','Manual','Disabled','Boot','System')]
		[string]$StartMode,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			## If on lower than Windows Vista and 'Automatic (Delayed Start)' selected, then change to 'Automatic' because 'Delayed Start' is not supported.
			If (($StartMode -eq 'Automatic (Delayed Start)') -and (([version]$envOSVersion).Major -lt 6)) { $StartMode = 'Automatic' }
			
			Write-Log -Message "Set service [$Name] startup mode to [$StartMode]." -Source ${CmdletName}
			
			## Set the name of the start up mode that will be passed to sc.exe
			[string]$ScExeStartMode = $StartMode
			If ($StartMode -eq 'Automatic') { $ScExeStartMode = 'Auto' }
			If ($StartMode -eq 'Automatic (Delayed Start)') { $ScExeStartMode = 'Delayed-Auto' }
			If ($StartMode -eq 'Manual') { $ScExeStartMode = 'Demand' }
			
			## Set the start up mode using sc.exe. Note: we found that the ChangeStartMode method in the Win32_Service WMI class set services to 'Automatic (Delayed Start)' even when you specified 'Automatic' on Win7, Win8, and Win10.
			$ChangeStartMode = & sc.exe config $Name start= $ScExeStartMode
			
			If ($global:LastExitCode -ne 0) {
				Throw "sc.exe failed with exit code [$($global:LastExitCode)] and message [$ChangeStartMode]."
			}
			
			Write-Log -Message "Successfully set service [$Name] startup mode to [$StartMode]." -Source ${CmdletName}
		}
		Catch {
			Write-Log -Message "Failed to set service [$Name] startup mode to [$StartMode]. `n$(Resolve-Error)" -Source ${CmdletName} -Severity 3
			If (-not $ContinueOnError) {
				Throw "Failed to set service [$Name] startup mode to [$StartMode]: $($_.Exception.Message)"
			}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-LoggedOnUser
Function Get-LoggedOnUser {
<#
.SYNOPSIS
	Get session details for all local and RDP logged on users.
.DESCRIPTION
	Get session details for all local and RDP logged on users using Win32 APIs. Get the following session details:
	 NTAccount, SID, UserName, DomainName, SessionId, SessionName, ConnectState, IsCurrentSession, IsConsoleSession, IsUserSession, IsActiveUserSession
	 IsRdpSession, IsLocalAdmin, LogonTime, IdleTime, DisconnectTime, ClientName, ClientProtocolType, ClientDirectory, ClientBuildNumber
.EXAMPLE
	Get-LoggedOnUser
.NOTES
	Description of ConnectState property:
	Value		 Description
	-----		 -----------
	Active		 A user is logged on to the session.
	ConnectQuery The session is in the process of connecting to a client.
	Connected	 A client is connected to the session.
	Disconnected The session is active, but the client has disconnected from it.
	Down		 The session is down due to an error.
	Idle		 The session is waiting for a client to connect.
	Initializing The session is initializing.
	Listening 	 The session is listening for connections.
	Reset		 The session is being reset.
	Shadowing	 This session is shadowing another session.
	
	Description of IsActiveUserSession property:
	If a console user exists, then that will be the active user session.
	If no console user exists but users are logged in, such as on terminal servers, then the first logged-in non-console user that is either 'Active' or 'Connected' is the active user.
	
	Description of IsRdpSession property:
	Gets a value indicating whether the user is associated with an RDP client session.

	
#>
	[CmdletBinding()]
	Param (
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
	}
	Process {
		Try {
			Write-Log -Message 'Get session information for all logged on users.' -Source ${CmdletName}
			Write-Output -InputObject ([PSADT.QueryUser]::GetUserSessionInfo("$env:ComputerName"))
		}
		Catch {
			Write-Log -Message "Failed to get session information for all logged on users. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
	}
	End {
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#region Function Get-PendingReboot
Function Get-PendingReboot {
<#
.SYNOPSIS
	Get the pending reboot status on a local computer.
.DESCRIPTION
	Check WMI and the registry to determine if the system has a pending reboot operation from any of the following:
	a) Component Based Servicing (Vista, Windows 2008)
	b) Windows Update / Auto Update (XP, Windows 2003 / 2008)
	c) SCCM 2012 Clients (DetermineIfRebootPending WMI method)
	d) App-V Pending Tasks (global based Appv 5.0 SP2)   
	e) Pending File Rename Operations (XP, Windows 2003 / 2008)
.EXAMPLE
	Get-PendingReboot
	
	Returns custom object with following properties:
	ComputerName, LastBootUpTime, IsSystemRebootPending, IsCBServicingRebootPending, IsWindowsUpdateRebootPending, IsSCCMClientRebootPending, IsFileRenameRebootPending, PendingFileRenameOperations, ErrorMsg
	
	*Notes: ErrorMsg only contains something if an error occurred
.EXAMPLE
	(Get-PendingReboot).IsSystemRebootPending
	Returns boolean value determining whether or not there is a pending reboot operation.
.NOTES

	
#>
	[CmdletBinding()]
	Param (
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
		
		## Initialize variables
		[string]$private:ComputerName = ([Net.Dns]::GetHostEntry('')).HostName
		$PendRebootErrorMsg = $null
	}
	Process {
		Write-Log -Message "Get the pending reboot status on the local computer [$ComputerName]." -Source ${CmdletName}
		
		## Get the date/time that the system last booted up
		Try {
			[nullable[datetime]]$LastBootUpTime = (Get-Date -ErrorAction 'Stop') - ([timespan]::FromMilliseconds([math]::Abs([Environment]::TickCount)))
		}
		Catch {
			[nullable[datetime]]$LastBootUpTime = $null
			[string[]]$PendRebootErrorMsg += "Failed to get LastBootUpTime: $($_.Exception.Message)"
			Write-Log -Message "Failed to get LastBootUpTime. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
		
		## Determine if a Windows Vista/Server 2008 and above machine has a pending reboot from a Component Based Servicing (CBS) operation
		Try {
			If (([version]$envOSVersion).Major -ge 5) {
				If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction 'Stop') {
					[nullable[boolean]]$IsCBServicingRebootPending = $true
				}
				Else {
					[nullable[boolean]]$IsCBServicingRebootPending = $false
				}
			}
		}
		Catch {
			[nullable[boolean]]$IsCBServicingRebootPending = $null
			[string[]]$PendRebootErrorMsg += "Failed to get IsCBServicingRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsCBServicingRebootPending. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
		
		## Determine if there is a pending reboot from a Windows Update
		Try {
			If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction 'Stop') {
				[nullable[boolean]]$IsWindowsUpdateRebootPending = $true
			}
			Else {
				[nullable[boolean]]$IsWindowsUpdateRebootPending = $false
			}
		}
		Catch {
			[nullable[boolean]]$IsWindowsUpdateRebootPending = $null
			[string[]]$PendRebootErrorMsg += "Failed to get IsWindowsUpdateRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsWindowsUpdateRebootPending. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
		
		## Determine if there is a pending reboot from a pending file rename operation
		[boolean]$IsFileRenameRebootPending = $false
		$PendingFileRenameOperations = $null
		If (Test-RegistryValue -Key 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Value 'PendingFileRenameOperations') {
			#  If PendingFileRenameOperations value exists, set $IsFileRenameRebootPending variable to $true
			[boolean]$IsFileRenameRebootPending = $true
			#  Get the value of PendingFileRenameOperations
			Try {
				[string[]]$PendingFileRenameOperations = Get-ItemProperty -LiteralPath 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction 'Stop' | Select-Object -ExpandProperty 'PendingFileRenameOperations' -ErrorAction 'Stop'
			}
			Catch { 
				[string[]]$PendRebootErrorMsg += "Failed to get PendingFileRenameOperations: $($_.Exception.Message)"
				Write-Log -Message "Failed to get PendingFileRenameOperations. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
			}
		}
		
		## Determine SCCM 2012 Client reboot pending status
		Try {
			[boolean]$IsSccmClientNamespaceExists = $false
			[psobject]$SCCMClientRebootStatus = Invoke-WmiMethod -ComputerName $ComputerName -NameSpace 'ROOT\CCM\ClientSDK' -Class 'CCM_ClientUtilities' -Name 'DetermineIfRebootPending' -ErrorAction 'Stop'
			[boolean]$IsSccmClientNamespaceExists = $true
			If ($SCCMClientRebootStatus.ReturnValue -ne 0) {
				Throw "'DetermineIfRebootPending' method of 'ROOT\CCM\ClientSDK\CCM_ClientUtilities' class returned error code [$($SCCMClientRebootStatus.ReturnValue)]"
			}
			Else {
				Write-Log -Message 'Successfully queried SCCM client for reboot status.' -Source ${CmdletName}
				[nullable[boolean]]$IsSCCMClientRebootPending = $false
				If ($SCCMClientRebootStatus.IsHardRebootPending -or $SCCMClientRebootStatus.RebootPending) {
					[nullable[boolean]]$IsSCCMClientRebootPending = $true
					Write-Log -Message 'Pending SCCM reboot detected.' -Source ${CmdletName}
				}
				Else {
					Write-Log -Message 'Pending SCCM reboot not detected.' -Source ${CmdletName}
				}
			}
		}
		Catch [System.Management.ManagementException] {
			[nullable[boolean]]$IsSCCMClientRebootPending = $null
			[boolean]$IsSccmClientNamespaceExists = $false
			Write-Log -Message "Failed to get IsSCCMClientRebootPending. Failed to detect the SCCM client WMI class." -Severity 3 -Source ${CmdletName}
		}
		Catch {
			[nullable[boolean]]$IsSCCMClientRebootPending = $null
			[string[]]$PendRebootErrorMsg += "Failed to get IsSCCMClientRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsSCCMClientRebootPending. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}

		## Determine if there is a pending reboot from an App-V global Pending Task. (User profile based tasks will complete on logoff/logon)
		Try {
			If (Test-Path -LiteralPath 'HKLM:SOFTWARE\Software\Microsoft\AppV\Client\PendingTasks' -ErrorAction 'Stop') {

				[nullable[boolean]]$IsAppVRebootPending = $true
			}
			Else {
				[nullable[boolean]]$IsAppVRebootPending = $false
			}
		}
		Catch {
			[nullable[boolean]]$IsAppVRebootPending = $null
			[string[]]$PendRebootErrorMsg += "Failed to get IsAppVRebootPending: $($_.Exception.Message)"
			Write-Log -Message "Failed to get IsAppVRebootPending. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
		}
		
		## Determine if there is a pending reboot for the system
		[boolean]$IsSystemRebootPending = $false
		If ($IsCBServicingRebootPending -or $IsWindowsUpdateRebootPending -or $IsSCCMClientRebootPending -or $IsFileRenameRebootPending) {
			[boolean]$IsSystemRebootPending = $true
		}
		
		## Create a custom object containing pending reboot information for the system
		[psobject]$PendingRebootInfo = New-Object -TypeName 'PSObject' -Property @{
			ComputerName = $ComputerName
			LastBootUpTime = $LastBootUpTime
			IsSystemRebootPending = $IsSystemRebootPending
			IsCBServicingRebootPending = $IsCBServicingRebootPending
			IsWindowsUpdateRebootPending = $IsWindowsUpdateRebootPending
			IsSCCMClientRebootPending = $IsSCCMClientRebootPending
			IsAppVRebootPending = $IsAppVRebootPending
			IsFileRenameRebootPending = $IsFileRenameRebootPending
			PendingFileRenameOperations = $PendingFileRenameOperations
			ErrorMsg = $PendRebootErrorMsg
		}
		Write-Log -Message "Pending reboot status on the local computer [$ComputerName]: `n$($PendingRebootInfo | Format-List | Out-String)" -Source ${CmdletName}
	}
	End {
		Write-Output -InputObject ($PendingRebootInfo | Select-Object -Property 'ComputerName','LastBootUpTime','IsSystemRebootPending','IsCBServicingRebootPending','IsWindowsUpdateRebootPending','IsSCCMClientRebootPending','IsAppVRebootPending','IsFileRenameRebootPending','PendingFileRenameOperations','ErrorMsg')
		
		Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
	}
}
#endregion

#endregion
##*=============================================
##* END FUNCTION LISTINGS
##*=============================================