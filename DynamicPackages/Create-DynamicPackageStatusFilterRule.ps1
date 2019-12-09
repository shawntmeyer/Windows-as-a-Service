<#
.Synopsis
   Create Status Filter Rules for Get-DynamicPackage OSD Script
.DESCRIPTION
   Creates Status Filter Rules in SCCM to automatically update two XML files - one for regular packages and one for driver packages whenever a package is modified, created, or deleted in SCCM.
.EXAMPLE
   Create-DynamicPackageStatusFilterRules -ScriptPackageName "Get-CMDynamicPackage Script"
#>
Param
(
    # Name of Configuration Manager Package containing Get-CMDymamicPackage script
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    $ScriptPackageName,
    # Script subdirectory, do NOT include trailing or leading "\"
    [string]$scriptsubdir
)

Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" # Import the ConfigurationManager.psd1 module 
$sitecode = (Get-PSDrive -PSProvider CMSite).Name
Set-Location ($sitecode + ":") # Set the current location to be the site code.
$ScriptPkgPath = ((Get-CMPackage -Name $ScriptPackageName).Pkgsourcepath)
If ($scriptsubdir) {$ScriptPkgPath = "$scriptPkgPath\$scriptsubdir"}

$statusfilterrulename = "Update Package XML - Package Insert"
If (Get-CMStatusFilterRule -Name $StatusFilterRuleName) { Get-CMStatusFilterRule -Name $statusfilterrulename | Remove-CMStatusFilterRule -Force }
New-CMStatusFilterRule -Name $statusfilterrulename -MessageType Audit -MessageId 30000 -SeverityType Informational -RunProgram $true -ProgramPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command `"Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\packages.xml' -force; Get-WmiObject -class sms_driverpackage -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\driverpackages.xml' -force; (Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Where-Object {`$_.Name -eq '$ScriptPackageName'}).RefreshPkgSource()`""

$statusfilterrulename = "Update Package XML - Package Update"
If (Get-CMStatusFilterRule -Name $StatusFilterRuleName) { Get-CMStatusFilterRule -Name $statusfilterrulename | Remove-CMStatusFilterRule -Force }
New-CMStatusFilterRule -Name $statusfilterrulename -MessageType Audit -MessageId 30001 -SeverityType Informational -RunProgram $true -ProgramPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command `"Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\packages.xml' -force; Get-WmiObject -class sms_driverpackage -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\driverpackages.xml' -force; (Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Where-Object {`$_.Name -eq '$ScriptPackageName'}).RefreshPkgSource()`""

$statusfilterrulename = "Update Package XML - Package Delete"
If (Get-CMStatusFilterRule -Name $StatusFilterRuleName) { Get-CMStatusFilterRule -Name $statusfilterrulename | Remove-CMStatusFilterRule -Force }
New-CMStatusFilterRule -Name $statusfilterrulename -MessageType Audit -MessageId 30002 -SeverityType Informational -RunProgram $true -ProgramPath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -command `"Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\packages.xml' -force; Get-WmiObject -class sms_driverpackage -Namespace root\sms\site_$sitecode | Select-Object pkgsourcepath, Description, ISVData, ISVString, Manufacturer, MifFileName, MifName, MifPublisher, MIFVersion, Name, PackageID, ShareName, Version | export-clixml -path '$ScriptPkgPath\driverpackages.xml' -force; (Get-WmiObject -class sms_package -Namespace root\sms\site_$sitecode | Where-Object {`$_.Name -eq '$ScriptPackageName'}).RefreshPkgSource()`""
