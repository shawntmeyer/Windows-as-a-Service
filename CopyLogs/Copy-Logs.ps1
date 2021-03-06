[cmdletbinding()]
param(
    [string] $LogDir = '\\cm01\logs$',
    [string] $LogID = "$env:ComputerName",
    [string[]] $Exclude = @( '*.exe','*.wim','*.dll','*.ttf','*.mui' )
)

$tsenvInitialized = $false
try
{
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $tsenvInitialized = $true
}
catch
{
    $tsenvInitialized = $false
}

[string[]] $Path = @(
        "$tsenv.Value('_SMSTSLogPath')"
        "$env:Systemdrive\`$WINDOWS.~BT\Sources\Panther"
        "$env:Systemdrive\`$WINDOWS.~BT\Sources\Rollback"
        "$env:SystemRoot\Panther"
        "$env:SystemRoot\SysWOW64\PKG_LOGS"
    )

new-item -itemtype Directory -Path $LogDir\$LogID -force -erroraction SilentlyContinue | out-null 

$TagFile = "$LogDir\$LogID\$($LogID.Replace('\','_'))"

#region Create temporary Store

$TempPath = [System.IO.Path]::GetTempFileName()
remove-item $TempPath
new-item -type directory -path $TempPath -force | out-null

foreach ( $Item in $Path ) { 

    $TmpTarget = (join-path $TempPath ( split-path -NoQualifier $Item ))
    write-Verbose "COPy $Item to $TmpTarget"
    copy-item -path $Item -Destination $TmpTarget -Force -Recurse -exclude $Exclude -ErrorAction SilentlyContinue

}

Compress-Archive -path "$TempPath\*" -DestinationPath "$LogDir\$LogID\$($LogID.Replace('\','_'))-$([datetime]::now.Tostring('s').Replace(':','-')).zip" -Force
remove-item $tempPath -Recurse -Force

#endregion