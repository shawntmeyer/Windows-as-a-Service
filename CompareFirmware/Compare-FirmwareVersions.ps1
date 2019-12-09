Param
(
    # Target version
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    $TargetVersion,

    # Current Version
    $CurrentVersion=(get-wmiobject -Class "WIN32_BIOS" -Property SMBIOSBIOSVersion).SMBIOSBIOSVersion,

    #Version Comparison Output Task Sequence Variable
    $TSVar="FirmwareUpdate"    
)

function Convert-Version
{
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $Version
    )
    $Version=$Version.ToUpper()

    If ($Version.Contains('VER.'))
    {
        $i=$Version.IndexOf('VER.')
        $Version=$Version.Substring($i+5,$Version.Length-($i+5))
        Return $Version
    }
    Elseif($Version.Contains(' V'))
    {
        $i=$Version.IndexOf(' V')
        $Version=$Version.Substring($i+2,$Version.Length-($i+2))
        Return $Version
    }
    Else
    {
        Return $Version
    }
    
}

Try
{
    $ts = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop

    If (!$TargetVersion) { $TargetVersion = $ts.env("FirmwareTargetVersion") }

    $TargetVersion = Convert-Version -Version $TargetVersion
    $CurrentVersion = Convert-Version -Version $CurrentVersion

    If ($targetversion -match ".")
    {
        Try { $targetversion = [system.version]::parse($targetversion) }
        Catch {}
    }

    If ($currentVersion -match ".")
    {
        Try { $currentversion = [System.Version]::Parse($CurrentVersion) }
        Catch {}
    }
    If ($targetVersion -gt $currentversion)
    {
        $ts.Value("$TSVar") = "TRUE"
    }
}
catch
{
}