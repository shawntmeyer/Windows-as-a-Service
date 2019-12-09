[CmdletBinding()]
Param (
    # Script Version Number. Used to track compliance in baselines and applications.
    [Parameter(Mandatory=$true)]
    [version]$Version,
    # The location where all In-Place Upgrade Prestaged content will be stored.
    [Parameter(Mandatory=$false)]
      [string]$IPUDir = "$($env:SystemRoot)\WSUSIPU"
)



If (Test-Path "$IPUDir\version.txt")
{
    $tsenv = New-Object -ComObject Microsoft.SMS.TSEnvironment
    $FileVersion = Get-Content "$IPUDir\version.txt"
    If ($FileVersion -and $fileVersion -eq $version)
    {
        $tsenv.Value("VersionMatch") = "TRUE"
    }
} 
