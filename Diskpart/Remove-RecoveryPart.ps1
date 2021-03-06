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
    $logDir = $env:temp
  }
  $ts=$null
  return $logDir
}

<#
.Synopsis
   Delete Partition From Disk
#>
function Delete-Partition
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [int]
        $Disk,

        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]

        [int]
        $Partition
    )

    "Select Disk $Disk", "select Partition $Partition" , "delete partition override", "exit" | Diskpart
}


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

$TranscriptDir = Get-LogDir
[string]$scriptFullName = $MyInvocation.MyCommand.Definition
[string]$LogName=[IO.Path]::GetFileNameWithoutExtension($scriptFullName) + ".log"

$Transcript = "$TranscriptDir\$LogName"

Start-Transcript -Path $Transcript -Force

Write-Output "Detecting if GPT or MBR Partition Scheme on Drive 0"

$SysPartition = Get-WMIObject -query "Select * from Win32_DiskPartition WHERE Index = 0 and Type = 'GPT: System'"

If (!$SysPartition)
{

    Write-Output "Detected MBR Partition Type."
    Write-Output "Now checking disk 0 to see if it has 2 or less partitions."
    $diskParts=Get-WmiObject -Query "Select * from Win32_Diskpartition where DiskIndex='0'"
    $PartCount = $diskParts.Count

    If ($Partcount -ge 3)
    {

        Write-Output "Found $PartCount Partitions which is too many for MBR2GPT. Now finding and removing any OEM Tools or Recovery Partitions"
        If ($tsenvInitialized -eq $true) { $tsenv.Value("DoMBR2GPT")='False' }

        [string]$temp = Invoke-Command -ScriptBlock {$dpscript = @"
list volume
"@;$dpscript|diskpart}

        $vols = $temp -split "\s(?=V)"
        $labels = ($vols[2] -split "(\s+)(?=-)")[0] -split "\s+"
        $Results = $vols[3..($vols.count-1)]|%{
            New-Object PSObject -property @{
                "$($labels[0])$($labels[1])"=$_.substring(0,10).trimend()
                $labels[2] = $_.substring(13,3).trim()
                $labels[3] = $_.substring(17,11).trim()
                $labels[4] = $_.substring(30,5).trim()
                $labels[5] = $_.substring(37,10).trim()
                $labels[6] = $_.substring(49,7).trim()
                $labels[7] = $_.substring(58,9).trim()
                $labels[8] = $_.substring(67,8).trim()
            }
        }
     
        $RecoveryParts = $results | Where-Object {$_.Label -eq 'Recovery' -or $_.Label -like 'HP_*'}
        
        If ($RecoveryParts)
        {        
            ForEach($RecoveryPart in $RecoveryParts)
            {

                $PartitionNumber=($RecoveryPart."Volume###" -Split "\s",2)[1]
                Write-Output "Recovery Partition found with Partition Number $PartitionNumber"
                Write-Output "Removing Recovery Partition with DiskPart"
                Delete-Partition -Disk 0 -Partition $PartitionNumber
            }
            $WindowsPart = $results | Where-Object {$_.Ltr -eq 'C'}
            If ($WindowsPart)
            {
                $VolumeNum = ($WindowsPart."Volume###" -Split "\s",2)[1]
                Write-Output "Extending Windows Partition, Partition Number $VolumeNum with Diskpart"
                "Select Disk 0", "sel Part $VolumeNum" , "extend", "exit"| Diskpart
            }
        }

        #Test for number of Partitions on Disk 0

        $diskParts=Get-WmiObject -Query "Select * from Win32_Diskpartition where DiskIndex='0'"
        $PartCount = $diskParts.Count
        If ($PartCount -le 2)
        {
            Write-Output "Successfully reduced the number of partitions to $PartCount"
            If ($tsenvInitialized -eq $true) { $tsenv.Value("DoMBR2GPT")='True' }
        } 


    }
    Else
    {
        Write-Output "Found 2 or less partitions. No action needed."
        If ($tsenvInitialized -eq $true) { $tsenv.Value("DoMBR2GPT")='True' }
    }
}
Else
{
    Write-Output "Detected GPT Partition Scheme. No need to change partitions."
}
Stop-Transcript
