$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$LogPath = $tsenv.Value("_SMSTSLogPath")
$UEFI = $tsenv.Value("_SMSTSBootUEFI")
$OSDDiskIndex = $tsenv.Value("OSDDiskIndex")
If (!$OSDDiskIndex) { $OSDDiskIndex = '0' }
If ($UEFI -eq $TRUE)
{
    "select disk $OSDDiskIndex","list partition","select partition 3","shrink desired=984 minimum=984","create partition primary","format quick fs=ntfs label=Recovery","set id=`"de94bba4-06d1-4d40-a16a-bfd50179d6ac`"","gpt attributes=0x8000000000000001","list partition" | diskpart | Tee-Object -FilePath "$LogPath\Create-RecoveryPartition.log"
}
else
{
"select disk $OSDDiskIndex","list partition","select partition 2","shrink desired=984 minimum=984","create partition primary","format quick fs=ntfs label=Recovery","set id=27","list partition" | diskpart | Tee-Object -FilePath "$LogPath\Create-RecoveryPartition.log"
}