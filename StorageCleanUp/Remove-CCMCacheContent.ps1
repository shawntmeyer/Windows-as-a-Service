<# 
.SYNOPSIS 
Delete Specified Item(s) From CCM Cache
.DESCRIPTION 
Uses ContentIDs to identify and purge content from the local ccm cache - Created by Gary Blok @gwblok
Partial Code borrowed from: https://gallery.technet.microsoft.com/scriptcenter/Deleting-the-SCCM-Cache-da03e4c7
Assist by Mark Godfrey @Geodesicz
.PARAMETER CachItemsToDelete
Comma separated values for the Content ID(s) of the cach item(s) to delete
.EXAMPLE 
.\Remove-CCMCacheContent.ps1 -CacheItemsToDelete "PS100123","20eb8ec8-0b7e-4831-a5ae-95680b11e6b5","PS111197"
.LINK
https://garytown.com
#> 

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=1,HelpMessage="ContentIDs")]
    [ValidateNotNullOrEmpty()]
    [String[]]$CacheItemsToDelete
)
#$CacheItemsToDelete = "PS100002","20eb8ec8-0b7e-4831-a5ae-95680b11e6b5","decbb5fe-1cbc-4984-bbf2-e76347150135"

$Logfile = "c:\windows\temp\Remove-CCMCacheContent.log"
# Connect to resource manager COM object    
$CMObject = New-Object -ComObject 'UIResource.UIResourceMgr' 
 
# Using GetCacheInfo method to return cache properties 
$CMCacheObjects = $CMObject.GetCacheInfo() 
 
# Delete Cache item 
$CMCacheObjects.GetCacheElements() | Where-Object {$_.ContentID -in $CacheItemsToDelete} | ForEach-Object { 
    #$CMCacheObjects.DeleteCacheElement($_.CacheElementID)
    Add-Content $Logfile -value "Deleted: Name: $($_.ContentID)  Version: $($_.ContentVersion)"
    Write-Host "Deleted: Name: $($_.ContentID)  Version: $($_.ContentVersion)" -BackgroundColor Red 
}