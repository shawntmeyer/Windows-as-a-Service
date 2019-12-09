<#
.SYNOPSIS
	Sets information during OSD / IPU
   
.DESCRIPTION 
    This script will add build, task sequence, and other information to the OS so that it can later be examined or inventoried.
    Information can be added to the registry, WMI, or both.

.PARAMETER Registry
    This switch will add information to the following location:
        - Registry

.PARAMETER WMI
    This switch will add information to the following location:
        - WMI Repository
    
.EXAMPLE
     Set-OSDInfo.ps1 -WMI -Registry

     Will add all information to the following locations:
        - Registry
        - WMI Repository 

.NOTES
    Modified from the versions by Stephane van Gulick from www.powershellDistrict.com
	V1.1, 2016-5-6: Added, values for Dtae/Time, OS Image ID, UEFI, and Launch Mode
    V1.1G, 2018-5-12: GaryTown Modified Version.  Seperated OSD, IPU & CompatScan sections
     -Includes gathering Setup.exe return code and logging that in "normal terms"
     -Requires several TS variables for this to work
        -SetOSDInfoType (OSD / CS / IPU)
        -SMSTS_FinishTSTime (Time at the end of the TS, used to figure out how long it took)
        -SMSTS_StartTSTime (Time when TS starts, used to figure out how long it took)
        -SMSTS_FinishUpgradeTime (Time at end of Upgrade Step, figure out how long setup engine ran)
        -SMSTS_StartUpgradeTime (Time at star of Upgrade Step, figure out how long setup engine ran)
        -SMSTS_BUILD (used to keep Build Upgrades seperate)
        -SMSTS_DMDepartment (Purely Environmental, can modify to fit needs, or remove)
        -SMSTS_DMLocation (Purely Environmental, can modify to fit needs, or remove)
        -CheckReadinessResult (Created if CheckReadiness Step Fails)
    V1.2, 2019-1-17: Added Info to record UBR & UserAccount
.LINK
	http://blog.configmgrftw.com
	https://garytown.com for Modifications to Jason's Original Script

.VERSION
    2019.01.17
#>
[cmdletBinding()]
Param(
        [Parameter(Mandatory=$false)][switch]$WMI,
        [Parameter(Mandatory=$false)][switch]$Registry,
        [Parameter(Mandatory=$false)][String]$Namespace,
        [Parameter(Mandatory=$false)][String]$Class,
        [Parameter(Mandatory=$true)][String]$ID,
        [Parameter(Mandatory=$false)][String]$AttributePrefix = "WaaS_"
)
# Start-Transcript >> $env:temp\PowerShellTranscript.log

Function Get-WMINamespace
{
  <#
	.SYNOPSIS
		Gets information about a specified WMI namespace.

	.DESCRIPTION
		Returns information about a specified WMI namespace.

    .PARAMETER  Namespace
		Specify the name of the namespace where the class resides in (default is "root\cimv2").

	.EXAMPLE
		Get-WMINamespace
        Lists all WMI namespaces.

	.EXAMPLE
		Get-WMINamespace -Namespace cimv2
        Returns the cimv2 namespace.

	.NOTES
		Version: 1.0

	.LINK
		http://blog.configmgrftw.com

#>
[CmdletBinding()]
	Param
    (
        [Parameter(Mandatory=$false,valueFromPipeLine=$true)][string]$Namespace
	)  
    begin
	{
		Write-Verbose "Getting WMI namespace $Namespace"
    }
    Process
	{
        if ($Namespace)
        {
            $filter = "Name = '$Namespace'"
            $return = Get-WmiObject -Namespace "root" -Class "__namespace" -filter $filter
        }
		else
		{
            $return = Get-WmiObject -Namespace root -Class __namespace
        }
    }
    end
	{
        return $return
    }
}

Function New-WMINamespace
{
<#
	.SYNOPSIS
		This function creates a new WMI namespace.

	.DESCRIPTION
		The function creates a new WMI namespsace.

    .PARAMETER Namespace
		Specify the name of the namespace that you would like to create.

	.EXAMPLE
		New-WMINamespace -Namespace "ITLocal"
        Creates a new namespace called "ITLocal"
		
	.NOTES
		Version: 1.0

	.LINK
		http://blog.configmgrftw.com

#>
[CmdletBinding()]
	Param(
        [Parameter(Mandatory=$true,valueFromPipeLine=$true)][string]$Namespace
	)

	if (!(Get-WMINamespace -Namespace "$Namespace"))
	{
		Write-Verbose "Attempting to create namespace $($Namespace)"

		$newNamespace = ""
		$rootNamespace = [wmiclass]'root:__namespace'
        $newNamespace = $rootNamespace.CreateInstance()
		$newNamespace.Name = $Namespace
		$newNamespace.Put() | out-null
		
		Write-Verbose "Namespace $($Namespace) created."

	}
	else
	{
		Write-Verbose "Namespace $($Namespace) is already present. Skipping.."
	}
}

Function Get-WMIClass
{
  <#
	.SYNOPSIS
		Gets information about a specified WMI class.

	.DESCRIPTION
		Returns the listing of a WMI class.

	.PARAMETER  ClassName
		Specify the name of the class that needs to be queried.

    .PARAMETER  Namespace
		Specify the name of the namespace where the class resides in (default is "root\cimv2").

	.EXAMPLE
		get-wmiclass
        List all the Classes located in the root\cimv2 namespace (default location).

	.EXAMPLE
		get-wmiclass -classname win32_bios
        Returns the Win32_Bios class.

	.EXAMPLE
		get-wmiclass -Class MyCustomClass
        Returns information from MyCustomClass class located in the default namespace (root\cimv2).

    .EXAMPLE
		Get-WMIClass -Namespace ccm -Class *
        List all the classes located in the root\ccm namespace

	.EXAMPLE
		Get-WMIClass -NameSpace ccm -Class ccm_client
        Returns information from the cm_client class located in the root\ccm namespace.

	.NOTES
		Version: 1.0

	.LINK
		http://blog.configmgrftw.com

#>
[CmdletBinding()]
	Param
	(
		[Parameter(Mandatory=$false,valueFromPipeLine=$true)][string]$Class,
        [Parameter(Mandatory=$false)][string]$Namespace = "cimv2"
	)  
    begin
	{
		Write-Verbose "Getting WMI class $Class"
    }
    Process
	{
		if (Get-WMINamespace -Namespace $Namespace)
		{
			$namespaceFullName = "root\$Namespace"

            Write-Verbose $namespaceFullName
		
			if (!$Class)
			{
				$return = Get-WmiObject -Namespace $namespaceFullName -Class * -list
			}
			else
			{
				$return = Get-WmiObject -Namespace $namespaceFullName -Class $Class -list
			}
		}
		else
		{
			Write-Verbose "WMI namespace $Namespace does not exist."
			
			$return = $null
		}
    }
    end
	{
        return $return
    }
}

Function New-WMIClass
{
<#
	.SYNOPSIS
		This function creates a new WMI class.

	.DESCRIPTION
		The function create a new WMI class in the specified namespace.
        It does not create a new namespace however.

	.PARAMETER Class
		Specify the name of the class that you would like to create.

    .PARAMETER Namespace
		Specify the namespace where class the class should be created.
        If not specified, the class will automatically be created in "root\cimv2"

    .PARAMETER Attributes
		Specify the attributes for the new class.

    .PARAMETER Key
		Specify the names of the key attribute (or attributes) for the new class.

	.EXAMPLE
		New-WMIClass -ClassName "OSD_Info"
        Creates a new class called "OSD_Info"
    .EXAMPLE
        New-WMIClass -ClassName "OSD_Info1","OSD_Info2"
        Creates two classes called "OSD_Info1" and "OSD_Info2" in the root\cimv2 namespace

	.NOTES
		Version: 1.0

	.LINK
		http://blog.configmgrftw.com

#>
[CmdletBinding()]
	Param(
		[Parameter(Mandatory=$true,valueFromPipeLine=$true)][string]$Class,
        [Parameter(Mandatory=$false)][string]$Namespace = "cimv2",
        [Parameter(Mandatory=$false)][System.Management.Automation.PSVariable[]]$Attributes,
        [Parameter(Mandatory=$false)][string[]]$Key
	)

	$namespaceFullName = "root\$Namespace"
	
	if (!(Get-WMINamespace -Namespace $Namespace))
	{
		Write-Verbose "WMI namespace $Namespace does not exist."

	}

    elseif (!(Get-WMIClass -Class $Class -NameSpace $Namespace))
	{
		Write-Verbose "Attempting to create class $($Class)"
			
		$newClass = ""
		$newClass = New-Object System.Management.ManagementClass($namespaceFullName, [string]::Empty, $null)
		$newClass.name = $Class

        foreach ($attr in $Attributes)
        {
            $attr.Name -match "$AttributePrefix(?<attributeName>.*)" | Out-Null
            $attrName = $matches['attributeName']

            $newClass.Properties.Add($attrName, [System.Management.CimType]::String, $false)
            Write-Verbose "   added attribute: $attrName"
        }

        foreach ($keyAttr in $Key)
        {
            $newClass.Properties[$keyAttr].Qualifiers.Add("Key", $true)
            Write-Verbose "   added key: $keyAttr"
        }


		$newClass.Put() | out-null
			
		Write-Verbose "Class $($Class) created."
	}
	else
	{
		Write-Verbose "Class $($Class) is already present. Skipping..."
    }

}

Function New-WMIClassInstance
{
    <#
	.SYNOPSIS
		Creates a new WMI class instance.

	.DESCRIPTION
		The function creates a new instance of the specified WMI class.

	.PARAMETER  Class
		Specify the name of the class to create a new instance of.

	.PARAMETER Namespace
        Specify the name of the namespace where the class is located (default is Root\cimv2).

	.PARAMETER Attributes
        Specify the attributes and their values using PSVariables.

	.EXAMPLE
        $MyNewInstance = New-WMIClassInstance -Class OSDInfo
        
        Creates a new instance of the WMI class "OSDInfo" and sets its attributes.
		
	.NOTES
		Version: 1.0

	.LINK
		http://blog.configmgrftw.com

#>

[CmdletBinding()]
	Param
    (
		[Parameter(Mandatory=$true)]
        [ValidateScript({
            $_ -ne ""
        })][string]$Class,
        [Parameter(Mandatory=$false)][string]$Namespace="cimv2",
        [Parameter(Mandatory=$false)][System.Management.Automation.PSVariable[]]$Attributes
	)

    $classPath = "root\$($Namespace):$($Class)"
    $classObj = [wmiclass]$classPath
    $classInstance = $classObj.CreateInstance()

    Write-Verbose "Created instance of $Class class."

    foreach ($attr in $Attributes)
    {
        $attr.Name -match "$AttributePrefix(?<attributeName>.*)" | Out-Null
        $attrName = $matches['attributeName']

        if ($attr.Value) 
        {
            $attrVal = $attr.Value
        } 
        else 
        {
            $attrVal = ""
        }

        $classInstance[$attrName] = $attrVal
        "   added attribute value for $($attrName): $($attrVal)" >> $env:temp\newWMIInstance.log 
    }

    $classInstance.Put()
}

Function New-RegistryItem
{
<#
.SYNOPSIS
	Sets a registry value in the specified key under HKLM\Software.
   
.DESCRIPTION 
    Sets a registry value in the specified key under HKLM\Software.
	
	
.PARAMETER Key
    Species the registry path under HKLM\SOFTWARE\ to create.
    Defaults to OperatingSystemDeployment.


.PARAMETER ValueName
    This parameter specifies the name of the Value to set.

.PARAMETER Value
    This parameter specifies the value to set.
    
.Example
     New-RegistryItem -ValueName Test -Value "abc"

.NOTES
	-Version: 1.0
	
#>



    [cmdletBinding()]
    Param(


        [Parameter(Mandatory=$false)]
        [string]$Key = "OperatingSystemDeployment",

        [Parameter(Mandatory=$true)]
        [string]$ValueName,

        [Parameter(Mandatory=$false)]
        [string]$Value
        
    )
    begin
    {
        $registryPath = "HKLM:SOFTWARE\WaaS\$ID"
    }
    Process
    {
        if ($registryPath -eq "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\")
        {
            write-verbose "The registry path that is tried to be created is the uninstall string.HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\."
            write-verbose "Creating this here would have as consequence to erase the whole content of the Uninstall registry hive."
                        
            exit 
        }

        ##Creating the registry node
        if (!(test-path $registryPath))
        {
            write-verbose "Creating the registry key at : $($registryPath)."
            
            try
            {
                New-Item -Path $registryPath -force -ErrorAction stop | Out-Null
            }
            catch [System.Security.SecurityException]
            {
                write-warning "No access to the registry. Please launch this function with elevated privileges."
            }
            catch
            {
                write-host "An unknown error occurred : $_ "
            }
        }
        else
        {
            write-verbose "The registry key already exists at $($registryPath)"
        }

        ##Creating the registry string and setting its value
        write-verbose "Setting the registry string $($ValueName) with value $($Value) at path : $($registryPath) ."

        try
        {
            New-ItemProperty -Path $registryPath  -Name $ValueName -PropertyType STRING -Value $Value -Force -ErrorAction Stop | Out-Null
        }
        catch [System.Security.SecurityException]
        {
            write-host "No access to the registry. Please launch this function with elevated privileges."
        }
        catch
        {
            write-host "An unknown error occurred : $_ "
        }
    }

    End
    {
    }
}


try
{
    $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
}
catch
{
	Write-Verbose "Not running in a task sequence."
}

$keyValue = "ID"

# New-Variable -Name "$($AttributePrefix)InstallationDate" -Value $(get-date -uformat "%Y%m%d-%T")

 New-Variable -Name "$($AttributePrefix)$keyValue" -Value $ID


        





if ($tsenv)
{
        #Get what kind of TS: CompatScan (CS) / InPlace Uprade (IPU) / Operating System Deployment (OSD) - Must have Step in TS that lets script know
        $SetOSDInfoType = $tsenv.Value("SetOSDInfoType")
        #Gets the Time in Minutes it takes to run Task Sequence - Requires you to set a Start Variable & Finish Variable (2 steps in TS) 
        $Difference = ([datetime]$TSEnv.Value('SMSTS_FinishTSTime')) - ([datetime]$TSEnv.Value('SMSTS_StartTSTime')) 
        $Difference = [math]::Round($Difference.TotalMinutes)

        #Gets CompatScan Results and Write Code & Friendly Name to Registry
        
        if (($SetOSDInfoType -eq 'IPU' -or $SetOSDInfoType -eq 'CS') -and ($tsenv.Value("_SMSTSOSUpgradeActionReturnCode") -or $tsenv.Value("CompatScanRetCode")))
        {
            if ($tsenv.Value("_SMSTSOSUpgradeActionReturnCode"))
            {
                [int64] $decimalreturncode = $tsenv.Value("_SMSTSOSUpgradeActionReturnCode")
            }
            If ($tsenv.Value("CompatScanRetCode"))
            {
                [int64] $decimalreturncode = $tsenv.Value("CompatScanRetCode")
            }
            #[int64] $hexreturncode = 0xC1900210
            $hexreturncode = "{0:X0}" -f [int64]$decimalreturncode

                $WinIPURet = @(
            @{ Err = "C1900210"; Msg = 'No compatibility issues.'}
            @{ Err = "C1900208"; Msg = 'Incompatible apps or drivers.' }
            @{ Err = "C1900204"; Msg = 'Selected migration choice is not available.' }
            @{ Err = "C1900200"; Msg = 'Not eligible for Windows 10.' }
            @{ Err = "C190020E"; Msg = 'Not enough free disk space.' }
            @{ Err = "C1900107"; Msg = 'Unsupported Operating System.' }
            @{ Err = "80070652"; Msg = 'Previous Install Pending, Reboot.' }
            @{ Err = "8024200D"; Msg = 'Update Needs to be Downloaded Again.' }
            @{ Err = "0"; Msg = 'Windows Setup completed successfully.' }
            )
            $ErrorMsg = $winipuret | ? err -eq $hexreturncode  | % Msg

            #Gets the Time in minutes it takes to run the Setup.exe Step (CS or IPU only)
            $DifferenceUpgrade = ([datetime]$TSEnv.Value('SMSTS_FinishUpgradeTime')) - ([datetime]$TSEnv.Value('SMSTS_StartUpgradeTime')) 
            $DifferenceUpgrade = [math]::Round($DifferenceUpgrade.TotalMinutes)
        }
	$taskSequenceXML = $tsenv.Value("_SMSTSTaskSequence")
	$imageIDElement = @(Select-Xml -Content $taskSequenceXML -XPath "//variable[@name='ImagePackageID']")
	 
#Run These during OSD
    if ($SetOSDInfoType -eq 'OSD')
    {
        New-Variable -Name "$($AttributePrefix)OSD_BootImageID" -Value $tsenv.Value("_SMSTSBootImageID")
        New-Variable -Name "$($AttributePrefix)OSD_InstallationMethod" -Value $tsenv.Value("_SMSTSMediaType")
        New-Variable -Name "$($AttributePrefix)OSD_OSImageID" -Value $imageIDElement[0].node.InnerText
        
        New-Variable -Name "$($AttributePrefix)OSD_OSBuild" -Value $tsenv.Value("SMSTS_BUILD")
#       New-Variable -Name "$($AttributePrefix)OSD_DMDepartment" -Value $tsenv.Value("SMSTS_DMDepartment")
#	    New-Variable -Name "$($AttributePrefix)OSD_DMLocation" -Value $tsenv.Value("SMSTS_DMLocation")
        New-Variable -Name "$($AttributePrefix)OSD_TSRunTime" -Value "$Difference"
        New-Variable -Name "$($AttributePrefix)OSD_TaskSequenceName" -Value $tsenv.Value("_SMSTSPackageName")
        New-Variable -Name "$($AttributePrefix)OSD_TaskSequenceID" -Value $tsenv.Value("_SMSTSPackageID")
        New-Variable -Name "$($AttributePrefix)OSD_TSDeploymentID" -Value $tsenv.Value("_SMSTSAdvertID")
        New-Variable -Name "$($AttributePrefix)OSD_InstallationDate" -Value $(get-date -uformat "%Y%m%d-%T")
        if ($tsenv.Value("_SMSTSUserStarted") -ne $null)
            {
            New-Variable -Name "$($AttributePrefix)OSD_UserInitiated" -Value $tsenv.Value("_SMSTSUserStarted")
            }
    }

#Run These if IPU
    if ($SetOSDInfoType -eq 'IPU')
    {
        New-Variable -Name "$($AttributePrefix)IPU_UserInitiated" -Value $tsenv.Value("_SMSTSUserStarted")
        New-Variable -Name "$($AttributePrefix)IPU_OSBuild" -Value $tsenv.Value("SMSTS_BUILD")
#	    New-Variable -Name "$($AttributePrefix)IPU_DMDepartment" -Value $tsenv.Value("SMSTS_DMDepartment")
#	    New-Variable -Name "$($AttributePrefix)IPU_DMLocation" -Value $tsenv.Value("SMSTS_DMLocation")
        New-Variable -Name "$($AttributePrefix)IPU_TSRunTime" -Value "$Difference"
        New-Variable -Name "$($AttributePrefix)IPU_TaskSequenceName" -Value $tsenv.Value("_SMSTSPackageName")
        New-Variable -Name "$($AttributePrefix)IPU_TaskSequenceID" -Value $tsenv.Value("_SMSTSPackageID")
        New-Variable -Name "$($AttributePrefix)IPU_TSDeploymentID" -Value $tsenv.Value("_SMSTSAdvertID")
        New-Variable -Name "$($AttributePrefix)IPU_InstallationDate" -Value $(get-date -uformat "%Y%m%d-%T")
        New-Variable -Name "$($AttributePrefix)IPU_CheckReadiness" -Value $tsenv.Value("CheckReadinessResult")   
        #If User Initiated from Software Center, Record User who triggered Upgrade.
        if ($tsenv.Value("_SMSTSUserStarted") -eq "True")
            {            New-Variable -Name "$($AttributePrefix)IPU_UserAccount" -Value $tsenv.Value("IPU_UserAccount")            }
        #If Check Readiness Step Passes, Fill in Blanks with Data
        if ($tsenv.Value("CheckReadinessResult") -eq "Pass")
            {
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineReturn" -Value "$ErrorMsg"
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineHexCode" -Value "$hexreturncode"
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineRunTime" -Value "$DifferenceUpgrade"
            }
        #If Check Readiness Step fails, then there is no data, so place "NA" as place holders
        else
            {
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineReturn" -Value "NA"
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineHexCode" -Value "NA"
            New-Variable -Name "$($AttributePrefix)IPU_SetupEngineRunTime" -Value "NA"
            }
       
   #Add Build Record Info so you know which Build of OS was deployed
        $UBR = (Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' CurrentBuildNumber)+'.'+(Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' UBR)
        New-Variable -Name "$($AttributePrefix)IPU_Build" -Value $UBR
   
   #Set WaaS Stage Info
        
        # If Check Readiness Results Fail, set WaaS Stage to "IPU CheckReadiness Failed"
        if ($tsenv.Value("CheckReadinessResult") -ne "Pass")     
            {
            New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "IPU CheckReadiness Failed"
            }
        #If the Upgrade Step was successful, Set WaaS Stage to "IPU Complete"
        if ($hexreturncode -eq "0") 
            {
            New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "IPU Complete"
            }
        #If the Upgrade wasn't successful but got passed the Check Readiness Steps, Set WaaS Stage to "IPU Failed" 
        if ($hexreturncode -ne "0" -and $tsenv.Value("CheckReadinessResult") -eq "Pass") 
            {
            New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "IPU Failed"
            }
         
        #Increments the amount of times the IPU TS runs        try { [int]$Value = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\WaaS\$ID" -Name "IPU_Attempts" -ErrorAction SilentlyContinue } catch {}        New-Variable -Name "$($AttributePrefix)IPU_Attempts" -Value ($Value + 1).ToString()         }
         
 
#This Section runs for CompatScan Task Sequences
    if ($SetOSDInfoType -eq 'CS')
        {    
        #Check if Driver Download was specified
        if ($tsenv.Value('DownloadDrivers') -ne "True")
            {
            $Skip = "True"
            New-Variable -Name "$($AttributePrefix)CS_TSDriverDLTime" -Value "NA"
            }
        Else
            {
            $DriverDifference = ([datetime]$TSEnv.Value('SMSTS_FinishTSDownTime')) - ([datetime]$TSEnv.Value('SMSTS_StartTSDownTime')) 
            $DriverDifference = [math]::Round($DriverDifference.TotalMinutes)
            #Check to see if this value is already populated from an earlier run, if so, use it, otherwise use the value from the download times.            try { [int]$DLValue = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\WaaS\$ID" -Name "CS_TSDriverDLTime" -ErrorAction SilentlyContinue } catch {}            if ($DLValue -ge "1")
                {
                New-Variable -Name "$($AttributePrefix)CS_TSDriverDLTime" -Value ($DLValue).ToString()
                }
            if ($DriverDifference -ge "1")
                {
                New-Variable -Name "$($AttributePrefix)CS_TSDriverDLTime" -Value "$DriverDifference"
                }
            }
        #Check if Download Failed and Write Failed
        if ($tsenv.Value("DownloadDriversPHail") -eq "True"){New-Variable -Name "$($AttributePrefix)CS_Errors" -Value "Driver Download Failed"}
        #If it didn't failed, set value to NA
        Else{New-Variable -Name "$($AttributePrefix)CS_Errors" -Value "NA"}

        New-Variable -Name "$($AttributePrefix)CS_TaskSequenceName" -Value $tsenv.Value("_SMSTSPackageName")
        New-Variable -Name "$($AttributePrefix)CS_TaskSequenceID" -Value $tsenv.Value("_SMSTSPackageID")
        New-Variable -Name "$($AttributePrefix)CS_TSDeploymentID" -Value $tsenv.Value("_SMSTSAdvertID")
        if ($tsenv.Value("CheckReadinessResult") -eq "Pass")
            {
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineReturn" -Value "$ErrorMsg"
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineHexCode" -Value "$hexreturncode"
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineRunTime" -Value "$DifferenceUpgrade"
            }
        else
            {
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineReturn" -Value "NA"
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineHexCode" -Value "NA"
            New-Variable -Name "$($AttributePrefix)CS_SetupEngineRunTime" -Value "NA"
            }
        New-Variable -Name "$($AttributePrefix)CS_TSRunTime" -Value "$Difference"
        New-Variable -Name "$($AttributePrefix)CS_InstallationDate" -Value $(get-date -uformat "%Y%m%d-%T")
        New-Variable -Name "$($AttributePrefix)CS_CheckReadiness" -Value $tsenv.Value("CheckReadinessResult")
        
        if ( $hexreturncode -eq "C1900208"){New-Variable -Name "$($AttributePrefix)CS_HardBlocker" -Value $tsenv.Value("SMSTS_HardBlocker")}
              
         if ( $hexreturncode -eq "C1900210") 
            {
               New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "CS Completed Successfully"
               New-Variable -Name "$($AttributePrefix)CS_HardBlocker" -Value "NA"
            }
         Else
            {
             if ($tsenv.Value("CheckReadinessResult") -ne "Pass")
                {
                New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "CS CheckReadiness Failed"
                }
            Else
                {
                New-Variable -Name "$($AttributePrefix)WaaS_Stage" -Value "CS CompatScan Failed"
                }
            }
            
        #Increments the amount of times the Precache CompatScan TS runs        try { [int]$Value = Get-ItemPropertyValue -Path "HKLM:SOFTWARE\WaaS\$ID" -Name "CS_Attempts" -ErrorAction SilentlyContinue } catch {}        New-Variable -Name "$($AttributePrefix)CS_Attempts" -Value ($Value + 1).ToString()                    
    }



    #$customInfo = @()
    #$customInfo = $tsenv.getVariables() | where {$_ -match "$($AttributePrefix).*"}

    #Foreach ($infoItem in $customInfo)
    #{
    #    New-Variable -Name $infoItem -Value $tsenv.value($infoItem)
    #}

}

$customAttributes = Get-Variable -Name "$AttributePrefix*"

if ($PSBoundParameters.ContainsKey("WMI"))
{
    New-WMINamespace -Namespace $Namespace
    New-WMIClass -Namespace $Namespace -Class $Class -Attributes $customAttributes -Key $keyValue
    New-WMIClassInstance -Namespace $Namespace -Class $Class -Attributes $customAttributes
}

if ($PSBoundParameters.ContainsKey("Registry"))
{
    foreach ($attr in $customAttributes)
    {
        $attr.Name -match "$AttributePrefix(?<attributeName>.*)" | Out-Null
        $attrName = $matches['attributeName']

        if ($attr.Value) 
        {
            $attrVal = $attr.Value
        } 
        else 
        {
            $attrVal = ""
        }
        
        Write-Verbose "Setting registry value named $attrName to $attrVal"



        New-RegistryItem -Key "$($Class)\$ID" -ValueName $attrName -Value $attrVal

    }
}