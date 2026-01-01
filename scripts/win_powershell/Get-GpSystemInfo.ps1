#Requires -RunAsAdministrator

# Written by Logan Bennett
# This script is written to accommodate xml and json outputs

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName='Basic')]
    [switch]$BasicInfo,

    [Parameter(ParameterSetName='Advanced')]
    [switch]$AdvancedInfo
)

# Coverted directly from Windows documentation
# https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.producttype?view=powershellsdk-7.4.0
Function ConvertFrom-ProductType
{
    Param(
        [Parameter(Mandatory=$True)]
        [int]$ProductType
    )

    # Does the conversion
    Switch ($ProductType)
    {
        1 {"Workstation"}
        2 {"Domain Controller"}
        3 {"Server"}
        default {"Unknown"}
    }
}

# Shorthand conversion for the Windows OS sourced from Danny Moran
# https://www.dannymoran.com/wmi-filter-cheat-sheet/
Function ConvertFrom-OSVersion
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$OSVersion,

        [Parameter(Mandatory=$True)]
        [int]$ProductType
    )

    # Windows Workstations
    if ($ProductType -eq 1)
    {
        Switch -Wildcard ($OSVersion)
        {
            "10.0.26200*" {"Windows 11 (25H2)"}
            "10.0.26100*" {"Windows 11 (24H2)"}
            "10.0.22631*" {"Windows 11 (23H2)"}
            "10.0.22621*" {"Windows 11 (22H2)"}
            "10.0.22000*" {"Windows 11 (21H2)"}
            "10.0.2*" {"Windows 11 (Unknown Release)"}
            "10.0.19045*" {"Windows 10 (22H2)"}
            "10.0.19044*" {"Windows 10 (21H2)"}
            "10.0.19043*" {"Windows 10 (21H1)"}
            "10.0.19042*" {"Windows 10 (20H2)"}
            "10.0.19041*" {"Windows 10 (2004)"}
            "10.0.18363*" {"Windows 10 (1909)"}
            "10.0.18362*" {"Windows 10 (1903)"}
            "10.0.17763*" {"Windows 10 (1809)"}
            "10.0.17134*" {"Windows 10 (1803)"}
            "10.0.16299*" {"Windows 10 (1709)"}
            "10.0.15063*" {"Windows 10 (1703)"}
            "10.0.14393*" {"Windows 10 (1607)"}
            "10.0.10586*" {"Windows 10 (1511)"}
            "10.0.10240*" {"Windows 10 (1507)"}
            "10.0.1*" {"Windows 10 (Unknown Release)"}
            "6.3*" {"Windows 8.1"}
            "6.2*" {"Windows 8.0"}
            "6.1*" {"Windows 7.0"}
            "6.0*" {"Windows Vista"}
            "5.1*" {"Windows XP"}
            "5.0*" {"Windows 2000"}
            Default {"Unknown Windows Workstation"}
        }
    }
    # Windows Servers
    elseif ($ProductType -eq 2 -or $ProductType -eq 3)
    {
        Switch -Wildcard ($OSVersion)
        {
            "10.0.26100*" {"Windows Server 2025"}
            "10.0.20348*" {"Windows Server 2022"}
            "10.0.17763*" {"Windows Server 2019"}
            "10.0.14393*" {"Windows Server 2016"}
            "6.3*" {"Windows Server 2012 R2"}
            "6.2*" {"Windows Server 2012"}
            "6.1*" {"Windows Server 2008 R2"}
            "6.0*" {"Windows Server 2008"}
            "5.2*" {"Windows Server 2003 / 2003 R2"}
            "5.0*" {"Windows Server 2000"}
            "10.0.19042*" {"Windows Server 20H2"}
            "10.0.19041*" {"Windows Server 2004"}
            "10.0.18363*" {"Windows Server 1909"}
            "10.0.18362*" {"Windows Server 1903"}
            "10.0.17134*" {"Windows Server 1809"}
            "10.0.16299*" {"Windows Server 1803"}
            "10.0.14393*" {"Windows Server 1709"}
            Default {"Unknown Windows Server"}
        }
    }
}

# Gets all the common data 
$OSData = Get-CimInstance -Query "Select * FROM Win32_OperatingSystem"
$BiosData = Get-CimInstance -Query "Select * FROM Win32_Bios"
$ComputerData = Get-CimInstance -Query "Select * FROM Win32_ComputerSystem"
$CPUData = Get-CimInstance -Query "Select * FROM Win32_Processor"
$MemoryData = Get-CimInstance -Query "Select * FROM Win32_PhysicalMemory"
$TimeData = Get-CimInstance -Query "Select * from win32_TimeZone"
$OperatingSystem = (ConvertFrom-OSVersion -OSVersion $OSData.Version -ProductType $OSData.ProductType)
$SystemTime = Get-Date -Format 'MM/dd/yyyy hh:mm:ss'
$IPAddress = ((Get-CimInstance -Namespace root\standardcimv2 'MSFT_NetIPAddress').IPAddress | ? {$_ -ne '127.0.0.1' -AND $_ -NE '::1'})

if ($BasicInfo)
{
    # Consolidates all the basic information
    $BasicInfoObject = [PSCustomObject]@{
        "Hostname" = $ComputerData.Name
        "Domain" = $ComputerData.Domain
        "OperatingSystem" = $OperatingSystem
        "InstallDate" = $OSData.InstallDate
        "IPAddress" = $IPAddress
        "Model" = $ComputerData.Model
        "SerialNumber" = $BiosData.SerialNumber
        "Manufacturer" = $BiosData.Manufacturer
        "BIOSVersion" = $BiosData.SMBIOSBIOSVersion
        "Processor" = $CPUData.Name
        "Architechture" = $OSData.OSArchitecture
        "TotalMemory" = ([string]($MemoryData.Capacity / 1GB) + " GB")
        "SystemTime" = $SystemTime
        "Timezone" = $TimeData.Caption
    }

    # Return to make the script easier to read
    Return $BasicInfoObject

}
elseif ($AdvancedInfo)
{
    # Gets all the advanced information
    # Careful on trusting the local users and groups; it doesn't show domain assignment, so be wary of that
    $ProcessData = Get-CimInstance -Query "Select * From win32_process"
    $ServiceData = Get-CimInstance -Query "Select * From win32_Service" | Select Name,PathName,StartMode,State,@{Name="ExecutionContext"; Expression="StartName"}
    $UserData = Get-CimInstance -Query "Select * From win32_Account WHERE LocalAccount='True' AND (SIDType = '1' OR SIDType = '5')"
    $GroupData = Get-CimInstance -Query "Select * From win32_Group WHERE LocalAccount = 'True'"
    $InstalledAppXData = Get-AppxPackage -AllUsers | Select Name,Publisher,Version,InstallLocation,PackageUserInformation
    $NetworkData = [PSCustomObject]@{
        "IPAddress" = $IPAddress
        "OpenPorts" = (Get-NetTCPConnection -State 'Listen') | Select LocalPort,OwningProcess
        "Connections" = (Get-NetTCPConnection -State 'Established') | Select RemoteAddress,RemotePort,LocalAddress,LocalPort,OwningProcess
        "NetworkedProcesses" = $ProcessData | ? {$_.ProcessID -in ((Get-CimInstance -Namespace root\standardcimv2 'MSFT_NetTCPConnection').OwningProcess)}
    }

    # Gets installed apps via the registry
    $InstalledAppsData = @()
    $InstalledAppsData += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $InstalledAppsData += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    
    # Gets the group membership
    $GroupMembershipArray = @()
    foreach ($Group in $GroupData)
    {
        $GroupMembershipObject = [PSCustomObject]@{
            "Name" = $Group.Name
            "Domain" = $Group.Domain
            "SID" = $Group.SID
            "Members" = ($Group | Get-CimAssociatedInstance -ResultClassName Win32_Account) | Select Name,Domain,SID
        }

        $GroupMembershipArray += $GroupMembershipObject
    }

    # Sets the correct variable and removes the array for memory management
    $GroupData = $GroupMembershipArray
    Remove-Variable GroupMembershipArray

    # Gets the hash and formats the rest of the Process data
    # The code gets strange here because sometimes the path doesn't exist for a process (because of integrity control) so filtering needs to be done
    # The filtering is done in the first if-else statement, the rest is just directly placed in the object and returned
    # Tis is not a bug, this is just how Windows handles some of its SYSTEM processes that we don't have the capability to natively idenitfy under the current integrity level

    $ProcessOwnerArray = @()
    foreach ($Process in $ProcessData)
    {
        if ($Process.ExecutablePath)
        {
            $Path = $Process.ExecutablePath
            $Hash = Get-FileHash -Algorithm SHA256 -Path $Path
        }
        else
        {
            $Hash = $Null
            $Path = $Null
        }

        $ProcessOwnerHashObject = [PSCustomObject]@{
            "Name" = $Process.Name
            "PID" = $Process.ProcessID
            "Path" = $Path
            "CommandLine" = $Process.CommandLine
            "CreationDate" = $Process.CreationDate
            "SHA256" = $Hash
            "Owner" = (Invoke-CimMethod $Process -MethodName GetOwner).User
        }
        
        $ProcessOwnerArray += $ProcessOwnerHashObject
    }

    # Sets the correct variable and removes the array for memory management
    $ProcessData=$ProcessOwnerArray
    Remove-Variable ProcessOwnerArray

    # Consolidates all objects into a nested object; gets all basic data PLUS extra data useful for analysis
    $AdvancedObject = [PSCustomObject]@{
        "Hostname" = $ComputerData.Name
        "Domain" = $ComputerData.Domain
        "OperatingSystem" = $OperatingSystem
        "InstallDate" = $OSData.InstallDate
        "IPAddress" = $IPAddress
        "Model" = $ComputerData.Model
        "SerialNumber" = $BiosData.SerialNumber
        "Manufacturer" = $BiosData.Manufacturer
        "BIOSVersion" = $BiosData.SMBIOSBIOSVersion
        "Processor" = $CPUData.Name
        "Architechture" = $OSData.OSArchitecture
        "TotalMemory" = ([string]($MemoryData.Capacity / 1GB) + " GB")
        "SystemTime" = $SystemTime
        "Timezone" = $TimeData.Caption
        "Processes" = $ProcessData
        "Services" = $ServiceData
        "LocalUsers" = $UserData
        "LocalGroups" = $GroupData
        "Apps" = $InstalledAppsData | Select DisplayName,PSChildName,InstallLocation,Version,ModifyPath,UninstallString
        "AppXApps" = $InstalledAppXData
        "Network" = $NetworkData
    }

    Return $AdvancedObject
}


