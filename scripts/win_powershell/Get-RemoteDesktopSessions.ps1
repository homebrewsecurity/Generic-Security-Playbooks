<#
    Author: Logan Bennett
    Date: 12/24/2025
    Description: This script gathers remote desktop connections on a local or remote machine.
    Notes: A function needs to be made to reduce the redundancy of the main code between remote and local execution.
           If you want to make the script faster you can lower the max logs the script searches through. Default is 200.
           Probably should make a variable that can set that value.
           The remote execution part has not been tested yet.
#>

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName="Remote")]
    $ComputerName,

    [Parameter(ParameterSetName="Remote")]
    [pscredential]$Credential,

    [Parameter(ParameterSetName="Remote")]
    [ValidateSet("WSMAN","DCOM")]
    $Protocol = "WSMAN"
)

Function Convert-ToHexString ([Int]$Number)
{
    "0x" + ($Number.ToString("X"))
}
    
# Does the remote stuff; not yet tested 
if ($ComputerName)
{

    # Sets up remote session with specified protocol
    Write-Verbose "Setting up CimSession to $ComputerName with the $Protocol protocol"
    $Options = New-CimSessionOption -Protocol $Protocol
    if ($Credential)
    {
        Write-Verbose "Setting CimSession credentials with provided creds"
        $CimSession = New-CimSession -SessionOption $Options -ComputerName $ComputerName -Credential $Credential

        if ($Protocol -eq "WSMAM")
        {
            # Not supported for DCOM yet
            # Need to get the last 200 login logs or so to find the last login with the login session later. If you're comfortable with the detection scope, lower the number for a faster script
            $LogonEvents = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-WinEvent -FilterHashtable @{"LogName" = "Security"; "ID" = 4624} -MaxEvents 200} -Credential $Credential
        }
    }
    else
    {
        Write-Verbose "No credentials specified, using default user context"
        $CimSession = New-CimSession -SessionOption $Options -ComputerName $ComputerName

        # Same as above but without creds
        $LogonEvents = Invoke-Command -ComputerName $ComputerName -ScriptBlock {Get-WinEvent -FilterHashtable @{"LogName" = "Security"; "ID" = 4624} -MaxEvents 200}
    }
    Write-Verbose "Connected to $ComputerName"

    # Gets the RDP sessions
    Write-Verbose "Getting remote RDP sessions"
    $RDPSessions = Get-CimInstance -Query "SELECT * FROM Win32_LogonSession WHERE LogonType = 10" -CimSession $CimSession

    # Gets the data and places it in a custom object; returns ReturnArray with all objects
    Write-Verbose "Looping through RDP sessions"
    $ReturnArray = @()
    foreach ($RDPSession in $RDPSessions)
    {
        Write-Verbose "Detected session LogonID $($RDPSession.LogonID) with LogonType $($RDPSession.LogonType)"
        $SessionAccountInfo = Get-CimAssociatedInstance $RDPSession -Association Win32_LoggedOnUser -CimSession $CimSession
        Write-Verbose "Session user is $($SessionAccountInfo.Name) with domain $($SessionAccountInfo.Domain)"

        # Gets the IP addresses. See below for a related command. Honestly this whole section probably needs to be a function
        $HexSession = Convert-ToHexString ([int]$RDPSession.LogonId)
        $IPAddresses = ((($LogonEvents | Where-Object {$_.Message -ilike "*$HexSession*"}).Message | Select-String -Pattern 'Source Network Address:\s+([0-9.]+)').Matches.Groups | Where {$_.Name -eq 1}).Value

        $Object = [PSCustomObject]@{
            "StartTime" = $RDPSession.StartTime
            "Username" = $SessionAccountInfo.Name
            "Domain" = $SessionAccountInfo.Domain
            "SourceIP" = $IPAddresses | Select -Unique
            "LogonID" = $RDPSession.LogonID
            "Authentication" = $RDPSession.AuthenticationPackage
            "LoggedOnComputer" = $ComputerName
        }

        $ReturnArray += $Object
    }

    # Tears down the con
    Write-Verbose "Tearing down created CimSession"
    Remove-CimSession $CimSession

    # GC to get rid of unreferenced kernel objects in memory related to the connection
    Write-Verbose "Running garbage collector"
    [GC]::Collect()
}

# Does the local stuff
else
{
    # Need to get the last 200 login logs or so to find the last login with the login session later. If you're comfortable with the detection scope, lower the number for a faster script
    $LogonEvents = Get-WinEvent -FilterHashtable @{"LogName" = "Security"; "ID" = 4624} -MaxEvents 200

    # Sets computernamer to the localhost
    Write-Verbose "Detected localhost execution"
    $ComputerName = hostname.exe

    # Gets the local rdp sessions
    Write-Verbose "Getting local instanced of RDP sessions"
    $RDPSessions = Get-CimInstance -Query "SELECT * FROM Win32_LogonSession WHERE LogonType = 10"

    # Loops through RDP sessions and stores data in custom object; returns data in ReturnArray
    Write-Verbose "Looping through local RDP sessions"
    $ReturnArray = @()
    foreach ($RDPSession in $RDPSessions)
    {
        # Gets the associations for the rdp login event
        Write-Verbose "Detected session LogonID $($RDPSession.LogonID) with LogonType $($RDPSession.LogonType)"
        $SessionAccountInfo = Get-CimAssociatedInstance $RDPSession -Association Win32_LoggedOnUser
        Write-Verbose "Session user is $($SessionAccountInfo.Name) with domain $($SessionAccountInfo.Domain)"

        # Gets the source IP for the session
        $HexSession = Convert-ToHexString ([int]$RDPSession.LogonId)
        $IPAddresses = ((($LogonEvents | Where-Object {$_.Message -ilike "*$HexSession*"}).Message | Select-String -Pattern 'Source Network Address:\s+([0-9.]+)').Matches.Groups | Where {$_.Name -eq 1}).Value

        $Object = [PSCustomObject]@{
            "StartTime" = $RDPSession.StartTime
            "Username" = $SessionAccountInfo.Name
            "Domain" = $SessionAccountInfo.Domain
            "SourceIP" = $IPAddresses | Select -Unique
            "LogonID" = $RDPSession.LogonID
            "HexLogonID" = $HexSession
            "Authentication" = $RDPSession.AuthenticationPackage
            "LoggedOnComputer" = $ComputerName
        }

        $ReturnArray += $Object
    }
}

# Returns the info to the user
Write-Verbose "Returning data and exiting script"
$ReturnArray