<#
.SYNOPSIS

Gets the current active remote desktop sessions on a local or remote machine.

.DESCRIPTION

Author: Logan Bennett
Date: 12/25/2025

Gathers data from the local or remote machine to parse current RDP session information.
This includes the RDP source, the authentication protocol, session start time, and the username.
WSMAN is the only supported protocol with this script. DCOM is possible, however data will be missing from the results.
The script uses a combination of Get-CimInstance and Get-WinEvent to do the bulk of the work.


.PARAMETER Credential
Specifies the authentication credentials used to query the remote machine.

.PARAMETER ComputerName
Specified the remote computer to which will be queried.

.INPUTS

None. You can't pipe objects to this script.

.OUTPUTS

PSCustomObject is outputed.

.EXAMPLE

PS> .\Get-GpRemoteDesktopSessions.ps1

.EXAMPLE

PS> .\Get-GpRemoteDesktopSessions.ps1 -Credential (Get-Credential) -ComputerName <RemoteComputerName>

#>

### Parameters ###

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName="Remote")]
    $ComputerName,

    [Parameter(ParameterSetName="Remote")]
    [pscredential]$Credential
)

### Functions ###

# Simply converts an int into a hex string
Function Convert-ToHexString ([Int]$Number)
{
    "0x" + ($Number.ToString("X"))
}

# A quick way to query the RDP sessions but overall fairly simple. Uses CIM to do so and if a remote sesison isn't passed it will run on the local machine
Function Get-GpRDPSessionList
{
    Param(
        [Parameter(ParameterSetName="Remote")]
        [CimSession]$CimSession
    )

    if ($CimSession)
    {
        Get-CimInstance -Query "SELECT * FROM Win32_LogonSession WHERE LogonType = 10" -CimSession $CimSession
    }
    else
    {
        Get-CimInstance -Query "SELECT * FROM Win32_LogonSession WHERE LogonType = 10"
    }
}

<#

Main function (Get-GpRDPSessions) of the script; gets all the information needed by a security analyst without manual correlation.

The function checks if there's an associated cimsession for remote connections. At this time the protocol cannot be DCOM because Get-WinEvent only supports WSMAN (WinRM);
this is a design choice due to the unfortunate speed limitations posed by the Win32_NTLogEvent class. In this case speed is prioritized over maintaining CIM/WMI continuity
between commands. A DCOM session can be passed, but the source IP will be missing. If that is the case, a warning will presented.

The function then executes checks against the remote machine via the passed in session. If no session is present, it will run on the local machine.

The steps are as follows:
  - Get the computername which is being assessed
  - List the computer's RDP sessions
  - Get the security logs (Max events up to 300 for detection capability, edit this if you'd like)
  - Loops through each session, gathers the session's user info, and parses the logs for the source IP
  - Returns a custom object containing relevant information

#>
Function Get-GpRDPSessions
{
    [CmdletBinding()]
    Param(
        [Parameter(ParameterSetName="Remote")]
        [CimSession]$CimSession,

        [Parameter(ParameterSetName="Remote")]
        [PSCredential]$Credential
    )

    if ($CimSession)
    {
        # Checks CimSession protocol
        if ($CimSession.Protocol -ilike "DCOM")
        {
            Write-Warning "The DCOM protocol is not fully supported in the Get-GpRDPSessions function. As such, the returned object will contain missing or null data."
        }

        # Gets computername and rdp session list
        $ComputerName = $CimSession.ComputerName
        $RDPSessions = Get-GpRDPSessionList -CimSession $CimSession

        # Checks if the credential is provided for the Get-WinEvent command. Acts accordingly
        if ($Credential)
        {
            $SecurityLogs = Get-WinEvent -FilterHashtable @{ LogName = "Security"; ID = 4624} -MaxEvents 300 -ComputerName $CimSession.ComputerName -Credential $Credential
        }
        else
        {
            $SecurityLogs = Get-WinEvent -FilterHashtable @{ LogName = "Security"; ID = 4624} -MaxEvents 300 -ComputerName $CimSession.ComputerName
        }

        # Starts the loop to create the custom objects
        $ReturnArray = @()
        foreach ($RDPSession in $RDPSessions)
        {
            # Converts the login id to a hex value for searching through the logs
            $HexSession = Convert-ToHexString ([Int]$RDPSession.LogonId)

            # Gets the user info from the RDP session
            $SessionAccountInfo = Get-CimAssociatedInstance $RDPSession -Association Win32_LoggedOnUser -CimSession $CimSession

            # Parses the logs for the source IP tied to the login session
            $IPs = ((($SecurityLogs | Where-Object {$_.Message -ilike "*$HexSession*"}).Message | Select-String -Pattern 'Source Network Address:\s+([0-9A-Fa-f:.]+)').Matches.Groups | Where-Object {$_.Name -eq 1}).Value

            # Creates the object
            $RemoteObject = [PSCustomObject]@{
                "Username" = $SessionAccountInfo.Name
                "Domain" = $SessionAccountInfo.Domain
                "IsLocalAccount" = $SessionAccountInfo.LocalAccount
                "StartTime" = $RDPSession.StartTime
                "LogonID" = $HexSession
                "AuthMethod" = $RDPSession.AuthenticationPackage
                "ComputerName" = $ComputerName
                "RemoteIP" = $IPs | Sort-Object -Unique
            }

            # Adds the object to the results
            $ReturnArray += $RemoteObject
        }
    }
    else
    {
        # Gets the computerhostname, the event logs, and the rdp session lists
        $ComputerName = hostname.exe
        $RDPSessions = Get-GpRDPSessionList
        $SecurityLogs = Get-WinEvent -FilterHashtable @{ LogName = "Security"; ID = 4624} -MaxEvents 300

        # Starts the loop to format the objects
        $ReturnArray = @()
        foreach ($RDPSession in $RDPSessions)
        {
            # Converts the logon id to a hex value to search through the logs
            $HexSession = Convert-ToHexString ([Int]$RDPSession.LogonId)

            # Gets the related user info tied to the rdp session
            $SessionAccountInfo = Get-CimAssociatedInstance $RDPSession -Association Win32_LoggedOnUser

            # Parses the logs to get the source IPs of the rdp connection
            $IPs = ((($SecurityLogs | Where-Object {$_.Message -ilike "*$HexSession*"}).Message | Select-String -Pattern 'Source Network Address:\s+([0-9A-Fa-f:.]+)').Matches.Groups | Where-Object {$_.Name -eq 1}).Value

            # Formats the object
            $LocalObject = [PSCustomObject]@{
                "Username" = $SessionAccountInfo.Name
                "Domain" = $SessionAccountInfo.Domain
                "IsLocalAccount" = $SessionAccountInfo.LocalAccount
                "StartTime" = $RDPSession.StartTime
                "LogonID" = $HexSession
                "AuthMethod" = $RDPSession.AuthenticationPackage
                "ComputerName" = $ComputerName
                "RemoteIP" = $IPs | Sort-Object -Unique
            }

            # Adds the object to the return array
            $ReturnArray += $LocalObject
        }
    }

    # Returns the results
    $ReturnArray
}

### Script Execution ###

# Writes an error and stops the script if the parameters aren't used correctly. If correct, checks for a remote session specified. If no session, run locally
if ($Credential -and -not $ComputerName)
{
    Write-Error "The Credential parameter requires the ComputerName parameter." -ErrorAction Stop
}
elseif ($ComputerName)
{
    # Checks if creds are provided. If not, use logged in security context
    if ($Credential)
    {
        # Uses specified context; ends if fails
        $CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop

        # Executes main function
        Get-GpRDPSessions -CimSession $CimSession -Credential $Credential
    }
    else
    {
        # Uses logged in context; script ends if fails
        $CimSession = New-CimSession -ComputerName $ComputerName -ErrorAction Stop

        # Executes main function on the remote machine
        Get-GpRDPSessions -CimSession $CimSession
    }
}
else
{
    # Executes the main function on the local machine
    Get-GpRDPSessions
}