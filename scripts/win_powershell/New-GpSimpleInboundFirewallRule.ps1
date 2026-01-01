#Requires -RunAsAdministrator

# Script written by Logan Bennett
# Sets up simple firewall rules allowing connections from RFC1918 IP addresses; edit as needed

[CmdletBinding()]
Param(
    [switch]$EnableRPC,
    [switch]$EnableSMB,
    [switch]$EnableRDP,
    [switch]$EnableWinRM,
    [switch]$EnableICMP,
    [switch]$EnableSNMPAgent,
    [switch]$EnableSNMPManagement,
    [switch]$EnableADWS,
    [switch]$EnableLDAP,
    [switch]$EnableGC,
    [switch]$EnableDNS,
    [switch]$EnableKerberos,
    [switch]$EnableNTP,
    [switch]$EnableKerbPwd,
    [switch]$EnableDHCP,

    [ValidateSet("Any","Domain","Private","Public")]
    [String]$Profile = "Any"
)

$GeneralParams = @{
    "PolicyStore" = "PersistentStore"
    "Direction" = "Inbound"
    "Profile" = [string]$Profile
    "Action" = "Allow"
    "Enabled" = "True"
    "RemoteAddress" = "LocalSubnet4"
}

# RPC Port Configuration
if ($EnableRPC)
{
    $DisplayName = "RPCMapper-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 135 -Protocol TCP -DisplayName $DisplayName

    $DisplayName = "RPCDynamicPorts-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort RPC -Protocol TCP -DisplayName $DisplayName
}

# SMB Configuration
if ($EnableSMB)
{
    $DisplayName = "SMB-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 445 -Protocol TCP -DisplayName $DisplayName
}

# RDP Configuration
if ($EnableRDP)
{
    $DisplayName = "RDP-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 3389 -Protocol TCP -DisplayName $DisplayName
}

# WinRM Configuration
if ($EnableWinRM)
{
    $DisplayName = "WinRMHTTP-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 5985 -Protocol TCP -DisplayName $DisplayName

    $DisplayName = "WinRMHTTPS-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 5986 -Protocol TCP -DisplayName $DisplayName
}

# ICMPv4 Configuration
if ($EnableICMP)
{
    $DisplayName = "ICMPEcho-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -IcmpType 8 -Protocol ICMPv4
}

# SNMP Agent Configuration (for querying)
if ($EnableSNMPAgent)
{
    $DisplayName = "SNMPAgent-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 161 -Protocol UDP
}

# SNMP Management Configuration (where MIB lives)
if ($EnableSNMPManagement)
{
    $DisplayName = "SNMPManagement-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 162 -Protocol UDP
}

# Enabled Active Directory Web Services
if ($EnableADWS)
{
    $DisplayName = "ADWS-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 9389 -Protocol TCP
}

# Enabled LDAP and LDAPS
if ($EnableLDAP)
{
    $DisplayName = "LDAP-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 389 -Protocol TCP

    $DisplayName = "LDAPSSL-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 636 -Protocol TCP
}

# Enabled GC and GCS
if ($EnableGC)
{
    $DisplayName = "GC-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 3268 -Protocol TCP

    $DisplayName = "GCSSL-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 3269 -Protocol TCP
}

# Enabled DNS
if ($EnableDNS)
{
    $DisplayName = "DNS-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 53 -Protocol UDP
}

# Enables Kerberos
if ($EnableKerberos)
{
    $DisplayName = "Kerberos-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 88 -Protocol TCP

    $DisplayName = "Kerberos-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 88 -Protocol UDP
}

# Enabled Kerberos Password Resets
if ($EnableKerbPwd)
{
    $DisplayName = "KerbPwd-TCP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 464 -Protocol TCP

    $DisplayName = "KerbPwd-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 464 -Protocol UDP
}

# Enables NTP
if ($EnableNTP)
{
    $DisplayName = "NTP-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 123 -Protocol UDP
}

# Enables DHCP service availability
if ($EnableDHCP)
{
    $DisplayName = "DHCP-UDP-$($GeneralParams.Direction)-$($GeneralParams.Action)-$($GeneralParams.Profile)"
    New-NetFirewallRule @GeneralParams -LocalPort 67 -RemotePort 68 -Protocol UDP
}

