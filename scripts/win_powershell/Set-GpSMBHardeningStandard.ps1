#Requires -RunAsAdministrator

# Written by Logan Bennett
# This script sets modern hardening standards for SMB, minus the firewall rules
# TODO: Some of these commands are only avaialble on Windows 11 and Windows Server 2025, so need to add OS version handeling
# For now this script is good for newer deployments

[CmdletBinding()]
Param(
    [switch]$ServerConfig,
    [switch]$ClientConfig
)

Function Remove-SMBVersion1
{
    # Begins removing insecure protocols
    $SMBFeatures = @('FS-SMB1','FS-SMB1-CLIENT','FS-SMB1-SERVER')
    Get-WindowsFeature -Name $SMBFeatures | Uninstall-WindowsFeature -Remove -IncludeManagementTools
}

#### Server Configuration ####

if ($ServerConfig)
    {

    # Checks if the service is running, if not exits
    $SMBService = Get-Service -Name 'LanmanServer' -ErrorAction Stop

    if ($SMBService.Status -eq 'Running')
    {
        # Removes SMB1 from the system
        Remove-SMBVersion1

        # Now disables SMBv1 & SMB/QUIC and turns on SMBv2/3
        Set-SmbServerConfiguration -EnableSMB1Protocol $False -EnableSMB2Protocol $True -EnableSMBQUIC $False

        # Enforces encryption over all shares and enables signing
        Set-SmbServerConfiguration -EncryptData $True -EnableSecuritySignature $True -RequireSecuritySignature $True

        # Sets a decent standard of encryption for the encryption algorithms
        Set-SmbServerConfiguration -EncryptionCiphers 'AES_128_GCM, AES_256_GCM'

        # Now restricts unencrypted access
        Set-SmbServerConfiguration -RejectUnencryptedAccess $True

        # Sets the only accepted SMB versions as 3.0
        Set-SmbServerConfiguration -Smb2DialectMin SMB300 -Smb2DialectMax SMB311

        # Sets an auth limiter to 10 seconds (increased from default 2 seconds)
        Set-SmbServerConfiguration -EnableAuthRateLimiter $True -InvalidAuthenticationDelayTimeInMs 10000 # 10 seconds in miliseconds

        # Sets auditing levels for suspicious behavior
        Set-SmbServerConfiguration -AuditInsecureGuestLogon $True -AuditClientDoesNotSupportEncryption $True -AuditSmb1Access $True -AuditClientDoesNotSupportSigning $True

        # Finally, sets forced logoff when user logon hours expire
        Set-SmbServerConfiguration -EnableForcedLogoff $True
    }
    else
    {
        Write-Error "The SMB service (Server / LanmanServer) is not running."
    }
}


##### Client Configuration #####

if($ClientConfig)
{
    # Removes SMB1 from the system
    Remove-SMBVersion1

    # Blocks NTLM for outbound authentication
    Set-SmbClientConfiguration -BlockNTLM $True 

    # Enforces encryption usage
    Set-SmbClientConfiguration -RequireEncryption $True

    # Enforces ciphers
    Set-SmbClientConfiguration -EncryptionCiphers 'AES_128_GCM, AES_256_GCM'

    # Enforces signing
    Set-SmbClientConfiguration -RequireSecuritySignature $True

    # Turns off mailslots
    Set-SmbClientConfiguration -EnableMailslots $False

    # Disables SMB via QUIC
    Set-SmbClientConfiguration -EnableSMBQUIC $False

    # Disables guest logins
    Set-SmbClientConfiguration -EnableInsecureGuestLogons $False
}

if (-not ($ServerConfig -and $ClientConfig))
{
    Write-Error "You must specify one or both of the available switches: ServerConfig / ClientConfig"
}
