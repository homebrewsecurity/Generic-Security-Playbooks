# Author: Logan Bennett
# Created: 03/05/2026
# Description: This script gets the contents of HKEY_USERS registry hive to list the currently acive users

$RegistryUsers = (Get-ChildItem registry::HKEY_USERS).Name.Split('\') | Select-String 'S-'

$ReturnArray = @()
$ErrorActionPreference = 'SilentlyContinue'
foreach ($SID in $RegistryUsers)
{
    $SidObject = New-Object System.Security.Principal.SecurityIdentifier($sid)

    $ReturnObject = [PSCustomObject]@{
        "Registry" = $SID
        "Account" = $SidObject.Translate([System.Security.Principal.NTAccount])
    }

    $ReturnArray += $ReturnObject
}

$ErrorActionPreference = 'Continue'

$ReturnArray

