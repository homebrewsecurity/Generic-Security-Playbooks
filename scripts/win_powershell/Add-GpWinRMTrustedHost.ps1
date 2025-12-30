#Requires -RunAsAdministrator

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)]
    [String]$Entry
)

# Gets the current trusted hosts
$CurrentHosts = (Get-Item 'WSMan:\localhost\Client\TrustedHosts').Value

# Compares them and exits if the trusted host already exists
if ($CurrentHosts | Select-String -Pattern $Entry)
{
    Write-Error "$Entry is already in TrustedHosts"
    Exit
}

# If it doesn't exist, check if the current hosts is empty or not. If it is, add the value
# If it isn't empty, append the new entry to the current list
if ([string]::IsNullOrEmpty($CurrentHosts))
{
    Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value "$Entry" -Force
}
else
{
    Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value "$CurrentHosts, $Entry" -Force
}