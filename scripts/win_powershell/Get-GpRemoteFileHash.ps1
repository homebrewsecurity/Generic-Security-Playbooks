# Author: Logan Bennett
# Date: 04/01/2026
# Description: This scripts gets the hash of a remote file on a different computer

# Note: WinRM is required to be running on the remote machine

[CmdletBinding()]
Param(
  [Parameter(Mandatory=$True)]
  [String]$ComputerName,

  [Parameter(Mandatory=$False)]
  [ValidateSet('SHA1','SHA256','MD5')]
  [String]$HashAlgorithm = 'SHA256',
  
  [Parameter(Mandatory=$True)]
  [String]$FilePath,
  
  [Parameter(Mandatory=$False)]
  [PSCredential]$Credential
)

if ($Credential)
{
  $Session = New-PSSession -Credential $Credential -ComputerName $ComputerName -Authentication Negotiate -ErrorAction Stop
}
else
{
  $Session = New-PSSession -ComputerName $ComputerName -Authentication Negotiate -ErrorAction Stop
}

Invoke-Command -Session $Session -ScriptBlock {Get-FileHash -LiteralPath $Using:FilePath -Algorithm $Using:HashAlgorithm} -ErrorAction Continue
Remove-PSSession $Session
