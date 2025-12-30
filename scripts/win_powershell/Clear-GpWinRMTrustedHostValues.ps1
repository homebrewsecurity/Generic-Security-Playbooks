#Requires -RunAsAdministrator

# Simple script to reduce manual load of typing the path
Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value "" -Force