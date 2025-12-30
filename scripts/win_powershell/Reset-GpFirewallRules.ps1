#Requires -RunAsAdministrator

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName = 'Clear')]
    [Switch]$ClearAllRules,

    [Parameter(ParameterSetName = 'Reset')]
    [Switch]$ResetToDefaults,

    [Parameter(ParameterSetName = 'Clear')]
    [Parameter(ParameterSetName = 'Reset')]
    [Switch]$DoNotConfirm
)

# Confirms a user's input; Here to reduce redundancy
Function Get-ConfirmUserInput
{
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Message
    )

    # Starts the loop. Doesn't exit until it returns boolean value
    while ($True)
    {
        # Response read from the specified message
        $Response = (Read-Host ($Message + " (Y/n)")).ToLower()

        # Switch that evaluates the response
        switch ($Response)
        {
            # Default is yes if value is null or a empty string
            $NULL {Return $True}
            "" {Return $True}

            # Returns true or false for y or n
            'y' {Return $True}
            'n' {Return $False}

            # If nothing matches tell the user to try again
            default {Write-Host "Invalid response, please enter 'y' or 'n'"}
        }
    }
}

# Reset to system defaults if specified
if ($ResetToDefaults)
{
    # Specifies command path for the execution
    $CommandPath = 'C:\Windows\System32\netsh.exe'
    $Arguments = 'adv firewall reset'
    $Message = "This command will reset all persistent firewall rules to the system defaults. If you are connected remotely, this could end your session. Continue?"

    # Skips if user didn't specify the switch
    if (-not ($DoNotConfirm))
    {
        # Calls custom function to confirm user input
        $Result = Get-ConfirmUserInput -Message $Message

        # Exits if the return is false
        if (-not ($Result)) {Exit}
    }

    # Executes the process to reset firewall rules to system defaults
    Start-Process -FilePath $CommandPath -ArgumentList $Arguments -Wait
}
elseif ($ClearAllRules)
{
    $Message = "This command will clear all current firewall rules. If you are connected remotely, this could end your session. Continue?"

    if (-not ($DoNotConfirm))
    {
        # Calls custom function to confirm user input
        $Result = Get-ConfirmUserInput -Message $Message

        # Exits if the return is false
        if (-not ($Result)) {Exit}
    }

    # Gets the rules in the active store (persistemt + rsop, even though rsop is read-only) then removes them
    Get-NetFirewallRule -PolicyStore ActiveStore | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}