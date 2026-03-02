<#
    AUTHOR
      - Logan Bennett
    NOTES
      - This script attempts to detect suspicious activity stemming from LOLBin activity
      - Script is for quick initial triage rather than a high-fidelity detection
#>

$LOLBas = (Invoke-WebRequest -Uri 'https://lolbas-project.github.io/api/lolbas.json' -Method Get -UseBasicParsing).Content | ConvertFrom-Json
$ExecutableLOLBinaries = ($LOLBas | Where-Object {$_.Commands.tags -like "*Execute*"}) # | Select -ExpandProperty Command

$ProcessInstances = Get-CimInstance -Query "Select * From win32_Process"

$SuspiciousProcesses = @()
foreach ($Process in $ProcessInstances)
{
    $ParentProcess = Get-Process -Id $Process.ParentProcessId -ErrorAction SilentlyContinue

    if ($ExecutableLOLBinaries.Name -like "$($ParentProcess.Name)*" -and ($Process.Path -notlike "C:\Windows\*" -and $Process.Path -notlike "C:\Program Files*"))
    {
        $SuspiciousProcesses += $Process
    }
}

$SuspiciousProcesses | Select Name,CommandLine,Path,ParentProcessID,ProcessID | FL
