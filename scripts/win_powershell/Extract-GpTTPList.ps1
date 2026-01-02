
# Written by Logan Bennett
# This is a simple script to extract TTPs from a report, list, file, etc.
# For files, the script only gets the raw content; pdfs, docx, etc. aren't supported. Text files work fine
# You can think of this as a strings parser

[CmdletBinding()]
Param(
    [Parameter(ParameterSetName="Raw")]
    [String]$String,

    [Parameter(ParameterSetName="Content")]
    [String]$File
)

Function Extract-TTPs
{
    Param(
        [Parameter(Mandatory=$True)]
        [String]$Content
    )

    ($Content | Select-String -Pattern 'T[A0-9]{4,5}[.0-9]{0,4}' -AllMatches).Matches.Value | Sort-Object -Unique
}

if ($String)
{
    Extract-TTPs -Content $String
}
elseif ($File -and (Test-Path $File))
{
    [string]$FileContent = Get-Content $File -ErrorAction Stop

    Extract-TTPs -Content $FileContent
}
else
{
    Write-Error "There was a problem accessing the file; please make sure your path is correct."
}