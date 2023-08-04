# Define the function to parse Sensitive Privilege Use events
filter ParseSPUEvent {
    $SelectorStrings = [string[]]@(
        'Event/EventData/Data[@Name="SubjectUserName"]',
        'Event/EventData/Data[@Name="SubjectDomainName"]',
        'Event/EventData/Data[@Name="SubjectUserSid"]',
        'Event/EventData/Data[@Name="ProcessId"]',
        'Event/EventData/Data[@Name="ProcessName"]'
    )
    $PropertySelector = [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new($SelectorStrings)
    $SubjectUserName, $SubjectDomainName, $SubjectUserSid, $ProcessId, $ProcessName = $_.GetPropertyValues($PropertySelector)

    # Exclude events where the ProcessName contains the full path to powershell.exe
    if ($ProcessName -notlike '*\powershell.exe') {
        [pscustomobject][ordered]@{
            DateTime     = $_.TimeCreated
            UserName     = $SubjectUserName
            Domain       = $SubjectDomainName
            UserSid      = $SubjectUserSid
            ProcessId    = $ProcessId
            ProcessName  = $ProcessName
        } | Write-Output
    }
}

# Continuously run the script
while ($true) {
    # Read the events with ID 4673 from the Security log and apply the ParseSPUEvent filter
    $events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4673; StartTime = (Get-Date).AddDays(-1)} | Where-Object { $_.ProviderName -ne 'Microsoft-Windows-PowerShell' }
    $events | ParseSPUEvent

    # Sleep for a specific interval (e.g., 1 minute) before checking for events again
    Start-Sleep -Seconds 60
}
