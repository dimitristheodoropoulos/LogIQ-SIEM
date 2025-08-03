# log_collector.ps1
param (
    [int]$Last = 20,
    [string]$ExportPath = "./windows_security_events.json",
    [switch]$SendToAPI
)

Write-Host "Collecting last $Last Windows Security login events..."

$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security';
    ID = 4624, 4625;
} -MaxEvents $Last

$parsed = @()

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{
        timestamp = $event.TimeCreated.ToString("s")
        event_type = if ($event.Id -eq 4624) { "login_success" } else { "failed" }
        message = $event.Message
        user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    }
    $parsed += $data
}

# Εξαγωγή σε JSON
$parsed | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 $ExportPath
Write-Host "Exported $($parsed.Count) events to $ExportPath"

# Προαιρετική αποστολή σε Flask API
if ($SendToAPI) {
    foreach ($event in $parsed) {
        try {
            Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/v1/security_events" `
                              -Method Post `
                              -ContentType "application/json" `
                              -Body ($event | ConvertTo-Json -Depth 3)
        } catch {
            Write-Warning "Failed to send event: $_"
        }
    }
    Write-Host "Events sent to Flask API."
}
