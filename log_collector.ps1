# log_collector.ps1
param (
    [int]$Last = 20,
    [string]$ExportPath = "./windows_security_events.json",
    [switch]$SendToAPI
)

Write-Host "🛡️ LogIQ SIEM - Windows Security Event Collector" -ForegroundColor Cyan
Write-Host "Collecting last $Last Windows Security login events..."

# Λήψη συμβάντων 4624 (Success) και 4625 (Failed)
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security';
        ID = 4624, 4625;
    } -MaxEvents $Last -ErrorAction Stop
} catch {
    Write-Error "Could not retrieve Windows Events. Make sure you are running as Administrator."
    return
}

$parsed = @()

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    
    # Εξαγωγή δεδομένων από το XML του Windows Event
    $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $ipAddress = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
    
    # Καθαρισμός IP (αν είναι τοπική "-" ή "::1")
    if ($ipAddress -eq "-" -or $ipAddress -eq "::1") { $ipAddress = "127.0.0.1" }

    $data = @{
        timestamp  = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")
        event_type = if ($event.Id -eq 4624) { "login_success" } else { "failed_login" }
        severity   = if ($event.Id -eq 4624) { "info" } else { "high" }
        username   = if ($targetUser) { $targetUser } else { "unknown" }
        ip         = if ($ipAddress) { $ipAddress } else { "0.0.0.0" }
        hostname   = $env:COMPUTERNAME
        status     = if ($event.Id -eq 4624) { "success" } else { "failed" }
        message    = "Windows Security Event ID $($event.Id): $($event.Message.Split(".")[0])"
    }
    $parsed += $data
}

# 1. Εξαγωγή σε τοπικό αρχείο JSON
$parsed | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 $ExportPath
Write-Host "✅ Exported $($parsed.Count) events to $ExportPath" -ForegroundColor Green

# 2. Αποστολή στο API του Xubuntu (Bridge Mode)
if ($SendToAPI) {
    $api_url = "http://192.168.0.128:5000/api/events"
    $headers = @{
        "X-API-KEY" = "LOGIQ_SUPER_SECRET_KEY_2026"
        "Content-Type" = "application/json"
    }

    Write-Host "🚀 Sending events to SIEM API at $api_url..." -ForegroundColor Yellow

    foreach ($event in $parsed) {
        try {
            $jsonBody = $event | ConvertTo-Json -Depth 3
            Invoke-RestMethod -Uri $api_url -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop
            Write-Host "[OK] Sent event: $($event.event_type) for user $($event.username)" -ForegroundColor Gray
        } catch {
            Write-Warning "Failed to send event to API: $($_.Exception.Message)"
        }
    }
    Write-Host "✨ Data synchronization complete." -ForegroundColor Green
}