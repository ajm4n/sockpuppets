#!/bin/bash
# SockPuppets C2 — Development Environment Setup
# Installs all toolchains needed to generate agents in every supported language.
#
# Usage: ./setup.sh [--all | --python | --go | --rust | --csharp | --c]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }

check_cmd() {
    if command -v "$1" &>/dev/null; then
        ok "$1 found: $($1 --version 2>/dev/null | head -1)"
        return 0
    else
        return 1
    fi
}

install_python_deps() {
    echo ""
    echo "=== Python Dependencies ==="
    check_cmd python3 || { fail "Python 3 not found"; return 1; }
    pip3 install --quiet cryptography aiohttp websockets 2>/dev/null
    ok "Python packages: cryptography, aiohttp, websockets"
}

install_go() {
    echo ""
    echo "=== Go Toolchain ==="
    if check_cmd go; then
        return 0
    fi
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install go
    elif [[ "$OSTYPE" == "linux"* ]]; then
        sudo apt-get update && sudo apt-get install -y golang-go 2>/dev/null || \
        sudo yum install -y golang 2>/dev/null || \
        { warn "Install Go manually: https://go.dev/dl/"; return 1; }
    fi
    check_cmd go
}

install_garble() {
    echo ""
    echo "=== Garble (Go obfuscator) ==="
    if check_cmd garble || [ -f ~/go/bin/garble ]; then
        ok "garble found"
        return 0
    fi
    go install mvdan.cc/garble@latest 2>/dev/null
    if [ -f ~/go/bin/garble ]; then
        ok "garble installed at ~/go/bin/garble"
    else
        warn "garble installation failed (optional — Go agents will build without obfuscation)"
    fi
}

install_rust() {
    echo ""
    echo "=== Rust Toolchain ==="
    if check_cmd rustc && command -v rustup &>/dev/null; then
        rustup target add x86_64-pc-windows-gnu 2>/dev/null
        rustup target add x86_64-unknown-linux-gnu 2>/dev/null
        ok "Rust cross-compilation targets added"
        return 0
    fi
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
    rustup target add x86_64-pc-windows-gnu
    check_cmd rustc
}

install_dotnet() {
    echo ""
    echo "=== .NET SDK (C#) ==="
    if check_cmd dotnet; then
        return 0
    fi
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install dotnet
    elif [[ "$OSTYPE" == "linux"* ]]; then
        sudo apt-get update && sudo apt-get install -y dotnet-sdk-8.0 2>/dev/null || \
        { warn "Install .NET manually: https://dot.net/download"; return 1; }
    fi
    check_cmd dotnet
}

install_mingw() {
    echo ""
    echo "=== MinGW (C cross-compiler for Windows) ==="
    if check_cmd x86_64-w64-mingw32-gcc; then
        return 0
    fi
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install mingw-w64
    elif [[ "$OSTYPE" == "linux"* ]]; then
        sudo apt-get update && sudo apt-get install -y gcc-mingw-w64-x86-64 2>/dev/null || \
        sudo yum install -y mingw64-gcc 2>/dev/null || \
        { warn "Install MinGW manually"; return 1; }
    fi
    check_cmd x86_64-w64-mingw32-gcc
}

install_all() {
    install_python_deps
    install_go
    install_garble
    install_rust
    install_dotnet
    install_mingw
}

# Parse arguments
case "${1:-}" in
    --python)  install_python_deps ;;
    --go)      install_go; install_garble ;;
    --rust)    install_rust ;;
    --csharp)  install_dotnet ;;
    --c)       install_mingw ;;
    --all|"")  install_all ;;
    *)
        echo "Usage: $0 [--all | --python | --go | --rust | --csharp | --c]"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "  SockPuppets Setup Complete"
echo "=========================================="
echo ""
echo "Supported agent languages:"
check_cmd python3 && echo "  Python:     ✓" || echo "  Python:     ✗"
check_cmd go      && echo "  Go:         ✓" || echo "  Go:         ✗"
check_cmd rustc   && echo "  Rust:       ✓" || echo "  Rust:       ✗"
check_cmd dotnet  && echo "  C#/.NET:    ✓" || echo "  C#/.NET:    ✗"
check_cmd x86_64-w64-mingw32-gcc && echo "  C (Windows):✓" || echo "  C (Windows):✗"
echo ""
echo "Run: python3 main.py"
