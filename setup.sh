#!/bin/bash
# SockPuppets C2 — Environment Setup
# Installs Python deps, toolchains, generates certs/keys if missing.
#
# Usage:
#   ./setup.sh              Install everything
#   ./setup.sh --python     Python venv + deps only
#   ./setup.sh --go         Go + garble
#   ./setup.sh --rust       Rust + cross targets
#   ./setup.sh --csharp     .NET SDK
#   ./setup.sh --c          MinGW cross-compiler
#   ./setup.sh --check      Validate install without changing anything
#   ./setup.sh --ci         Non-interactive (no prompts, skip optional tools)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="$SCRIPT_DIR/setup.log"
ERRORS=0
WARNINGS=0
CHECK_ONLY=false
CI_MODE=false
MIN_PYTHON="3.10"

# --- Output ---

if [ -t 1 ] && [ "${TERM:-dumb}" != "dumb" ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; DIM=''; BOLD=''; NC=''
fi

ok()   { echo -e "${GREEN}[+]${NC} $1"; echo "[+] $1" >> "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; echo "[!] $1" >> "$LOG_FILE"; WARNINGS=$((WARNINGS + 1)); }
fail() { echo -e "${RED}[-]${NC} $1"; echo "[-] $1" >> "$LOG_FILE"; ERRORS=$((ERRORS + 1)); }
info() { echo -e "${DIM}    $1${NC}"; echo "    $1" >> "$LOG_FILE"; }
section() { echo ""; echo -e "${BOLD}=== $1 ===${NC}"; echo "=== $1 ===" >> "$LOG_FILE"; }

# --- Helpers ---

cmd_exists() { command -v "$1" &>/dev/null; }

cmd_version() {
    if cmd_exists "$1"; then
        # go uses 'go version', everything else uses '--version'
        if [ "$1" = "go" ]; then
            go version 2>/dev/null | awk '{print $3}'
        else
            $1 --version 2>/dev/null | head -1
        fi
    fi
}

version_ge() {
    # Returns 0 if $1 >= $2 (dotted version comparison)
    printf '%s\n%s\n' "$2" "$1" | sort -V | head -1 | grep -qx "$2"
}

python_version() {
    python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null
}

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "$ID" in
                ubuntu|debian|kali|pop) echo "debian" ;;
                fedora|rhel|centos|rocky|alma) echo "rhel" ;;
                arch|manjaro) echo "arch" ;;
                *) echo "linux-unknown" ;;
            esac
        else
            echo "linux-unknown"
        fi
    else
        echo "unknown"
    fi
}

pkg_install() {
    local os_type="$1"; shift
    case "$os_type" in
        macos)
            if ! cmd_exists brew; then
                warn "Homebrew not found — install from https://brew.sh"
                return 1
            fi
            brew install "$@" 2>>"$LOG_FILE"
            ;;
        debian)
            sudo apt-get update -qq >>"$LOG_FILE" 2>&1
            sudo apt-get install -y -qq "$@" >>"$LOG_FILE" 2>&1
            ;;
        rhel)
            sudo dnf install -y -q "$@" >>"$LOG_FILE" 2>&1 || \
            sudo yum install -y -q "$@" >>"$LOG_FILE" 2>&1
            ;;
        arch)
            sudo pacman -S --noconfirm --needed "$@" >>"$LOG_FILE" 2>&1
            ;;
        *)
            warn "Cannot auto-install on this OS — install manually: $*"
            return 1
            ;;
    esac
}

# --- Install steps ---

install_python_deps() {
    section "Python Environment"
    local os_type; os_type=$(detect_os)

    if ! cmd_exists python3; then
        fail "Python 3 not found"
        info "Install: https://www.python.org/downloads/"
        return 1
    fi

    local pyver; pyver=$(python_version)
    if ! version_ge "$pyver" "$MIN_PYTHON"; then
        fail "Python $pyver found, need >= $MIN_PYTHON (str | None syntax)"
        info "Upgrade: https://www.python.org/downloads/"
        return 1
    fi
    ok "Python $pyver"

    if $CHECK_ONLY; then
        # Verify venv and packages
        if [ ! -d ".venv" ]; then
            warn "Virtual environment not found (.venv/)"
        else
            ok "Virtual environment exists"
            local missing=0
            for pkg in websockets aiohttp cryptography yaml rich pyinstaller; do
                local imp=$pkg
                [ "$pkg" = "yaml" ] && imp="yaml"
                if ! .venv/bin/python3 -c "import $imp" 2>/dev/null; then
                    warn "Package missing: $pkg"
                    missing=$((missing + 1))
                fi
            done
            [ $missing -eq 0 ] && ok "All core packages present"
        fi
        return 0
    fi

    # Create or validate venv
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv 2>>"$LOG_FILE"
        if [ $? -ne 0 ]; then
            fail "Failed to create virtual environment"
            info "On Debian/Ubuntu: sudo apt install python3-venv python3-dev"
            return 1
        fi
        ok "Virtual environment created"
    else
        ok "Virtual environment exists"
    fi

    # Validate venv has a working python and pip
    local VPYTHON=".venv/bin/python3"
    local VPIP=".venv/bin/pip"
    if [ ! -x "$VPYTHON" ]; then
        warn "Broken venv (no python3 binary) — recreating"
        rm -rf .venv
        python3 -m venv .venv 2>>"$LOG_FILE"
        if [ ! -x "$VPYTHON" ]; then
            fail "Cannot create working virtual environment"
            info "On Debian/Ubuntu: sudo apt install python3-venv python3-dev"
            return 1
        fi
        ok "Virtual environment recreated"
    fi

    if [ ! -x "$VPIP" ]; then
        $VPYTHON -m ensurepip --upgrade >>"$LOG_FILE" 2>&1
    fi

    # Upgrade pip first
    $VPYTHON -m pip install --quiet --upgrade pip >>"$LOG_FILE" 2>&1

    # Core deps
    if $VPIP install -r requirements.txt >>"$LOG_FILE" 2>&1; then
        ok "Core packages: websockets, aiohttp, cryptography, pyyaml, rich, pyinstaller"
    else
        fail "Failed to install core requirements"
        info "Check setup.log for details"
        info "Try: .venv/bin/pip install -r requirements.txt"
        return 1
    fi

    # GUI deps
    if [ -f requirements-gui.txt ]; then
        if $VPIP install -r requirements-gui.txt >>"$LOG_FILE" 2>&1; then
            ok "GUI packages: fastapi, uvicorn, pydantic"
        else
            warn "Failed to install GUI requirements (GUI will be unavailable)"
        fi
    fi

    # TUI deps
    if [ -f requirements-tui.txt ]; then
        if $VPIP install -r requirements-tui.txt >>"$LOG_FILE" 2>&1; then
            ok "TUI packages: textual"
        else
            warn "Failed to install TUI requirements (TUI will be unavailable)"
        fi
    fi

    # Verify critical imports
    local verify_fail=0
    for mod in websockets aiohttp cryptography yaml; do
        if ! .venv/bin/python3 -c "import $mod" 2>/dev/null; then
            fail "Import verification failed: $mod"
            verify_fail=1
        fi
    done
    [ $verify_fail -eq 0 ] && ok "Import verification passed"
}

install_go() {
    section "Go Toolchain"
    local os_type; os_type=$(detect_os)

    if cmd_exists go; then
        ok "Go: $(cmd_version go)"
        return 0
    fi

    if $CHECK_ONLY; then
        warn "Go not installed"
        return 1
    fi

    case "$os_type" in
        macos)  pkg_install macos go ;;
        debian) pkg_install debian golang-go ;;
        rhel)   pkg_install rhel golang ;;
        arch)   pkg_install arch go ;;
        *)      warn "Install Go manually: https://go.dev/dl/"; return 1 ;;
    esac

    if cmd_exists go; then
        ok "Go installed: $(cmd_version go)"
    else
        fail "Go installation failed"
        info "Install manually: https://go.dev/dl/"
        return 1
    fi
}

install_garble() {
    section "Garble (Go obfuscator)"

    if cmd_exists garble || [ -f "$HOME/go/bin/garble" ]; then
        ok "garble found"
        return 0
    fi

    if $CHECK_ONLY; then
        warn "garble not installed (optional)"
        return 0
    fi

    if ! cmd_exists go; then
        warn "Go not installed — skipping garble"
        return 0
    fi

    if go install mvdan.cc/garble@latest >>"$LOG_FILE" 2>&1; then
        ok "garble installed"
    else
        warn "garble install failed (optional — agents build without obfuscation)"
    fi
}

install_rust() {
    section "Rust Toolchain"

    if cmd_exists rustc && cmd_exists cargo; then
        ok "Rust: $(cmd_version rustc)"

        if $CHECK_ONLY; then
            rustup target list --installed 2>/dev/null | grep -q "x86_64-pc-windows-gnu" && \
                ok "Windows cross target installed" || warn "Missing: rustup target add x86_64-pc-windows-gnu"
            return 0
        fi

        rustup target add x86_64-pc-windows-gnu >>"$LOG_FILE" 2>&1
        rustup target add x86_64-unknown-linux-gnu >>"$LOG_FILE" 2>&1
        ok "Cross-compilation targets configured"
        return 0
    fi

    if $CHECK_ONLY; then
        warn "Rust not installed"
        return 1
    fi

    # Always pass -y — we're in a script, interactive prompts will fail
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable >>"$LOG_FILE" 2>&1

    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    if cmd_exists rustc; then
        rustup target add x86_64-pc-windows-gnu >>"$LOG_FILE" 2>&1
        ok "Rust installed: $(cmd_version rustc)"
    else
        fail "Rust installation failed"
        info "Install manually: https://rustup.rs"
        return 1
    fi
}

install_dotnet() {
    section ".NET SDK (C#)"
    local os_type; os_type=$(detect_os)

    if cmd_exists dotnet; then
        ok ".NET: $(dotnet --version 2>/dev/null)"
        return 0
    fi

    if $CHECK_ONLY; then
        warn ".NET SDK not installed"
        return 1
    fi

    case "$os_type" in
        macos)  pkg_install macos dotnet ;;
        debian)
            # Try versioned names (varies by Ubuntu/Debian release)
            pkg_install debian dotnet-sdk-9.0 2>/dev/null || \
            pkg_install debian dotnet-sdk-8.0 2>/dev/null || \
            pkg_install debian dotnet9 2>/dev/null || \
            pkg_install debian dotnet8 2>/dev/null || {
                warn ".NET not in apt repos — install via https://dot.net/download"
                info "Or: wget https://dot.net/v1/dotnet-install.sh && bash dotnet-install.sh"
                return 1
            }
            ;;
        rhel)   pkg_install rhel dotnet-sdk-8.0 ;;
        arch)   pkg_install arch dotnet-sdk ;;
        *)      warn "Install .NET manually: https://dot.net/download"; return 1 ;;
    esac

    if cmd_exists dotnet; then
        ok ".NET installed: $(dotnet --version 2>/dev/null)"
    else
        fail ".NET installation failed"
        info "Install manually: https://dot.net/download"
        return 1
    fi
}

install_mingw() {
    section "MinGW (C cross-compiler)"
    local os_type; os_type=$(detect_os)

    if cmd_exists x86_64-w64-mingw32-gcc; then
        ok "MinGW: $(x86_64-w64-mingw32-gcc --version 2>/dev/null | head -1)"
        return 0
    fi

    if $CHECK_ONLY; then
        warn "MinGW not installed"
        return 1
    fi

    case "$os_type" in
        macos)  pkg_install macos mingw-w64 ;;
        debian) pkg_install debian gcc-mingw-w64-x86-64 ;;
        rhel)   pkg_install rhel mingw64-gcc ;;
        arch)   pkg_install arch mingw-w64-gcc ;;
        *)      warn "Install MinGW manually"; return 1 ;;
    esac

    if cmd_exists x86_64-w64-mingw32-gcc; then
        ok "MinGW installed"
    else
        fail "MinGW installation failed"
        return 1
    fi
}

generate_certs() {
    section "TLS Certificates"

    if [ -f "certs/server.pem" ] && [ -f "certs/server.key" ]; then
        # Validate cert isn't expired
        if cmd_exists openssl; then
            if openssl x509 -checkend 86400 -noout -in certs/server.pem >>"$LOG_FILE" 2>&1; then
                ok "TLS cert valid (certs/server.pem)"
                return 0
            else
                warn "TLS cert expired or expiring — regenerating"
            fi
        else
            ok "TLS cert exists (certs/server.pem)"
            return 0
        fi
    fi

    if $CHECK_ONLY; then
        warn "TLS cert missing (certs/server.pem)"
        return 1
    fi

    if ! cmd_exists openssl; then
        warn "openssl not found — cannot generate TLS cert"
        info "HTTPS listeners will not work until certs are provided"
        return 1
    fi

    mkdir -p certs
    openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
        -out certs/server.pem -days 365 -nodes \
        -subj "/CN=localhost/O=SockPuppets" >>"$LOG_FILE" 2>&1

    if [ -f "certs/server.pem" ] && [ -f "certs/server.key" ]; then
        chmod 600 certs/server.key
        ok "Generated self-signed TLS cert (365 days)"
    else
        fail "TLS cert generation failed"
        return 1
    fi
}

generate_keys() {
    section "Encryption Keys"

    if [ -f "keys/server_x25519.bin" ]; then
        ok "X25519 server key exists"
        return 0
    fi

    if $CHECK_ONLY; then
        warn "X25519 server key missing (keys/server_x25519.bin)"
        return 1
    fi

    mkdir -p keys

    # Generate via Python (cryptography lib) if available
    if [ -f ".venv/bin/python3" ]; then
        .venv/bin/python3 -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
key = X25519PrivateKey.generate()
with open('keys/server_x25519.bin', 'wb') as f:
    f.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
" >>"$LOG_FILE" 2>&1

        if [ -f "keys/server_x25519.bin" ]; then
            chmod 600 keys/server_x25519.bin
            ok "Generated X25519 server key"
            return 0
        fi
    fi

    # Fallback: openssl rand (X25519 private keys are 32 random bytes)
    if cmd_exists openssl; then
        openssl rand -out keys/server_x25519.bin 32 >>"$LOG_FILE" 2>&1
        if [ -f "keys/server_x25519.bin" ]; then
            chmod 600 keys/server_x25519.bin
            ok "Generated X25519 server key (via openssl)"
            return 0
        fi
    fi

    # Last resort: /dev/urandom
    if [ -c /dev/urandom ]; then
        dd if=/dev/urandom of=keys/server_x25519.bin bs=32 count=1 2>>"$LOG_FILE"
        if [ -f "keys/server_x25519.bin" ]; then
            chmod 600 keys/server_x25519.bin
            ok "Generated X25519 server key (via /dev/urandom)"
            return 0
        fi
    fi

    warn "Could not generate X25519 key — crypto handshake will fail"
    info "Install Python cryptography package first, then re-run"
    return 1
}

install_cli() {
    section "CLI Command"
    local target="/usr/local/bin/sockpuppets"
    local source="$SCRIPT_DIR/bin/sockpuppets"

    if [ ! -f "$source" ]; then
        fail "bin/sockpuppets not found in repo"
        return 1
    fi

    if [ -L "$target" ] || [ -f "$target" ]; then
        local existing; existing=$(readlink -f "$target" 2>/dev/null || echo "$target")
        if [ "$existing" = "$source" ]; then
            ok "sockpuppets command already installed"
            return 0
        fi
    fi

    if $CHECK_ONLY; then
        if cmd_exists sockpuppets; then
            ok "sockpuppets command available"
        else
            warn "sockpuppets command not installed"
        fi
        return 0
    fi

    if [ -w "/usr/local/bin" ] || [ "$(id -u)" -eq 0 ]; then
        ln -sf "$source" "$target"
    else
        sudo ln -sf "$source" "$target" 2>>"$LOG_FILE"
    fi

    if [ $? -eq 0 ] && [ -L "$target" ]; then
        chmod +x "$source"
        ok "Installed: sockpuppets → $source"
    else
        warn "Could not install to /usr/local/bin (try: sudo ln -sf $source $target)"
    fi
}

smoke_test() {
    section "Smoke Test"

    if [ ! -f ".venv/bin/python3" ]; then
        warn "Skipping smoke test (no venv)"
        return 1
    fi

    local result
    result=$(.venv/bin/python3 -c "
import sys
errors = []

# Core imports
for mod in ['websockets', 'aiohttp', 'cryptography', 'yaml', 'rich']:
    try:
        __import__(mod)
    except ImportError:
        errors.append(f'  missing: {mod}')

# Server import
sys.path.insert(0, '.')
try:
    from server import SockPuppetsServer
except Exception as e:
    errors.append(f'  server import: {e}')

# Agent generator
try:
    from agent import AgentGenerator
except Exception as e:
    errors.append(f'  agent import: {e}')

if errors:
    print('FAIL')
    for e in errors:
        print(e)
else:
    print('OK')
" 2>&1)

    if echo "$result" | head -1 | grep -q "^OK$"; then
        ok "Core imports verified (server, agent, crypto)"
    else
        fail "Smoke test failed:"
        echo "$result" | tail -n +2 | while read -r line; do
            info "$line"
        done
        return 1
    fi

    # GUI import check
    if .venv/bin/python3 -c "from fastapi import FastAPI; from gui.api import router" >>"$LOG_FILE" 2>&1; then
        ok "GUI imports verified (fastapi, gui.api)"
    else
        warn "GUI imports failed — web interface unavailable"
    fi

    # TUI import check
    if .venv/bin/python3 -c "from textual.app import App; from tui.app import SockPuppetsTUI" >>"$LOG_FILE" 2>&1; then
        ok "TUI imports verified (textual, tui.app)"
    else
        warn "TUI imports failed — terminal UI unavailable"
    fi
}

# --- Main ---

> "$LOG_FILE"
echo "SockPuppets setup log — $(date)" >> "$LOG_FILE"
echo "OS: $(uname -srm)" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"

echo ""
echo -e "${BOLD}SockPuppets C2 — Setup${NC}"
echo -e "${DIM}$(detect_os) | $(uname -m)${NC}"

# Parse arguments
ACTION="all"
for arg in "$@"; do
    case "$arg" in
        --python)  ACTION="python" ;;
        --go)      ACTION="go" ;;
        --rust)    ACTION="rust" ;;
        --csharp)  ACTION="csharp" ;;
        --c)       ACTION="c" ;;
        --check)   CHECK_ONLY=true; ACTION="all" ;;
        --ci)      CI_MODE=true ;;
        --all)     ACTION="all" ;;
        --help|-h)
            echo "Usage: $0 [--all | --python | --go | --rust | --csharp | --c | --check | --ci]"
            echo ""
            echo "  --all       Install everything (default)"
            echo "  --python    Python venv + all pip deps"
            echo "  --go        Go toolchain + garble"
            echo "  --rust      Rust + Windows cross target"
            echo "  --csharp    .NET 8 SDK"
            echo "  --c         MinGW cross-compiler"
            echo "  --check     Validate only, don't install"
            echo "  --ci        Non-interactive mode"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (try --help)"
            exit 1
            ;;
    esac
done

case "$ACTION" in
    python)
        install_python_deps
        ;;
    go)
        install_go
        install_garble
        ;;
    rust)
        install_rust
        ;;
    csharp)
        install_dotnet
        ;;
    c)
        install_mingw
        ;;
    all)
        install_python_deps
        install_go
        install_garble
        install_rust
        install_dotnet
        install_mingw
        generate_certs
        generate_keys
        install_cli
        smoke_test
        ;;
esac

# --- Summary ---

section "Summary"
echo ""

if $CHECK_ONLY; then
    echo -e "${BOLD}Validation Results${NC}"
else
    echo -e "${BOLD}Toolchain Status${NC}"
fi

echo ""
cmd_exists python3 && echo -e "  Python:      ${GREEN}✓${NC} $(python_version)" \
                   || echo -e "  Python:      ${RED}✗${NC}"
cmd_exists go      && echo -e "  Go:          ${GREEN}✓${NC} $(go version 2>/dev/null | awk '{print $3}')" \
                   || echo -e "  Go:          ${RED}✗${NC}"
cmd_exists rustc   && echo -e "  Rust:        ${GREEN}✓${NC} $(rustc --version 2>/dev/null | awk '{print $2}')" \
                   || echo -e "  Rust:        ${RED}✗${NC}"
cmd_exists dotnet  && echo -e "  .NET:        ${GREEN}✓${NC} $(dotnet --version 2>/dev/null)" \
                   || echo -e "  .NET:        ${RED}✗${NC}"
cmd_exists x86_64-w64-mingw32-gcc \
                   && echo -e "  MinGW:       ${GREEN}✓${NC}" \
                   || echo -e "  MinGW:       ${RED}✗${NC}"
[ -f "certs/server.pem" ] \
                   && echo -e "  TLS Cert:    ${GREEN}✓${NC}" \
                   || echo -e "  TLS Cert:    ${RED}✗${NC}"
[ -f "keys/server_x25519.bin" ] \
                   && echo -e "  X25519 Key:  ${GREEN}✓${NC}" \
                   || echo -e "  X25519 Key:  ${RED}✗${NC}"
cmd_exists sockpuppets \
                   && echo -e "  CLI Command: ${GREEN}✓${NC} $(which sockpuppets 2>/dev/null)" \
                   || echo -e "  CLI Command: ${RED}✗${NC}"

echo ""
if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}${ERRORS} error(s)${NC}, ${WARNINGS} warning(s) — see setup.log"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${GREEN}Done${NC} with ${YELLOW}${WARNINGS} warning(s)${NC}"
else
    echo -e "${GREEN}Done — all clear${NC}"
fi

if ! $CHECK_ONLY; then
    echo ""
    if cmd_exists sockpuppets; then
        echo "Run:"
        echo -e "  ${CYAN}sockpuppets${NC}               # Interactive CLI"
        echo -e "  ${CYAN}sockpuppets tui${NC}           # Terminal UI"
        echo -e "  ${CYAN}sockpuppets gui${NC}           # Web GUI on :13337"
        echo -e "  ${CYAN}sockpuppets help${NC}          # All commands"
    else
        echo "Activate the environment:"
        echo -e "  ${CYAN}source .venv/bin/activate${NC}"
        echo ""
        echo "Run:"
        echo -e "  ${CYAN}python main.py${NC}            # CLI"
        echo -e "  ${CYAN}python main.py --gui${NC}      # Web GUI on :13337"
        echo -e "  ${CYAN}python main.py --tui${NC}      # Terminal UI"
    fi
fi
echo ""
