#!/bin/bash
set -e

echo "=== Auto-Recon Setup ==="
echo ""

# ── Rust ──
if ! command -v cargo &>/dev/null; then
    echo "[1/4] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "[1/4] Rust already installed"
fi

# ── Go ──
if ! command -v go &>/dev/null; then
    echo "[2/4] Installing Go..."
    GO_VERSION="1.23.6"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    # Persist
    grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> ~/.bashrc
else
    echo "[2/4] Go already installed"
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
fi

# ── Python tools ──
echo "[3/4] Installing Python tools..."
if ! command -v pipx &>/dev/null; then
    pip install pipx --break-system-packages 2>/dev/null || pip install pipx
    pipx ensurepath
fi
export PATH="$HOME/.local/bin:$PATH"

# BBOT
if ! command -v bbot &>/dev/null; then
    echo "  Installing bbot..."
    pipx install bbot
else
    echo "  bbot already installed"
fi

# linkfinder
if ! python3 -c "import linkfinder" 2>/dev/null; then
    echo "  Installing linkfinder..."
    pip install linkfinder --break-system-packages 2>/dev/null || pip install linkfinder
else
    echo "  linkfinder already installed"
fi

# ── Go tools ──
echo "[4/4] Installing Go recon tools..."
export PATH="$HOME/go/bin:$PATH"

TOOLS=(
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for tool in "${TOOLS[@]}"; do
    name=$(basename "${tool%%@*}")
    if ! command -v "$name" &>/dev/null; then
        echo "  Installing $name..."
        go install "$tool"
    else
        echo "  $name already installed"
    fi
done

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    echo "  Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || true
fi

# ── Build h1scout ──
echo ""
echo "=== Building h1scout ==="
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source "$HOME/.cargo/env"
cargo build --release

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Binary: $SCRIPT_DIR/target/release/h1scout"
echo ""
echo "Make sure your PATH includes:"
echo '  export PATH="$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:/usr/local/go/bin:$PATH"'
echo ""
echo "Next steps:"
echo "  export H1_USERNAME='your_username'"
echo "  export H1_API_TOKEN='your_token'"
echo "  ./target/release/h1scout fetch"
echo "  ./target/release/h1scout list --top 10"
echo "  ./target/release/h1scout select"
