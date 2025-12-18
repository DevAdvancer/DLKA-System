#!/bin/bash
# Complete setup for control node

set -e

INSTALL_DIR="$(pwd)"
echo "=========================================="
echo "Control Node Installation"
echo "=========================================="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
mkdir -p keys logs data

# Generate monitor keys
if [ ! -f "keys/monitor1.pub" ]; then
    echo "Generating monitor node keypairs..."
    python3 << 'EOF'
from crypto_utils import CryptoUtils
import os

for i in range(1, 4):
    priv, pub = CryptoUtils.generate_keypair()

    with open(f'keys/monitor{i}.priv', 'wb') as f:
        f.write(priv)

    with open(f'keys/monitor{i}.pub', 'wb') as f:
        f.write(pub)

    print(f"✓ Generated keypair for Monitor {i}")
EOF
fi

# Set permissions
chmod 600 keys/*.priv 2>/dev/null || true
chmod 644 keys/*.pub 2>/dev/null || true

echo ""
echo "=========================================="
echo "✓ Installation complete!"
echo "=========================================="
echo ""
echo "To start the control node:"
echo "  source venv/bin/activate"
echo "  python3 control_node.py"
echo ""
echo "For systemd service:"
echo "  sudo cp systemd/attest-control.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable attest-control"
echo "  sudo systemctl start attest-control"
echo ""
