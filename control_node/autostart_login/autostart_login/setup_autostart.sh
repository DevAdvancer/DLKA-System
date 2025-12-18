#!/bin/bash

set -e

INSTALL_DIR="/home/devadvancer/MinorProject/control_node"
SERVICE_NAME="attest-control"
USER="devadvancer"

echo "=================================================="
echo "Control Node Auto-Start Setup"
echo "=================================================="

# 1. Verify installation
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: Control node not found at $INSTALL_DIR"
    exit 1
fi

cd "$INSTALL_DIR"

# 2. Create virtual environment if needed
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# 3. Install dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 4. Create directories
mkdir -p logs data keys

# 5. Generate keys if needed
if [ ! -f "keys/monitor1.pub" ]; then
    echo "Generating monitor keypairs..."
    python3 << 'EOF'
from crypto_utils import CryptoUtils
for i in range(1, 4):
    priv, pub = CryptoUtils.generate_keypair()
    with open(f'keys/monitor{i}.priv', 'wb') as f:
        f.write(priv)
    with open(f'keys/monitor{i}.pub', 'wb') as f:
        f.write(pub)
    print(f"✓ Generated keypair for Monitor {i}")
EOF
fi

# 6. Set permissions
chmod 600 keys/*.priv
chmod 644 keys/*.pub
chmod +x control_node.py

# 7. Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << EOF
[Unit]
Description=Kernel Attestation Control Node
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
Group=${USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/control_node.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# 8. Enable and start service
echo "Enabling service..."
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}.service
sudo systemctl start ${SERVICE_NAME}.service

# 9. Wait and check status
sleep 3
sudo systemctl status ${SERVICE_NAME}.service --no-pager

echo ""
echo "=================================================="
echo "✓ Setup Complete!"
echo "=================================================="
echo ""
echo "Service Status:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo ""
echo "View Logs:"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Test API:"
echo "  curl http://localhost:5000/health"
echo ""
echo "Configuration:"
echo "  Edit: ${INSTALL_DIR}/config.yaml"
echo ""
