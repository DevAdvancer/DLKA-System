#!/bin/bash
# install.sh - Auto-load module on boot

MODULE_NAME="attest_lkm"
MODULE_PATH="$(pwd)/attest_lkm.ko"
SYSTEMD_SERVICE="/etc/systemd/system/attest-lkm.service"

echo "Installing $MODULE_NAME to auto-start on boot..."

# Copy module to /lib/modules
sudo mkdir -p /lib/modules/6.14.0-63.fc42.x86_64/extra
sudo cp "$MODULE_PATH" /lib/modules/$(uname -r)/extra/
sudo depmod -a

# Add to /etc/modules-load.d/
echo "$MODULE_NAME" | sudo tee /etc/modules-load.d/attest-lkm.conf

# Create systemd service
cat <<EOF | sudo tee $SYSTEMD_SERVICE
[Unit]
Description=Kernel Attestation Module
DefaultDependencies=no
Before=sysinit.target

[Service]
Type=oneshot
ExecStart=/sbin/modprobe $MODULE_NAME
ExecStop=/sbin/rmmod $MODULE_NAME
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable attest-lkm.service

echo "Installation complete!"
echo "Module will load on next boot."
echo "To start now: sudo systemctl start attest-lkm"
