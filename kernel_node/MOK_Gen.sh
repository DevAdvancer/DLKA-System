#!/bin/bash
# generate_keys.sh

mkdir -p keys
cd keys

# Generate private key
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.priv \
    -outform DER -out MOK.der -nodes -days 36500 \
    -subj "/CN=Attest LKM Signing Key/"

# Convert to PEM for viewing
openssl x509 -inform der -in MOK.der -out MOK.pem

echo "Keys generated in ./keys/"
echo "Enroll MOK.der into Secure Boot:"
echo "   sudo mokutil --import keys/MOK.der"
echo "   (Reboot and enroll via UEFI prompt)"
