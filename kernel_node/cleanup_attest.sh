#!/usr/bin/env bash
# Unload attest_lkm and delete all MOKs whose subject/issuer
# contains a given string (default: "Attest").

set -euo pipefail
MATCH="${1:-Attest}"

echo "── Unloading attest_lkm if present ─────────────"
if lsmod | grep -q "^attest_lkm"; then
        sudo rmmod attest_lkm && echo "  ✔ unloaded"
else
        echo "  (module not loaded)"
fi

echo "── Scheduling deletion of matching MOK keys ───"
to_del=$(mokutil --list-enrolled | awk "/$MATCH/ {print \$1}")
if [[ -z "$to_del" ]]; then
        echo "  No MOK keys contain \"$MATCH\""
        exit 0
fi

for h in $to_del; do
        echo "  → mokutil --delete $h"
        sudo mokutil --delete "$h"
done

echo "----------------------------------------------------------------"
echo "Keys scheduled.  Reboot now and, in the blue MokManager screen,"
echo "choose  'Delete MOK'  (or  'Reset MOK list'), select each key,"
echo "confirm with your one-time password, and reboot again."
echo "----------------------------------------------------------------"
