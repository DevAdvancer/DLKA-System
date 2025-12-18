#!/bin/bash

echo "Checking Control Node Health..."
echo "========================================"

# 1. Check service status
echo "1. Service Status:"
sudo systemctl is-active attest-control && echo "  ✓ Running" || echo "  ✗ Not running"

# 2. Check port
echo "2. Port Status:"
sudo ss -tulpn | grep 5000 > /dev/null && echo "  ✓ Port 5000 listening" || echo "  ✗ Port not open"

# 3. Check API
echo "3. API Health:"
RESPONSE=$(curl -s http://localhost:5000/health)
echo "$RESPONSE" | grep -q "healthy" && echo "  ✓ API responding" || echo "  ✗ API not responding"

# 4. Check logs
echo "4. Recent Errors:"
ERROR_COUNT=$(sudo journalctl -u attest-control --since "10 minutes ago" | grep -c ERROR || echo 0)
echo "  Errors in last 10 min: $ERROR_COUNT"

# 5. Check baseline
echo "5. Baseline Status:"
[ -f "/home/devadvancer/MinorProject/control_node/data/baseline.json" ] && echo "  ✓ Baseline exists" || echo "  ⚠ No baseline"

echo "========================================"
echo "✓ Health check complete"
