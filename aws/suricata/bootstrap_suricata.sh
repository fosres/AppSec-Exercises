#!/usr/bin/env bash
# ============================================================
# Suricata IDS Lab — Bootstrap Script
# Run this inside a fresh lab-create instance to recreate
# the full Suricata lab setup from Week 9.
#
# Usage:
#   lab-connect (connect to fresh instance via SSM)
#   sudo bash bootstrap_suricata.sh
#
# What this does:
#   1. Installs Suricata 7.x from the official OISF PPA
#   2. Installs nginx as the HTTP target for SQLi tests
#   3. Installs nmap and dnsutils for testing rules
#   4. Configures suricata.yaml (HOME_NET, af-packet, rule-files)
#   5. Writes custom.rules with all 7 detection rules
#   6. Validates config and starts Suricata
#   7. Prints verification output
#
# Prerequisites:
#   - Debian 13 EC2 instance (lab-create)
#   - Outbound internet access (security group allows egress)
#   - Run as root (sudo)
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ── Must run as root ─────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"

# ── Detect network interface and subnet ──────────────────────
log "Detecting network interface..."
IFACE=$(ip route | awk '/default/ {print $5}' | head -1)
[[ -n "$IFACE" ]] || die "Could not detect network interface"

# Get the subnet in CIDR notation from the interface address
# e.g. inet 172.31.29.30/20 → calculate network address 172.31.16.0/20
IFACE_CIDR=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' | head -1)
[[ -n "$IFACE_CIDR" ]] || die "Could not detect IP for $IFACE"

SUBNET=$(python3 -c "
import ipaddress
net = ipaddress.IPv4Interface('$IFACE_CIDR').network
print(str(net))
")
[[ -n "$SUBNET" ]] || die "Could not calculate subnet from $IFACE_CIDR"

log "Interface: $IFACE"
log "Subnet (HOME_NET): $SUBNET"

# ── Install dependencies ──────────────────────────────────────
log "Updating package lists..."
apt-get update -y -q

log "Installing prerequisites..."
apt-get install -y -q \
	curl \
	wget \
	gnupg \
	lsb-release \
	nginx \
	nmap \
	dnsutils \
	tcpdump \
	python3

# ── Install Suricata from Debian backports ────────────────────
log "Installing Suricata..."
# Suricata is available directly in Debian trixie (13) repos
apt-get install -y -q suricata || die "Suricata install failed — check apt output above"

# ── Create custom rules directory ────────────────────────────
log "Creating rules directory..."
mkdir -p /etc/suricata/rules

# ── Write custom.rules ───────────────────────────────────────
log "Writing custom.rules..."
cat > /etc/suricata/rules/custom.rules << 'RULES'
# ============================================================
# Suricata Custom Rules — Week 9 Lab
# Pass rules must come FIRST — Suricata processes top to bottom
# ============================================================

# ── Pass rules (whitelist legitimate AWS traffic) ────────────
pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)

# ── Alert rules ──────────────────────────────────────────────
alert tcp any any -> $HOME_NET any (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
# alert tcp $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:2;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:2;)
RULES

log "custom.rules written (C2 rule commented out — re-enable after whitelisting all AWS endpoints)"

# ── Configure suricata.yaml ───────────────────────────────────
log "Configuring suricata.yaml..."

# Set HOME_NET to the detected subnet
sed -i "s|HOME_NET: \".*\"|HOME_NET: \"[$SUBNET]\"|" /etc/suricata/suricata.yaml

# Set af-packet to monitor both enX0/eth0 and lo
python3 - << PYEOF
import re

with open('/etc/suricata/suricata.yaml', 'r') as f:
	content = f.read()

# Replace af-packet interface section
iface = "$IFACE"
new_afpacket = f"""af-packet:
  - interface: {iface}
  - interface: lo
"""

content = re.sub(
	r'af-packet:.*?(?=\n\S|\Z)',
	new_afpacket,
	content,
	flags=re.DOTALL
)

with open('/etc/suricata/suricata.yaml', 'w') as f:
	f.write(content)

print("af-packet configured")
PYEOF

# Set rule-files to only load custom.rules
python3 - << PYEOF
import re

with open('/etc/suricata/suricata.yaml', 'r') as f:
	content = f.read()

content = re.sub(
	r'rule-files:.*?(?=\n\S|\Z)',
	'rule-files:\n  - /etc/suricata/rules/custom.rules\n',
	content,
	flags=re.DOTALL
)

with open('/etc/suricata/suricata.yaml', 'w') as f:
	f.write(content)

print("rule-files configured")
PYEOF

# ── Enable and start nginx ────────────────────────────────────
log "Starting nginx (HTTP target for SQLi tests)..."
systemctl enable nginx -q
systemctl start nginx

# ── Validate Suricata config ──────────────────────────────────
log "Validating Suricata configuration..."
suricata -T -c /etc/suricata/suricata.yaml -v 2>&1 | grep -E "Configuration|Error|Warning|rules" || true

# ── Start Suricata ────────────────────────────────────────────
log "Starting Suricata..."
systemctl enable suricata -q
systemctl restart suricata
sleep 5

# ── Verify ───────────────────────────────────────────────────
log "Verifying Suricata is running..."
systemctl is-active suricata || die "Suricata failed to start — check: journalctl -u suricata"

log "Checking rules loaded..."
sleep 3
SIGS=$(grep "signatures processed" /var/log/suricata/suricata.log | tail -1)
echo "  $SIGS"

# ── Print instance IP ─────────────────────────────────────────
INSTANCE_IP=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1)

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN} Suricata Lab Ready${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  Interface:    $IFACE"
echo "  HOME_NET:     $SUBNET"
echo "  Instance IP:  $INSTANCE_IP"
echo "  fast.log:     /var/log/suricata/fast.log"
echo "  custom.rules: /etc/suricata/rules/custom.rules"
echo ""
echo "  Test commands:"
echo ""
echo "  Rule 1 (SQLi UNION):"
echo "  curl -v -G \"http://$INSTANCE_IP/\" --data-urlencode \"id=1' UNION SELECT username,password FROM users--\""
echo ""
echo "  Rule 2 (SQLi OR):"
echo "  curl -v \"http://$INSTANCE_IP/?id=1%27%20OR%201%3D1--\""
echo ""
echo "  Rule 3 (Port scan):"
echo "  sudo nmap -sS --max-rate 10 $INSTANCE_IP"
echo ""
echo "  Rule 5 (DNS tunneling):"
echo "  dig \$(python3 -c \"print('A'*60 + '.' + 'B'*60 + '.' + 'C'*60)\").google.com @8.8.8.8"
echo ""
echo "  Watch alerts:"
echo "  sudo tail -f /var/log/suricata/fast.log"
echo ""
