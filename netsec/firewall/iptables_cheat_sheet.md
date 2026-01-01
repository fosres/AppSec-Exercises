# Amazing Reference:

https://github.com/trimstray/iptables-essentials?tab=readme-ov-file#allow-incoming-ssh-from-specific-ip-address-or-subnet

# View rules
iptables -L -v -n

# Flush all rules (start clean)
iptables -F
iptables -X

# Allow established connections (ALWAYS FIRST!)
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow specific service
iptables -A FORWARD -d 10.0.1.0/24 -p tcp --dport 80 -j ACCEPT

# Drop invalid packets
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# Set default policy
iptables -P FORWARD DROP

# Save rules
iptables-save > rules.txt

# Logging (Challenge 1 requirement)
iptables -A FORWARD -p tcp --dport 22 -m limit --limit 5/min -j LOG --log-prefix "SSH-DENY: "
