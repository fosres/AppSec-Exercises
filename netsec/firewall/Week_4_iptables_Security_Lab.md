# Week 4: iptables Security Engineering Lab

**Candidate:** Tanveer Salim (fosres)

**Format:** Scenario-based challenges (SpaceX Interview Style)

**Sources:**
- Grace Nolan's Security Engineering Notes (github.com/gracenolan/Notes)
- SpaceX Product Security Interview Question 8
- Complete 48-Week Security Engineering Curriculum, Pages 13-14

**Time Limit:** 3 hours

**Rules:** 
- You may use man pages and online documentation
- Write complete, working iptables commands
- Explain your reasoning for each rule

---

# Scenario 1: Startup Web Application

You are the first Security Engineer at a startup. The engineering team has deployed their web application and asks you to configure the server's firewall.

## Network Diagram

```
                                    INTERNET
                                        │
                                        │
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    │                                       │
           ┌───────┴───────┐                       ┌───────┴───────┐
           │   Legitimate  │                       │   Attackers   │
           │     Users     │                       │  (anywhere)   │
           │               │                       │               │
           └───────┬───────┘                       └───────┬───────┘
                   │                                       │
                   │                                       │
                   └───────────────────┬───────────────────┘
                                       │
                                       │
                              ┌────────┴────────┐
                              │                 │
                              │   Web Server    │
                              │                 │
                              │  104.196.45.120 │
                              │                 │
                              │  Services:      │
                              │  - HTTPS (443)  │
                              │  - SSH (22)     │
                              │                 │
                              │  eth0 (public)  │
                              │                 │
                              └─────────────────┘
```

## Requirements

1. The web application must be accessible via HTTPS from anywhere on the internet
2. SSH must only be accessible from the CTO's home IP: `73.189.45.22`
3. The server must be able to resolve DNS to function properly
4. The server must be able to download security updates from Ubuntu repositories
5. Protect SSH from brute force attacks (max 4 attempts per minute)
6. Drop all other inbound traffic
7. Log dropped packets for security monitoring

## Your Task

Write a complete iptables firewall configuration for this server. Include comments explaining each rule.


My answer below:

```
iptables -P INPUT DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s 73.189.45.22 --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p tcp -s 73.189.45.22 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -s 73.189.45.22 --dport 22 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp  --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j LOG --log-prefix "LOG INPUT dropped"
iptables -A INPUT -j DROP
iptables -A OUTPUT -j LOG --log-prefix "LOG OUTPUT dropped"
iptables -A OUTPUT -j DROP
```


---

# Scenario 2: Corporate Network with DMZ

You've been hired as a Security Engineer at a mid-size company. They have a standard three-tier network architecture and need you to configure the firewall that sits between all three zones.

## Network Diagram

```
                                         INTERNET
                                             │
                                             │
                                    ┌────────┴────────┐
                                    │  ISP Router     │
                                    │  (not managed)  │
                                    └────────┬────────┘
                                             │
                                             │ 203.0.113.1 (gateway)
                                             │
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                     │
│                                      FIREWALL                                       │
│                                                                                     │
│     eth0 (WAN)                    eth1 (DMZ)                    eth2 (LAN)          │
│     203.0.113.10                  10.0.1.1                      10.0.0.1            │
│                                                                                     │
└─────────┬─────────────────────────────┬─────────────────────────────┬───────────────┘
          │                             │                             │
          │                             │                             │
          │                    ┌────────┴────────┐           ┌────────┴────────┐
          │                    │   DMZ Network   │           │   LAN Network   │
          │                    │   10.0.1.0/24   │           │   10.0.0.0/24   │
          │                    └────────┬────────┘           └────────┬────────┘
          │                             │                             │
          │               ┌─────────────┼─────────────┐               │
          │               │             │             │               │
          │        ┌──────┴──────┐ ┌────┴────┐ ┌──────┴──────┐ ┌──────┴──────┐
          │        │ Web Server  │ │  Mail   │ │ DNS Server  │ │ Employee    │
          │        │ 10.0.1.10   │ │ Server  │ │ 10.0.1.30   │ │ Workstations│
          │        │             │ │10.0.1.20│ │             │ │10.0.0.50-200│
          │        │ HTTPS: 443  │ │         │ │ DNS: 53     │ │             │
          │        │ HTTP: 80    │ │SMTP: 25 │ │             │ │             │
          │        └─────────────┘ │IMAPS:993│ └─────────────┘ └─────────────┘
          │                        └─────────┘
          │
          │
   ┌──────┴──────┐
   │ Admin VPN   │
   │ Endpoint    │
   │             │
   │ 198.51.100.50│
   │             │
   │ (needs SSH  │
   │  to all DMZ │
   │  servers)   │
   └─────────────┘
```

## Traffic Flow Requirements

| Source | Destination | Service | Port(s) | Allow? |
|--------|-------------|---------|---------|--------|
| Internet | Web Server | HTTPS | 443 | Yes |
| Internet | Web Server | HTTP | 80 | Yes (redirect to HTTPS) |
| Internet | Mail Server | SMTP | 25 | Yes |
| Internet | Mail Server | IMAPS | 993 | Yes |
| Internet | DNS Server | DNS | 53/udp, 53/tcp | Yes |
| Admin VPN (198.51.100.50) | All DMZ Servers | SSH | 22 | Yes |
| Employee Workstations | Internet | HTTP/HTTPS | 80, 443 | Yes |
| Employee Workstations | Internet | DNS | 53 | Yes |
| DMZ Servers | Internet | DNS | 53 | Yes (for updates) |
| DMZ Servers | Internet | HTTP/HTTPS | 80, 443 | Yes (for updates) |
| Any | Any | ICMP ping | - | Rate limited |
| Everything else | - | - | - | DROP and LOG |

## Security Requirements

1. **Brute Force Protection:** SSH must be protected against brute force (max 5 attempts per 60 seconds per source IP)
2. **Port Scan Detection:** Block packets with invalid TCP flag combinations (NULL, XMAS, SYN+FIN)
3. **SYN Flood Protection:** Rate limit incoming SYN packets to 50/second
4. **Connection Limits:** No single IP can have more than 50 concurrent connections to any server
5. **Logging:** All dropped traffic must be logged with appropriate prefixes
6. **NAT:** 
   - External users access DMZ services via the firewall's public IP (203.0.113.10)
   - Internal users and DMZ servers access internet via MASQUERADE

## Your Task

Write a complete iptables firewall configuration for this corporate network. This firewall handles traffic between all three zones.

```bash
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "LOG NULL"
iptables -A FORWARD -p tcp --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "LOG XMAS"
iptables -A FORWARD -p tcp --tcp-flags ALL ALL -j DROP
iptables -A FORWARD -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "LOG SYN+FIN"
iptables -A FORWARD -p tcp --tcp-flags ALL SYN,FIN -j DROP
# SYN Flood Protection
iptables -N syn_flood
iptables -A FORWARD -p tcp --syn -j syn_flood
iptables -A syn_flood -m limit --limit 50/s -j RETURN
iptables -A syn_flood -m limit --limit 50/s -j LOG --log-prefix "LOG SYN-Flood Attacks"
iptables -A syn_flood -j DROP

iptables -A FORWARD -p icmp -m limit --limit  50/s -j ACCEPT

iptables -A FORWARD -p icmp -m limit --limit 50/s -j LOG --log-prefix PING-DROP:
iptables -A FORWARD -p icmp -j DROP

iptables -A OUTPUT -p icmp -j ACCEPT
# Internet -> Web Server
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j LOG --log-prefix "Internet -> Web Server Conn Limit Exceeded"
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j LOG --log-prefix "Internet -> Web Server Conn Limit Exceeded"
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.10 --dport 443 -j ACCEPT
# Internet -> Mail Server SMTP
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.20 --dport 25 -j LOG --log-prefix "SMTP Mail Server Conn Limit Exceeded"
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.20 --dport 25 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.20 --dport 25 -j ACCEPT
# Internet -> Mail Server IMAPS
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.20 --dport 993 -j LOG --log-prefix "IMAPS Mail Server Conn Limit Exceeded"
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.20 --dport 993 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.20 --dport 993 -j ACCEPT
# DNS Server
##				DNS Server TCP
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j LOG --log-prefix "LOG Excessive DNS Request"
iptables -A FORWARD -p tcp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j ACCEPT
##				DNS Server UDP
iptables -A FORWARD -p udp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j LOG --log-prefix "LOG Excessive UDP DNS Requests"
iptables -A FORWARD -p udp -m connlimit --connlimit-above 50 -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j DROP
iptables -A FORWARD -p udp -i eth0 -o eth1 -d 10.0.1.30 --dport 53 -j ACCEPT

# SSH Brute-Force Detection for Admin VPN --> DMZ Servers

iptables -A FORWARD -p tcp -i eth0 -o eth1 -s 198.51.100.50 -d 10.0.1.0/24 --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A FORWARD -p tcp -i eth0 -o eth1 -s 198.51.100.50 -d 10.0.1.0/24 --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 6 -j LOG --log-prefix "SSH Hit-Count from Admin VPN to DMZ Servers Exceeded"
iptables -A FORWARD -p tcp -i eth0 -o eth1 -s 198.51.100.50 -d 10.0.1.0/24 --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 6 -j DROP
iptables -A FORWARD -p tcp -i eth0 -o eth1 -s 198.51.100.50 -d 10.0.1.0/24 --dport 22 -j ACCEPT

#Employee Workstations to HTTP/S

iptables -A FORWARD -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 50 -i eth2 -o eth0 -s 10.0.0.0/24 -j LOG --log-prefix "LOG Excessive Employee HTTP Requests"
iptables -A FORWARD -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 50 -i eth2 -o eth0 -s 10.0.0.0/24 -j DROP
iptables -A FORWARD -p tcp -m multiport --dports 80,443 -i eth2 -o eth0 -s 10.0.0.0/24 -j ACCEPT

#Employee Workstations to DNS (TCP)

iptables -A FORWARD -p tcp --dport 53 -m connlimit --connlimit-above 50 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j LOG --log-prefix "LOG Excessive Employee DNS Requests"
iptables -A FORWARD -p tcp --dport 53 -m connlimit --connlimit-above 50 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j DROP
iptables -A FORWARD -p tcp --dport 53 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j ACCEPT

#Employee Workstations to DNS (UDP)
iptables -A FORWARD -p udp --dport 53 -m connlimit --connlimit-above 50 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j LOG --log-prefix "LOG Excessive Employee DNS Requests"
iptables -A FORWARD -p udp --dport 53 -m connlimit --connlimit-above 50 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j DROP
iptables -A FORWARD -p udp --dport 53 -i eth2 -o eth1 -s 10.0.0.0/24 -d 10.0.1.30 -j ACCEPT

# External NAT: Users Access DMZ Through Firewall's Public IP

## DNAT to Web Server
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to-destination 10.0.1.10:80
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 10.0.1.10:443

## DNAT to Mail Server

iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25 -j DNAT --to-destination 10.0.1.20:25
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 993 -j DNAT --to-destination 10.0.1.20:993

## DNAT to DNS Server

iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j DNAT --to-destination 10.0.1.30:53
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j DNAT --to-destination 10.0.1.30:53

# Internal NAT: DMZ Accesses Internet 

iptables -t nat -A POSTROUTING -o eth0 -s 10.0.0.0/24 -j MASQUERADE

iptables -t nat -A POSTROUTING -o eth0 -s 10.0.1.0/24 -j MASQUERADE

#DMZ Servers to Internet (DNS (UDP): Port 53)

iptables -A FORWARD -p tcp --dport 53 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j LOG --log-prefix "LOG Excessive DMZ (UDP) DNS Requests"
iptables -A FORWARD -p tcp --dport 53 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j DROP
iptables -A FORWARD -p tcp --dport 53 -i eth1 -o eth0 -s 10.0.1.0/24 -j ACCEPT

#DMZ Servers to Internet (DNS (UDP): Port 53)

iptables -A FORWARD -p udp --dport 53 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j LOG --log-prefix "LOG Excessive DMZ (TCP) DNS Requests"
iptables -A FORWARD -p udp --dport 53 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j DROP
iptables -A FORWARD -p udp --dport 53 -i eth1 -o eth0 -s 10.0.1.0/24 -j ACCEPT

# DMZ Servers to HTTP/S
iptables -A FORWARD -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j LOG --log-prefix "LOG Excessive DMZ Servers HTTP Requests"
iptables -A FORWARD -p tcp -m multiport --dports 80,443 -m connlimit --connlimit-above 50 -i eth1 -o eth0 -s 10.0.1.0/24 -j DROP
iptables -A FORWARD -p tcp -m multiport --dports 80,443 -i eth1 -o eth0 -s 10.0.1.0/24 -j ACCEPT

# Allow All Traffic (ICMP Rate Limit)
iptables -A FORWARD -p icmp -m limit --limit 5/min --limit-burst 7 -j ACCEPT
#Log Traffic Exceeding ICMP Rate Limit
iptables -A FORWARD -p icmp -j LOG --log-prefix "LOG ICMP Traffic Exceeding Rate Limit"
iptables -A FORWARD -p icmp -j DROP

#Log All Other Dropped Traffic
iptables -A FORWARD -j LOG --log-prefix "Logging all other FORWARDED Traffic to be Dropped"
iptables -A FORWARD -j DROP




```

---

# Scenario 3: Incident Response - Compromised Server

You receive an alert at 2 AM. Your monitoring system detected the following from your web server:

1. 500+ failed SSH login attempts from `45.33.32.0/24` in the last hour
2. Unusual outbound connections to IP `185.234.72.10` on port `4444`
3. Large data transfer (50GB) to `91.121.87.0/24` over the past 4 hours
4. Port scan activity detected from `192.241.xx.xx` range

The server currently has this basic firewall:

```bash
# Current (insufficient) firewall
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

## Network Diagram

```
                                    INTERNET
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
            │                           │                           │
   ┌────────┴────────┐         ┌────────┴────────┐         ┌────────┴────────┐
   │  Brute Force    │         │   C2 Server     │         │  Data Exfil     │
   │  Attackers      │         │                 │         │  Destination    │
   │                 │         │ 185.234.72.10   │         │                 │
   │ 45.33.32.0/24   │         │ Port 4444       │         │ 91.121.87.0/24  │
   │                 │         │                 │         │                 │
   └────────┬────────┘         └────────┬────────┘         └────────┬────────┘
            │                           │                           │
            │                           │                           │
            └───────────────────────────┼───────────────────────────┘
                                        │
                                        │
                               ┌────────┴────────┐
                               │                 │
                               │  Compromised    │
                               │  Web Server     │
                               │                 │
                               │  104.196.45.120 │
                               │                 │
                               │  Legit Services:│
                               │  - HTTPS (443)  │
                               │  - SSH (22)     │
                               │                 │
                               └─────────────────┘
                               
                               
Legitimate Admin IP: 73.189.45.22
```

## Your Task

Write an emergency iptables configuration that:

1. **Immediately blocks** the known malicious IPs/ranges
2. **Stops data exfiltration** by restricting outbound traffic to only necessary services
3. **Prevents further brute force** with rate limiting
4. **Allows legitimate administration** from the admin IP only
5. **Maintains web service availability** for legitimate users
6. **Logs all suspicious activity** for forensic analysis

```bash
#!/bin/bash
# INCIDENT RESPONSE - Emergency Firewall
# Timestamp: 2025-01-08 02:00 UTC
# Reason: Active compromise detected

iptables -F
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

#Enable conntracking for INPUT and OUTPUT chains

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Ban Brute Force SSH Attackers

iptables -A INPUT -s 45.33.32.0/24 -p tcp --dport 22 -j LOG --log-prefix "Ban Brute Force SSH Attackers"
iptables -A INPUT -s 45.33.32.0/24 -p tcp --dport 22 -j DROP

# Ban Data Exfiltration

iptables -A OUTPUT -d 91.121.87.0/24 -j LOG --log-prefix "Ban Data Exfiltration"
iptables -A OUTPUT -d 91.121.87.0/24 -j DROP

# Ban Malicious Port Scanning

iptables -A INPUT -s 192.241.0.0/16 -j LOG --log-prefix "Ban Malicious Port Scanning"
iptables -A INPUT -s 192.241.0.0/16 -j DROP

# Ban Data Transfer to C2 Server

iptables -A OUTPUT -d 185.234.72.10 -j LOG --log-prefix "Ban All Traffic to C2 Server"
iptables -A OUTPUT -d 185.234.72.10 -j DROP

# First Allow Rate-Limited Admin SSH Attempts

iptables -A INPUT -s 73.189.45.22 -p tcp --dport 22 -m limit --limit 5/min --limit-burst 7 -j ACCEPT
iptables -A INPUT -s 73.189.45.22 -p tcp --dport 22 -j LOG --log-prefix "Admin IP Rate-Limit Exceeded"
iptables -A INPUT -s 73.189.45.22 -p tcp --dport 22 -j DROP

# Allow HTTP/S Traffic From Compromised Web Server to Internet (Needed for Software Updates)

iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow DNS Traffic From Compromised Web Server to Internet (Needed for Software Updates)

iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow HTTP/S Traffic From Internet to Compromised Web Server  (Needed for Clients)

iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow Loopback

iptables -A INPUT -i lo -j ACCEPT

iptables -A OUTPUT -o lo -j ACCEPT

# Now ban All Other INCOMING Traffic to Web Server

iptables -A INPUT -j LOG --log-prefix "Banning all other Inbound traffic"
iptables -A INPUT -j DROP

# Now ban All other Outbound

iptables -A OUTPUT -j LOG --log-prefix "Banning all other Outbound Traffic"
iptables -A OUTPUT -j DROP


```

---

# Scenario 4: Cloud NAT Gateway

Your company is migrating to the cloud. You need to configure a NAT gateway instance that allows private instances to access the internet while remaining protected.

## Network Diagram

```
                                         INTERNET
                                             │
                                             │
                                             │
                                    ┌────────┴────────┐
                                    │  Cloud Router   │
                                    │                 │
                                    └────────┬────────┘
                                             │
                                             │
                              ┌──────────────┴──────────────┐
                              │                             │
                              │      PUBLIC SUBNET          │
                              │      172.16.0.0/24          │
                              │                             │
                              │  ┌───────────────────────┐  │
                              │  │                       │  │
                              │  │     NAT Gateway       │  │
                              │  │                       │  │
                              │  │  eth0: 172.16.0.10    │  │
                              │  │  (public, has EIP)    │  │
                              │  │                       │  │
                              │  │  eth1: 172.16.1.1     │  │
                              │  │  (private subnet gw)  │  │
                              │  │                       │  │
                              │  └───────────┬───────────┘  │
                              │              │              │
                              └──────────────┼──────────────┘
                                             │
                              ┌──────────────┴──────────────┐
                              │                             │
                              │      PRIVATE SUBNET         │
                              │      172.16.1.0/24          │
                              │                             │
                              │  ┌─────────┐ ┌─────────┐    │
                              │  │ App     │ │ App     │    │
                              │  │ Server  │ │ Server  │    │
                              │  │ .10     │ │ .11     │    │
                              │  └─────────┘ └─────────┘    │
                              │                             │
                              │  ┌─────────┐ ┌─────────┐    │
                              │  │   DB    │ │  Cache  │    │
                              │  │ Server  │ │ Server  │    │
                              │  │ .20     │ │ .21     │    │
                              │  └─────────┘ └─────────┘    │
                              │                             │
                              └─────────────────────────────┘


Operations Team VPN: 10.8.0.0/24 (connects via VPN to 172.16.0.10)
```

#### Requirements

1. **Outbound NAT:** Private subnet instances must access internet via NAT gateway (CHECK)
2. **Restricted Egress:** Private instances can ONLY access: (CHECK)
   - DNS (53/udp, 53/tcp)
   - HTTP/HTTPS (80, 443) for package updates
   - NTP (123/udp) for time sync
3. **SSH Access:** Only Operations Team VPN (10.8.0.0/24) can SSH to the NAT gateway (CHECK)
4. **No Direct Inbound:** No internet-initiated connections to private subnet (CHECK)
5. **Logging:** Log any denied egress attempts (potential data exfiltration indicators) (CHECK)
6. **IP Forwarding:** Must be enabled for NAT to work (CHECK)

## Your Task

Write the complete NAT gateway firewall configuration.

```bash
#!/bin/bash
# Cloud NAT Gateway Firewall
# Public Interface: eth0 (172.16.0.10, has Elastic IP)
# Private Interface: eth1 (172.16.1.1)
# Private Subnet: 172.16.1.0/24

# Enable IP Forwarding
cat << EOF >> /etc/sysctl.d/40-custom.conf
net/ipv4/ip_forward = 1
EOF

#iptables Rules Start Here

iptables -F
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# Allow FORWARD chain conntracking

iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow loopback

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow Operations Team VPN Inside Subnet

iptables -A INPUT -p tcp -s 10.8.0.0/24 -d 172.16.0.10 --dport 22 -j ACCEPT

# NAT for Egress

iptables -t nat -A POSTROUTING -s 172.16.1.0/24 -o eth0 -j MASQUERADE

# Allow Private Subnet to Access HTTP/S

iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow Private Subnet to Access DNS

iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -p tcp --dport 53 -j ACCEPT
iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -p udp --dport 53 -j ACCEPT

# Allow Private Subnet to Access NTP
iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -p udp --dport 123 -j ACCEPT

# Deny All Other Egress Attempts by Private Subnet

iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -j LOG --log-prefix "Deny All Other Egress by Private Subnet"
iptables -A FORWARD -s 172.16.1.0/24 -o eth0 -j DROP

# Deny All Other Forwarding Traffic

iptables -A FORWARD -j DROP
```

---

# Scenario 5: SpaceX-Style Troubleshooting

The engineering team deployed a file server but the firewall is misconfigured. Users are reporting connectivity issues. Analyze the network and firewall rules to identify and fix all problems.

## Network Diagram

```
                                        INTERNET
                                            │
                                            │
                                   ┌────────┴────────┐
                                   │                 │
                                   │  Cloud Router   │
                                   │                 │
                                   └────────┬────────┘
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               │                                                         │
               │                                                         │
      ┌────────┴────────┐                                       ┌────────┴────────┐
      │                 │                                       │                 │
      │  Seattle Office │                                       │  Austin Office  │
      │  NAT Router     │                                       │  NAT Router     │
      │                 │                                       │                 │
      │  WAN: 52.12.45.100                                      │  WAN: 104.210.32.55
      │  LAN: 192.168.1.1                                       │  LAN: 192.168.1.1
      │                 │                                       │                 │
      └────────┬────────┘                                       └────────┬────────┘
               │                                                         │
               │                                                         │
      ┌────────┴────────┐                                       ┌────────┴────────┐
      │                 │                                       │                 │
      │  Developer      │                                       │  Developer      │
      │  Workstation    │                                       │  Workstation    │
      │                 │                                       │                 │
      │  192.168.1.50   │                                       │  192.168.1.75   │
      │                 │                                       │                 │
      │  Needs:         │                                       │  Needs:         │
      │  - HTTPS        │                                       │  - HTTPS        │
      │  - SSH          │                                       │  - SSH          │
      │                 │                                       │                 │
      └─────────────────┘                                       └─────────────────┘



                                   ┌─────────────────┐
                                   │                 │
                                   │   FILE SERVER   │
                                   │                 │
                                   │  20.141.12.34   │
                                   │                 │
                                   │  Services:      │
                                   │  - HTTPS (443)  │
                                   │  - SSH (22)     │
                                   │                 │
                                   └─────────────────┘
```

### Current File Server Firewall (BROKEN)

```bash
# Chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP  
iptables -P OUTPUT DROP

# Input rules
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -d 20.141.12.34 --dport 443 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.50 -d 20.141.12.34 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.1.75 -d 20.141.12.34 --dport 22 -j ACCEPT

# Output rules
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

## Reported Problems

1. **Seattle developer** can access HTTPS but cannot SSH to the server
2. **Austin developer** can access HTTPS but cannot SSH to the server  
3. **Neither developer** can ping the server
4. **Server** cannot download security updates
5. **Server** cannot resolve DNS names

## Your Task

### Part A: Root Cause Analysis

For each reported problem, explain the root cause:

````
Problem 1 (Seattle SSH fails):

# The File Server exists outside Seattle's LAN. So the source address `192.168.1.50` is
# meaningless to the File Server.

# So the below iptables rule:

```
iptables -A INPUT -p tcp -s 192.168.1.50 -d 20.141.12.34 --dport 22 -j ACCEPT
```

# Should be replaced with:

```
iptables -A INPUT -p tcp -s 52.12.45.100 -d 20.141.12.34 --dport 22 -j ACCEPT
```


# Problem 2 (Austin SSH fails):

# Similiar problem as Problem 1 the below iptables rule:

```
iptables -A INPUT -p tcp -s 192.168.1.75 -d 20.141.12.34 --dport 22 -j ACCEPT
```

# should be replaced with:

```
iptables -A INPUT -p tcp -s 104.210.32.55 -d 20.141.12.34 --dport 22 -j ACCEPT
```

# Problem 3 (Ping fails):

# The following iptables rules must be appended to the INPUT chain:

```
iptables -A INPUT -p icmp -s 104.210.32.55 -d 20.141.12.34 -j ACCEPT

iptables -A INPUT -p icmp -s 52.12.45.100 -d 20.141.12.34 -j ACCEPT
```


Problem 4 (No updates):

# The following iptables rule must be appended to the OUTPUT chain:

```
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
```


Problem 5 (DNS fails):

# The following iptables rules must be appended to the OUTPUT chain:

```
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
```

````

### Part B: Write the Fixed Firewall

Write a corrected firewall configuration that:
- Fixes all reported problems
- Allows HTTPS from anywhere
- Allows SSH from both office public IPs
- Allows ping (rate limited)
- Allows server to download updates and resolve DNS
- Logs dropped packets

```bash
#!/bin/bash
# Fixed File Server Firewall
# Server IP: 20.141.12.34

iptables -F

# Chain policies

iptables -P INPUT DROP
iptables -P FORWARD DROP  
iptables -P OUTPUT DROP

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow Loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow HTTPS from Anywhere
iptables -A INPUT -p tcp -d 20.141.12.34 --dport 443 -j ACCEPT

# Allow Seattle to SSH to File Server

iptables -A INPUT -p tcp -s 52.12.45.100 -d 20.141.12.34 --dport 22 -j ACCEPT

# Allow Austin Office to SSH to File Server

iptables -A INPUT -p tcp -s 104.210.32.55 -d 20.141.12.34 --dport 22 -j ACCEPT

# Allow PINGING to File Server

iptables -A INPUT -p icmp -d 20.141.12.34 -m limit --limit 5/min -j ACCEPT

iptables -A INPUT -p icmp -d 20.141.12.34 -j LOG --log-prefix "LOG Excessive PINGS"

iptables -A INPUT -p icmp -d 20.141.12.34 -j DROP

# Allow File Server to HTTP/S and DNS for Server Updates

iptables -A OUTPUT -s 20.141.12.34 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A OUTPUT -s 20.141.12.34 -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -s 20.141.12.34 -p udp --dport 53 -j ACCEPT

# Logging and DROPPING ALL OTHER PACKETS

iptables -A INPUT -j LOG --log-prefix "LOG All Other Inbound packets"
iptables -A INPUT -j DROP

iptables -A OUTPUT -j LOG --log-prefix "Log All Other Outbound packets"
iptables -A OUTPUT -j DROP




```

---

# Answer Key Reference

Do not look at this section until you have completed all scenarios.

When you submit your answers, I will grade them against these criteria:

## Grading Rubric

| Criterion | Points |
|-----------|--------|
| Correct chain selection (INPUT/OUTPUT/FORWARD) | 15 |
| Proper stateful rules (ESTABLISHED,RELATED first) | 15 |
| Correct NAT configuration (DNAT/SNAT/MASQUERADE) | 15 |
| Understanding of NAT IP translation | 15 |
| Brute force protection implementation | 10 |
| Port scan detection rules | 10 |
| Proper logging configuration | 5 |
| Complete solution (no missing rules) | 10 |
| Correct syntax | 5 |

**Total: 100 points**

**Passing Score: 85%**

---

## Submission

Complete all 5 scenarios and submit for grading.
