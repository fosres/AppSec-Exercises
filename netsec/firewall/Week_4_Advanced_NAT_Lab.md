# Week 4: Advanced NAT Practice Lab

**Candidate:** Tanveer Salim (fosres)

**Format:** Scenario-based challenges (SpaceX Interview Style)

**Sources:**
- Grace Nolan's Security Engineering Notes (github.com/gracenolan/Notes)
- SpaceX Product Security Interview Question 8
- Complete 48-Week Security Engineering Curriculum, Pages 13-14

**Time Limit:** 2 hours

**Difficulty:** Harder than Scenario 4

**Rules:** 
- You may use man pages and online documentation
- Write complete, working iptables commands
- Explain your reasoning for each rule

---

# Scenario A: Multi-Tier Application with Bastion Host

Your company runs a production application in AWS. Security policy requires all administrative access go through a bastion (jump) host. You're configuring the bastion's firewall.

## Network Diagram

```
                                        INTERNET
                                            │
                                            │
               ┌────────────────────────────┴────────────────────────────┐
               │                                                         │
               │                                                         │
      ┌────────┴────────┐                                               │
      │                 │                                               │
      │  Security Team  │                                               │
      │  Office NAT     │                                               │
      │                 │                                               │
      │  WAN: 198.51.100.10                                             │
      │  LAN: 10.50.0.1 │                                               │
      │                 │                                               │
      └────────┬────────┘                                               │
               │                                                         │
      ┌────────┴────────┐                                               │
      │  Security       │                                               │
      │  Engineers      │                                               │
      │                 │                                               │
      │  10.50.0.20-30  │                                               │
      │                 │                                               │
      │  Needs SSH to:  │                                               │
      │  - Bastion      │                                               │
      │  - App servers  │                                               │
      │    (via bastion)│                                               │
      └─────────────────┘                                               │
                                                                        │
                                                                        │
                              ┌─────────────────────────────────────────┘
                              │
                              │
                     ┌────────┴────────┐
                     │   AWS VPC       │
                     │   10.0.0.0/16   │
                     │                 │
                     └────────┬────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         │                    │                    │
┌────────┴────────┐  ┌────────┴────────┐  ┌───────┴─────────┐
│ PUBLIC SUBNET   │  │ PRIVATE SUBNET  │  │ DATABASE SUBNET │
│ 10.0.1.0/24     │  │ 10.0.2.0/24     │  │ 10.0.3.0/24     │
│                 │  │                 │  │                 │
│ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │   BASTION   │ │  │ │  App Server │ │  │ │  Database   │ │
│ │             │ │  │ │  #1         │ │  │ │  Primary    │ │
│ │ eth0:       │ │  │ │             │ │  │ │             │ │
│ │ 10.0.1.10   │ │  │ │ 10.0.2.10   │ │  │ │ 10.0.3.10   │ │
│ │ (has EIP:   │ │  │ │             │ │  │ │             │ │
│ │ 54.23.45.67)│ │  │ └─────────────┘ │  │ └─────────────┘ │
│ │             │ │  │                 │  │                 │
│ │ eth1:       │ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │
│ │ 10.0.2.1    │ │  │ │  App Server │ │  │ │  Database   │ │
│ │ (private    │ │  │ │  #2         │ │  │ │  Replica    │ │
│ │  subnet gw) │ │  │ │             │ │  │ │             │ │
│ │             │ │  │ │ 10.0.2.11   │ │  │ │ 10.0.3.11   │ │
│ └─────────────┘ │  │ │             │ │  │ │             │ │
│                 │  │ └─────────────┘ │  │ └─────────────┘ │
└─────────────────┘  └─────────────────┘  └─────────────────┘

Traffic Flows:
- Security Team SSHs to Bastion (via NAT router WAN IP)
- Bastion SSHs to App Servers (internal)
- App Servers need outbound HTTP/HTTPS/DNS (via Bastion NAT)
- App Servers connect to Database (internal, no NAT)
- Database has NO internet access (strict isolation)
```

## Requirements

1. **External SSH to Bastion:**
   - Only Security Team office (public IP: 198.51.100.10) can SSH to Bastion
   - Rate limit: 3 attempts per minute (strict security)
   - Log all SSH attempts (successful and blocked)

2. **Bastion to Internal SSH:**
   - Bastion can SSH to App Servers (10.0.2.0/24) only
   - Bastion CANNOT SSH to Database subnet (10.0.3.0/24) — separation of duties
   - DBA team has separate access path (not your concern)

3. **NAT Gateway Function:**
   - App Servers access internet via Bastion (MASQUERADE)
   - Restricted egress: DNS (53), HTTP (80), HTTPS (443) only
   - Log denied egress attempts

4. **Database Isolation:**
   - NO traffic from Bastion to Database subnet
   - NO traffic from Database subnet through Bastion
   - This is enforced at Bastion level as defense-in-depth

5. **Port Scan Detection:**
   - Detect and log NULL, XMAS, SYN+FIN scans on external interface
   - Drop invalid packets

6. **Brute Force Protection:**
   - Claude, we agreed to keep this exercise simple and rate limit for up to 3 conns/min for External SSH to Bastion

## Your Task

Write the complete Bastion host firewall configuration.

```bash
#!/bin/bash
# Bastion Host Firewall
# Public Interface: eth0 (10.0.1.10, EIP: 54.23.45.67)
# Private Interface: eth1 (10.0.2.1)
# App Subnet: 10.0.2.0/24
# Database Subnet: 10.0.3.0/24 (BLOCKED)

# Enable IP Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Your rules here:

iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# Forward, Input and Output Connection Tracking for Bastion

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow Loopback Interface for Bastion

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Log and Drop - NULL, XMAS, SYN+FIN scans on external interface

## Log and Drop NULL packets
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "LOG NULL packets"
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL NONE -j DROP

## Log and Drop XMAS packets

iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "LOG XMAS Packets"
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL ALL -j DROP

## Log and Drop SYN+FIN Packets

iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "LOG SYN+FIN Packets"
iptables -A INPUT -i eth0 -p tcp --tcp-flags ALL SYN,FIN -j DROP

## Log and Drop Invalid Packets

iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j LOG --log-prefix "LOG Invalid"
iptables -A INPUT -i eth0 -m conntrack --ctstate INVALID -j DROP

# NAT POSTROUTING MASQUERADING App Servers to Access Internet

iptables -t nat -A POSTROUTING -s 10.0.2.0/24 -o eth0 -j MASQUERADE

# Ban Traffic from Database via Bastion

iptables -A FORWARD -s 10.0.3.0/24 -j LOG --log-prefix "LOG Banned Traffic from Database via Bastion"
iptables -A FORWARD -s 10.0.3.0/24 -j DROP

# App Servers Access Internet (Ports 80,443,53)

iptables -A FORWARD -i eth1 -o eth0 -p tcp -s 10.0.2.0/24 -m multiport --dports 80,443 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -p tcp -s 10.0.2.0/24 --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -p udp -s 10.0.2.0/24 --dport 53 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -j LOG --log-prefix "LOG Denied Egress"
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.2.0/24 -j DROP

# External SSH to Bastion

iptables -A INPUT -i eth0 -s 198.51.100.10 -d 10.0.1.0/24 -p tcp --dport 22 -m limit --limit 3/min -j LOG --log-prefix "LOG successful External SSH to Bastion"
iptables -A INPUT -i eth0 -s 198.51.100.10 -d 10.0.1.0/24 -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT
iptables -A INPUT -i eth0 -s 198.51.100.10 -d 10.0.1.0/24 -p tcp --dport 22 -j LOG --log-prefix "LOG blocked External SSH to Bastion"
iptables -A INPUT -i eth0 -s 198.51.100.10 -d 10.0.1.0/24 -p tcp --dport 22 -j DROP

# Bastion to Internal SSH

iptables -A OUTPUT -p tcp -s 10.0.1.0/24 -d 10.0.2.0/24 --dport 22 -j ACCEPT

# Ban Traffic from Bastion to Database Subnet

iptables -A OUTPUT -s 10.0.1.0/24 -d 10.0.3.0/24 -j DROP

# Ban All Other Input Traffic (Implied by Default Policy Drops so need to be explicit below)

# iptables -A INPUT -j DROP

# Ban All Other Outbound Traffic

# iptables -A OUTPUT -j DROP

# Ban All Other FORWARD Traffic

# iptables -A FORWARD -j DROP

```

---

# Scenario B: Kubernetes Node with Pod Networking (Simplified)

You're a Security Engineer at a startup using Kubernetes. The platform team asks you to understand and secure the iptables rules on a worker node. Container networking uses NAT for pod-to-external communication.

## Network Diagram

```
                                        INTERNET
                                            │
                                            │
                                   ┌────────┴────────┐
                                   │  Cloud Gateway  │
                                   │  (default route)│
                                   └────────┬────────┘
                                            │
                                            │
                              ┌─────────────┴─────────────┐
                              │                           │
                              │    KUBERNETES CLUSTER     │
                              │    Node Network:          │
                              │    192.168.100.0/24       │
                              │                           │
                              └─────────────┬─────────────┘
                                            │
                   ┌────────────────────────┼────────────────────────┐
                   │                        │                        │
          ┌────────┴────────┐      ┌────────┴────────┐      ┌────────┴────────┐
          │  WORKER NODE 1  │      │  WORKER NODE 2  │      │   MASTER NODE   │
          │                 │      │  (your focus)   │      │                 │
          │ 192.168.100.10  │      │ 192.168.100.20  │      │ 192.168.100.5   │
          │                 │      │                 │      │                 │
          └─────────────────┘      └────────┬────────┘      └─────────────────┘
                                            │
                                   ┌────────┴────────┐
                                   │  WORKER NODE 2  │
                                   │                 │
                                   │  eth0:          │
                                   │  192.168.100.20 │
                                   │  (node IP)      │
                                   │                 │
                                   │  docker0:       │
                                   │  172.17.0.1     │
                                   │  (bridge)       │
                                   │                 │
                                   └────────┬────────┘
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    │                       │                       │
           ┌────────┴────────┐     ┌────────┴────────┐     ┌────────┴────────┐
           │     POD A       │     │     POD B       │     │     POD C       │
           │   (frontend)    │     │   (backend)     │     │   (worker)      │
           │                 │     │                 │     │                 │
           │  172.17.0.10    │     │  172.17.0.11    │     │  172.17.0.12    │
           │                 │     │                 │     │                 │
           │  Needs:         │     │  Needs:         │     │  Needs:         │
           │  - Serve HTTP   │     │  - Connect to   │     │  - Pull from    │
           │    externally   │     │    external API │     │    S3 (HTTPS)   │
           │  - Port 8080    │     │  - HTTPS only   │     │  - No inbound   │
           │                 │     │                 │     │                 │
           └─────────────────┘     └─────────────────┘     └─────────────────┘


Port Publishing (configured by Kubernetes):
- Node:30080 → Pod A:8080 (NodePort service for frontend)

Traffic Flows:
- External users: Internet → Node:30080 → Pod A:8080
- Pod B: 172.17.0.11 → MASQUERADE → External API (HTTPS)
- Pod C: 172.17.0.12 → MASQUERADE → S3 (HTTPS)
- Pod-to-Pod: 172.17.0.x → 172.17.0.y (local, no NAT)
```

## Current Broken Firewall

The previous engineer left this incomplete configuration:

```bash
# Policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Some rules exist
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# NodePort - but something is wrong
iptables -t nat -A PREROUTING -p tcp --dport 30080 -j DNAT --to-destination 172.17.0.10:8080
iptables -A FORWARD -p tcp -d 172.17.0.10 --dport 8080 -j ACCEPT

# Pods can't reach the internet - missing rules
```

## Reported Problems

1. **External users** can't reach the frontend (Node:30080)
2. **Pod B** can't connect to external APIs (HTTPS)
3. **Pod C** can't pull from S3 (HTTPS)
4. **Cluster admins** can't SSH to the node from Master (192.168.100.5)
5. **Kubelet** health checks are failing (Master → Node:10250)
6. **Pods** can communicate with each other, but it's SLOW (hint: check conntrack)

## Requirements for Fixed Firewall

1. **NodePort Service:**
   - External traffic to Node:30080 must reach Pod A:8080
   - DNAT in PREROUTING
   - FORWARD rules to allow the traffic
   - Return traffic handled by conntrack

2. **Pod Egress:**
   - Pods (172.17.0.0/24) can access external HTTPS (443) only
   - Pods can access external DNS (53)
   - MASQUERADE for pod traffic leaving the node
   - Log other egress attempts (potential container escape/exfil)

3. **Cluster Communication:**
   - Master (192.168.100.5) can SSH to node (port 22)
   - Master can reach Kubelet API (port 10250)
   - Other nodes can reach this node on pod network

4. **Pod-to-Pod (Local):**
   - Traffic on docker0 bridge should be allowed without NAT
   - Don't MASQUERADE local traffic

5. **Security:**
   - No direct inbound to pod IPs from outside (only via NodePort)
   - Rate limit SSH to node
   - Log dropped packets

## Your Task

### Part A: Root Cause Analysis

Explain why each problem occurs with the current broken firewall:

```
Problem 1 (NodePort unreachable):


Problem 2 (Pod B can't reach external HTTPS):


Problem 3 (Pod C can't pull from S3):


Problem 4 (Can't SSH from Master):


Problem 5 (Kubelet health checks fail):


Problem 6 (Slow pod-to-pod - hint):

```

### Part B: Write the Fixed Firewall

```bash
#!/bin/bash
# Kubernetes Worker Node Firewall
# Node IP: 192.168.100.20
# Pod Network: 172.17.0.0/24
# Docker Bridge: docker0 (172.17.0.1)
# Master Node: 192.168.100.5

# Your rules here:


```

---

# Grading Rubric

## Scenario A: Bastion Host (50 points)

| Criterion | Points |
|-----------|--------|
| Correct INPUT rules for external SSH | 8 |
| SSH rate limiting with logging | 7 |
| OUTPUT rules for Bastion → App Servers SSH | 5 |
| FORWARD rules for App Server egress | 8 |
| MASQUERADE for App Servers | 5 |
| Database subnet isolation (explicit DENY) | 7 |
| Port scan detection | 5 |
| Loopback and stateful rules | 3 |
| Correct interface usage (-i/-o) | 2 |

## Scenario B: Kubernetes Node (50 points)

| Criterion | Points |
|-----------|--------|
| Root cause analysis (6 problems) | 12 |
| NodePort DNAT + FORWARD rules | 8 |
| Pod egress MASQUERADE (excluding local) | 8 |
| Cluster communication (SSH, Kubelet) | 7 |
| Pod-to-Pod local traffic (docker0) | 5 |
| Logging and rate limiting | 5 |
| Correct NAT table usage | 5 |

**Total: 100 points**

**Passing Score: 85%**

---

## Hints (Only Look If Stuck)

<details>
<summary>Scenario A Hint 1: Database Isolation</summary>

Place explicit DROP rules BEFORE any ACCEPT rules:
```bash
iptables -A FORWARD -d 10.0.3.0/24 -j LOG --log-prefix "DB_ACCESS_DENIED: "
iptables -A FORWARD -d 10.0.3.0/24 -j DROP
```

</details>

<details>
<summary>Scenario A Hint 2: Bastion SSH to App Servers</summary>

Bastion initiating SSH is OUTPUT (from bastion), not FORWARD. FORWARD is for traffic passing through.
```bash
iptables -A OUTPUT -p tcp -d 10.0.2.0/24 --dport 22 -j ACCEPT
```

</details>

<details>
<summary>Scenario B Hint 1: NodePort Not Working</summary>

DNAT changes the destination, but you also need:
1. FORWARD rule to accept traffic to the NEW destination
2. The FORWARD rule must match post-DNAT destination (172.17.0.10), not original (node IP)
3. Check if return traffic can get out (conntrack on FORWARD)

</details>

<details>
<summary>Scenario B Hint 2: MASQUERADE Excluding Local</summary>

Don't MASQUERADE traffic staying on the node:
```bash
# Only MASQUERADE traffic leaving via eth0, not docker0
iptables -t nat -A POSTROUTING -s 172.17.0.0/24 -o eth0 -j MASQUERADE
```

</details>

<details>
<summary>Scenario B Hint 3: Slow Pod-to-Pod</summary>

If pod-to-pod traffic is being MASQUERADED unnecessarily, conntrack has to track every local connection, adding latency. Ensure MASQUERADE only applies to `-o eth0`, not `-o docker0`.

</details>
