# Packet Tracing Quiz

**Purpose:** Test your ability to trace packets through networks with NAT, routers, and firewalls.

**Format:** For each scenario, identify the source and destination IP at each hop.

**Time:** 30 minutes

**Passing Score:** 85%

---

# Section A: Outbound NAT (MASQUERADE/SNAT)

## Question 1

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Client   │         │ NAT Router │         │ Web Server │
│            ├────────►│            ├────────►│            │
│ 10.0.0.50  │         │ WAN: 203.0.113.5     │ 93.184.216.34
└────────────┘         │ LAN: 10.0.0.1│       └────────────┘
                       └────────────┘
```

Client sends HTTP request to Web Server.

**At Point A (Client → NAT Router):**
- Source IP: 10.0.0.50
- Destination IP: 93.184.216.34

**At Point B (NAT Router → Web Server):**
- Source IP: 203.0.113.5
- Destination IP: 93.184.216.34

---

## Question 2

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Workstation│         │ NAT Router │         │   Router   │         │   Server   │
│            ├────────►│            ├────────►│            ├────────►│            │
│192.168.1.100        │ WAN: 74.125.1.1      │            │         │ 8.8.8.8    │
└────────────┘         │ LAN: 192.168.1.1    │ 74.125.1.254         └────────────┘
                       └────────────┘         └────────────┘
```

Workstation sends DNS query to 8.8.8.8.

**At Point A (Workstation → NAT Router):**
- Source IP: 192.168.1.100
- Destination IP: 8.8.8.8

**At Point B (NAT Router → Router):**
- Source IP: 74.125.1.1
- Destination IP: 8.8.8.8

**At Point C (Router → Server):**
- Source IP: 74.125.1.1
- Destination IP: 8.8.8.8

---

## Question 3

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│  Laptop    │         │ Home NAT   │         │  ISP NAT   │         │   Server   │
│            ├────────►│            ├────────►│  (CGNAT)   ├────────►│            │
│192.168.0.25│         │ WAN: 100.64.1.50    │ WAN: 52.1.2.3        │ 151.101.1.69
└────────────┘         │ LAN: 192.168.0.1    │ LAN: 100.64.0.1      └────────────┘
                       └────────────┘         └────────────┘
```

Laptop connects to Server (Double NAT / Carrier-Grade NAT scenario).

**At Point A (Laptop → Home NAT):**
- Source IP: 192.168.0.25
- Destination IP: 151.101.1.69

**At Point B (Home NAT → ISP NAT):**
- Source IP: 100.64.1.50
- Destination IP: 151.101.1.69

**At Point C (ISP NAT → Server):**
- Source IP: 52.1.2.3
- Destination IP: 151.101.1.69

**What source IP does the Server see?** 52.1.2.3

---

# Section B: Inbound NAT (DNAT / Port Forwarding)

## Question 4

```
                       ┌────────────┐
                       │ NAT Router │
┌────────────┐         │            │         ┌────────────┐
│  Internet  ├────────►│ WAN: 203.0.113.10   │ Web Server │
│   Client   │         │ LAN: 10.0.0.1├─────►│            │
│ 72.45.67.89│         │            │         │ 10.0.0.100 │
└────────────┘         │ DNAT:      │         └────────────┘
                       │ 80→10.0.0.100:80
                       └────────────┘
```

Internet Client connects to http://203.0.113.10 (port 80).

**At Point A (Client → NAT Router WAN):**
- Source IP: 72.45.67.89
- Destination IP: 203.0.113.10

**At Point B (NAT Router → Web Server):**
- Source IP: 72.45.67.89
- Destination IP: 10.0.0.100

**What source IP does the Web Server see?** 72.45.67.89

---

## Question 5

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│  Attacker  │         │   Router   │         │  Firewall  │         │ SSH Server │
│            ├────────►│            ├────────►│  (NAT)     ├────────►│            │
│ 45.33.32.1 │         │            │         │ WAN: 104.44.1.1      │ 10.0.0.50  │
└────────────┘         │ 45.33.32.254         │ DNAT: 22→10.0.0.50:22│            │
                       └────────────┘         └────────────┘         └────────────┘
```

Attacker attempts SSH to 104.44.1.1.

**At Point A (Attacker → Router):**
- Source IP: 45.33.32.1
- Destination IP: 104.44.1.1

**At Point B (Router → Firewall):**
- Source IP: 45.33.32.1
- Destination IP: 104.44.1.1

**At Point C (Firewall → SSH Server):**
- Source IP: 45.33.32.1
- Destination IP: 10.0.0.50

**If SSH Server has firewall rule: `-s 45.33.32.254 --dport 22 -j DROP`**
**Will this block the attacker?** No **Why?** Wrong Source IP address: it blocks the Router instead!

---

# Section C: Mixed Scenarios (SpaceX Style)

## Question 6

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Developer  │         │ Office NAT │         │   Router   │         │ File Server│
│            ├────────►│            ├────────►│            ├────────►│            │
│192.168.1.50│         │ WAN: 198.51.100.10  │            │         │ 20.0.0.100 │
└────────────┘         │ LAN: 192.168.1.1    │ 198.51.100.254       └────────────┘
                       └────────────┘         └────────────┘
```

File Server has this iptables rule:
```
iptables -A INPUT -s 192.168.1.50 --dport 22 -j ACCEPT
```

Developer-->Office NAT

Source IP: 192.168.1.50

Destination IP: 20.0.0.100



Office NAT -->Router

Source IP: 198.51.100.10

Destination IP: 20.0.0.100



Router --> File Server

Source IP: 198.51.100.10

Destination IP: 20.0.0.100



**Will the Developer be able to SSH to the File Server?** NO

**What source IP does the File Server actually see?** 198.51.100.10

**Write the corrected iptables rule:** 

```
iptables -A INPUT -s 198.51.100.10 --dport 22 -j ACCEPT
```



---

## Question 7

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Admin    │         │  VPN GW    │         │   Server   │
│            ├─────────┤            ├────────►│            │
│ 10.8.0.50  │ VPN     │ 10.8.0.1   │         │ 172.16.0.10│
│(VPN tunnel)│         │ 172.16.0.1 │         │            │
└────────────┘         └────────────┘         └────────────┘

Admin is connected via VPN. VPN Gateway does NOT NAT internal traffic.
```

Admin SSHs to Server (172.16.0.10).



Admin-->VPN GW

Source IP: 10.8.0.50

Destination IP: 172.16.0.10



VPN GW-->Server

Source IP: 10.8.0.50

Destination IP: 172.16.0.10

**What source IP does the Server see?** 10.8.0.50

**Server has firewall rule:**
```
iptables -A INPUT -s 10.8.0.0/24 --dport 22 -j ACCEPT
```

10.8.0.0/24 --> Range of IPs: (10.8.0.1 - 10.8.0.254)

**Will Admin be allowed to SSH?** YES

---

## Question 8

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Seattle    │         │ Seattle    │         │            │         │            │
│ Developer  ├────────►│ NAT Router ├────────►│  Internet  ├────────►│ Cloud LB   │
│192.168.1.75│         │ WAN: 52.12.1.1      │            │         │ 35.200.1.1 │
└────────────┘         └────────────┘         │            │         └─────┬──────┘
                                              │            │               │ DNAT to Backend!
┌────────────┐         ┌────────────┐         │            │         ┌─────▼──────┐
│ Austin     │         │ Austin     │         │            │         │ Backend    │
│ Developer  ├────────►│ NAT Router ├────────►│            │         │ Server     │
│192.168.1.75│         │ WAN: 104.210.1.1    │            │         │ 10.0.0.50  │
└────────────┘         └────────────┘         └────────────┘         └────────────┘

Note: Both developers have the SAME private IP (192.168.1.75) - different offices.
Cloud Load Balancer DNATs to Backend Server.
```



Seattle Developer --> Seattle NAT Router				Austin Developer-->Austin NAT Router

Source IP: 192.168.1.75											Source IP: 192.168.1.75

Destination IP: 35.200.1.1										 Destination IP: 35.200.1.1

Seattle NAT Router-->Cloud LB					Austin NAT Router-->Cloud LB

Source IP: 52.12.1.1										Source IP: 104.210.1.1

Destination IP: 35.200.1.1							  Destination IP: 35.200.1.1 

(Seattle )Cloud LB-->Backend Server		(Austin) Cloud LB-->Backend Server

Source IP: 52.12.1.1									Source IP: 104.210.1.1

Destination IP: 10.0.0.50							Destination IP: 10.0.0.50



Backend Server has this firewall rule:

```
iptables -A INPUT -s 192.168.1.75 --dport 443 -j ACCEPT
```

**Will Seattle Developer connect?** NO

**Will Austin Developer connect?** NO

**What two source IPs does Backend Server actually see?**
- Seattle: 52.12.1.1
- Austin: 104.210.1.1

**Write corrected firewall rule to allow both offices:**

```
iptables -A INPUT -s 52.12.1.1 --dport 443 -j ACCEPT
iptables -A INPUT -s 104.210.1.1 --dport 443 -j ACCEPT
```



__________

---

## Question 9

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│ App Server │         │ NAT Gateway│         │ External   │
│            ├────────►│            ├────────►│ API        │
│ 10.0.2.50  │         │ priv: 10.0.2.1      │ 151.101.1.1│
└────────────┘         │ pub: 54.23.45.67    └────────────┘
                       └────────────┘
```

App Server makes HTTPS request to External API.



App Server-->NAT Gateway

Source IP: 10.0.2.50

Destination IP: 151.101.1.1

NAT Gateway-->External API

Source IP: 54.23.45.67

Destination IP: 151.101.1.1

**What source IP does External API see?** 54.23.45.67

**External API has allowlist:**
```
Allowed IPs: 54.23.45.67, 54.23.45.68
```

**Will the request succeed?** YES

---

## Question 10

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│ Malicious  │         │   Router   │         │  Firewall  │         │ Web Server │
│ Scanner    ├────────►│    (no NAT)├────────►│   (NAT)    ├────────►│            │
│ 45.33.32.1 │         │            │         │ WAN: 104.44.1.1      │ 10.0.0.80  │
└────────────┘         │ 45.33.32.254         │ DNAT: 443→10.0.0.80  │            │
                       └────────────┘         └────────────┘         └────────────┘

Web Server has this firewall rule to block the scanner:
iptables -A INPUT -s 45.33.32.254 -j DROP
```



Scanner-->Router (no NAT)

Source IP: 45.33.32.1

Destination IP: 104.44.1.1

Router (no NAT) --> Firewall (NAT)

Source IP: 45.33.32.1

Destination IP: 104.44.1.1

Firewall (NAT) --> Web Server

Source IP: 45.33.32.1

Destination IP: 10.0.0.80

**Will this rule block the scanner?** NO

**What source IP does the Web Server see?** 45.33.32.1

**Write the corrected blocking rule:** 

```
iptables -A INPUT -s 45.33.32.1 -j DROP
```



---

# Section D: Return Traffic

## Question 11

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│   Client   │         │ NAT Router │         │   Server   │
│            │◄────────┤            │◄────────┤            │
│ 10.0.0.50  │         │ WAN: 203.0.113.5    │ 93.184.216.34
└────────────┘         │ LAN: 10.0.0.1│       └────────────┘
                       └────────────┘
```

Server sends HTTP response back to Client.

Server-->NAT Router

Source IP: 93.184.216.34

Destination IP: 203.0.113.5

NAT Router --> Client

Source IP: 93.184.216.34

Destination IP: 10.0.0.50



**At Point A (Server → NAT Router):**
- Source IP: 93.184.216.34
- Destination IP: 203.0.113.5

**At Point B (NAT Router → Client):**
- Source IP: 93.184.216.34
- Destination IP: 10.0.0.50

**What changes the destination IP from 203.0.113.5 to 10.0.0.50?** NAT Router

---

## Question 12

```
┌────────────┐         ┌────────────┐         ┌────────────┐
│ Internet   │         │  Firewall  │         │ Web Server │
│ Client     │◄────────┤    (NAT)   │◄────────┤            │
│ 72.45.67.89│         │ DNAT: 80→10.0.0.100 │ 10.0.0.100 │
└────────────┘         │ WAN: 203.0.113.10   └────────────┘
                       └────────────┘
```

Web Server sends HTTP response back to Internet Client.

Client-->Firewall (NAT)

Source: 72.45.67.89

Destination: 203.0.113.10

Firewall (NAT)-->Server

Source: 72.45.67.89

Destination: 10.0.0.100

-------------------------------------------------

Server --> Firewall (NAT)

Source IP: 10.0.0.100

Destination IP: 72.45.67.89

Firewall (NAT) --> Client

Source: 203.0.113.10

Destination IP: 72.45.67.89

**At Point A (Web Server → Firewall):**
- Source IP: 10.0.0.100
- Destination IP: 72.45.67.89

**At Point B (Firewall → Internet Client):**
- Source IP: 203.0.113.10
- Destination IP: 72.45.67.89

---

# Answer Key

## Section A

**Q1:**
- Point A: SRC=10.0.0.50, DST=93.184.216.34
- Point B: SRC=203.0.113.5, DST=93.184.216.34

**Q2:**
- Point A: SRC=192.168.1.100, DST=8.8.8.8
- Point B: SRC=74.125.1.1, DST=8.8.8.8
- Point C: SRC=74.125.1.1, DST=8.8.8.8 (Router doesn't change IP)

**Q3:**
- Point A: SRC=192.168.0.25, DST=151.101.1.69
- Point B: SRC=100.64.1.50, DST=151.101.1.69
- Point C: SRC=52.1.2.3, DST=151.101.1.69
- Server sees: 52.1.2.3

## Section B

**Q4:**
- Point A: SRC=72.45.67.89, DST=203.0.113.10
- Point B: SRC=72.45.67.89, DST=10.0.0.100 (DNAT changed destination only)
- Web Server sees: 72.45.67.89

**Q5:**
- Point A: SRC=45.33.32.1, DST=104.44.1.1
- Point B: SRC=45.33.32.1, DST=104.44.1.1 (Router doesn't change IP)
- Point C: SRC=45.33.32.1, DST=10.0.0.50 (DNAT changed destination only)
- Will rule block attacker? NO
- Why? Rule looks for source 45.33.32.254 (router IP), but actual source is 45.33.32.1 (attacker IP). Routers don't change source IP.

## Section C

**Q6:**
- Will Developer SSH? NO
- Server sees: 198.51.100.10
- Corrected rule: `iptables -A INPUT -s 198.51.100.10 --dport 22 -j ACCEPT`

**Q7:**
- Server sees: 10.8.0.50 (VPN doesn't NAT)
- Will Admin SSH? YES (10.8.0.50 matches 10.8.0.0/24)

**Q8:**
- Seattle connect? NO
- Austin connect? NO
- Seattle source IP: 52.12.1.1
- Austin source IP: 104.210.1.1
- Corrected rule: `iptables -A INPUT -s 52.12.1.1 --dport 443 -j ACCEPT` and `iptables -A INPUT -s 104.210.1.1 --dport 443 -j ACCEPT`

**Q9:**
- External API sees: 54.23.45.67
- Will request succeed? YES (54.23.45.67 is in allowlist)

**Q10:**
- Will rule block scanner? NO
- Server sees: 45.33.32.1 (router doesn't change source, only NAT/firewall does DNAT on destination)
- Corrected rule: `iptables -A INPUT -s 45.33.32.1 -j DROP`

## Section D

**Q11:**
- Point A: SRC=93.184.216.34, DST=203.0.113.5
- Point B: SRC=93.184.216.34, DST=10.0.0.50
- What changes it? NAT connection tracking (conntrack) - NAT remembers the original connection and reverses the translation for return traffic.

**Q12:**
- Point A: SRC=10.0.0.100, DST=72.45.67.89
- Point B: SRC=203.0.113.10, DST=72.45.67.89 (NAT reverses DNAT, changes source back to public IP)

---

# Scoring

| Section | Questions | Points Each | Total |
|---------|-----------|-------------|-------|
| A (Outbound NAT) | 3 | 10 | 30 |
| B (Inbound NAT) | 2 | 10 | 20 |
| C (Mixed/SpaceX) | 5 | 8 | 40 |
| D (Return Traffic) | 2 | 5 | 10 |

**Total: 100 points**
**Passing: 85 points**

---

# Key Concepts Summary

1. **NAT changes source IP (outbound)** - MASQUERADE/SNAT
2. **NAT changes destination IP (inbound)** - DNAT
3. **Routers DON'T change source or destination IP** - just forward
4. **DNAT changes destination but NOT source** - attacker IP survives DNAT
5. **Conntrack reverses translations for return traffic**
6. **VPN without NAT preserves original source IP**
7. **Same private IP in different offices = different public IPs after NAT**
