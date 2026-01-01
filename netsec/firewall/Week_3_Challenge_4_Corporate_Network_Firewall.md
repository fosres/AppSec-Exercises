# Challenge 4: Corporate Network Firewall

## Objective
Configure a firewall for a corporate network with three zones: Internet, Corporate LAN, and Server Farm. You will implement access controls, logging, and security protections.

---

## Network Topology

```
                    [Internet]
                        |
                     (eth0)
                        |
                  [FIREWALL]
                    /      \
                (eth1)    (eth2)
                  /          \
          [Corporate LAN]  [Server Farm]
          192.168.10.0/24  192.168.20.0/24
```

### Interface Configuration
- **eth0**: Internet interface (public IP)
- **eth1**: Corporate LAN (192.168.10.0/24)
- **eth2**: Server Farm (192.168.20.0/24)

### Network Details

**Corporate LAN (192.168.10.0/24):**

- Employee workstations: 192.168.10.10 - 192.168.10.200
- IT Admin workstation: 192.168.10.5

**Server Farm (192.168.20.0/24):**
- Web Server: 192.168.20.10 (HTTP/HTTPS)
- Mail Server: 192.168.20.20 (SMTP/IMAP)
- Database Server: 192.168.20.30 (MySQL port 3306)
- DNS Server: 192.168.20.40 (DNS port 53)

---

## Your Tasks

### Part 1: Basic Setup (REQUIRED)

**1. Set default policies:**

- INPUT: ACCEPT
- FORWARD: DROP
- OUTPUT: ACCEPT

**2. Allow established connections:**
- Place this rule FIRST in the FORWARD chain
- Use conntrack to allow RELATED,ESTABLISHED traffic

**3. Drop invalid packets:**
- Place this rule SECOND in the FORWARD chain
- Use conntrack to drop INVALID traffic

---

### Part 2: Internet ↔ Server Farm (REQUIRED)

**Allow these services from Internet to Server Farm:**

1. **HTTP (port 80) to Web Server only**
   - Destination: 192.168.20.10
   - No rate limiting needed

2. **HTTPS (port 443) to Web Server only**
   - Destination: 192.168.20.10
   - No rate limiting needed

3. **SMTP (port 25) to Mail Server only**
   - Destination: 192.168.20.20
   - No rate limiting needed

4. **Block everything else from Internet to Server Farm**
   - Log denied traffic WITH rate limiting (5 logs per minute, burst 10)
   - Then drop the traffic

**Allow these services from Server Farm to Internet:**

5. **HTTPS (port 443) from all servers**
   - Source: 192.168.20.0/24
   - For software updates

6. **DNS (port 53 TCP and UDP) from DNS Server only**
   - Source: 192.168.20.40
   - No rate limiting needed

---

### Part 3: Corporate LAN ↔ Server Farm (REQUIRED)

**Allow these services from Corporate LAN to Server Farm:**

7. **HTTPS (port 443) to Web Server**
   - Employees need to access internal web portal

8. **IMAP (port 993) to Mail Server**
   - Employees need to read email

9. **SSH (port 22) to ALL servers - IT Admin ONLY**
   - Source: 192.168.10.5 (IT Admin workstation)
   - Destination: 192.168.20.0/24 (any server)

10. **MySQL (port 3306) to Database Server - Web Server ONLY**
    - Source: 192.168.20.10 (Web Server)
    - Destination: 192.168.20.30 (Database Server)
    - Note: This is Server Farm → Server Farm (same interface)

11. **Block everything else from Corporate LAN to Server Farm**
    - Log denied traffic WITH rate limiting (5 logs per minute, burst 7)
    - Then drop the traffic

**Block from Server Farm to Corporate LAN:**

12. **Servers should NOT initiate connections to Corporate LAN**
    - Block ALL traffic from Server Farm to Corporate LAN
    - Log violations WITH rate limiting (5 logs per minute, burst 7)
    - Then drop the traffic

---

### Part 4: Corporate LAN ↔ Internet (REQUIRED)

**Allow from Corporate LAN to Internet:**

13. **HTTP (port 80) for all employees**
    - Source: 192.168.10.0/24

14. **HTTPS (port 443) for all employees**
    - Source: 192.168.10.0/24

15. **DNS (port 53 TCP and UDP) for all employees**
    - Source: 192.168.10.0/24

16. **Block everything else from Corporate LAN to Internet**
    - Log denied traffic WITH rate limiting (5 logs per minute, burst 7)
    - Then drop the traffic

**Block from Internet to Corporate LAN:**

17. **Internet should NOT reach Corporate LAN directly**
    - Block ALL traffic from Internet to Corporate LAN
    - Log violations WITH rate limiting (5 logs per minute, burst 10)
    - Then drop the traffic

---

### Part 5: Security Protections (REQUIRED)

**18. Anti-spoofing rules:**
- Block packets on eth1 that don't have source 192.168.10.0/24
- Block packets on eth2 that don't have source 192.168.20.0/24
- Log each violation (no rate limiting needed for spoofing logs)
- Place these rules EARLY (after ESTABLISHED/INVALID, before other rules)

---

## Clear Requirements Summary

### What MUST have rate limiting:
- Logs for denied Internet → Server Farm traffic
- Logs for denied Corporate LAN → Server Farm traffic
- Logs for denied Server Farm → Corporate LAN traffic
- Logs for denied Corporate LAN → Internet traffic
- Logs for denied Internet → Corporate LAN traffic

### What does NOT need rate limiting:
- ALLOW rules (none of them)
- Anti-spoofing logs (NEEDS LOGGING ; NOT RATE LIMITING)
- Fragment protection (not required for this challenge)

### What needs logging:
- All DENIED traffic (with rate limiting as specified above)
- Anti-spoofing violations (without rate limiting)

### What does NOT need logging:
- ALLOWED traffic (don't log successful connections)

---

## Deliverable

Create a bash script that:
1. Sets default policies
2. Implements all rules in the order specified
3. Uses clear comments for each section
4. Can be run with: `sudo bash challenge4.sh`

**Save your work to:** `challenge4.sh`

---

## Testing Your Firewall

**Test these scenarios (you don't need to actually test, just verify your rules would allow/block):**

### Should be ALLOWED:
- Internet → Web Server port 443 ✓
- Employee (192.168.10.50) → Web Server port 443 ✓
- IT Admin (192.168.10.5) → Database Server port 22 ✓
- Web Server (192.168.20.10) → Database Server port 3306 ✓
- Employee (192.168.10.50) → Internet port 443 ✓

### Should be BLOCKED and LOGGED:
- Internet → Database Server port 3306 ✗
- Regular Employee (192.168.10.50) → Database Server port 22 ✗
- Mail Server (192.168.20.20) → Employee workstation port 445 ✗
- Internet → Employee workstation port 3389 ✗

### Should be BLOCKED and LOGGED (anti-spoofing):
- Packet on eth1 with source 10.0.0.1 (not 192.168.10.0/24) ✗
- Packet on eth2 with source 172.16.0.1 (not 192.168.20.0/24) ✗

---

## Success Criteria

Your firewall is correct if:
- ✅ All 18 requirements are implemented
- ✅ Rate limiting is on ALL log rules for denied traffic (NOT on anti-spoofing logs)
- ✅ No rate limiting on ALLOW rules
- ✅ Anti-spoofing rules are early in the chain
- ✅ ESTABLISHED/INVALID rules are first
- ✅ Script runs without errors

---

## Hints

1. **Rule order matters:**
   - ESTABLISHED/INVALID first
   - Anti-spoofing second
   - ALLOW rules before DENY rules
   - LOG before DROP for same path

2. **Interface specifications:**
   - Always use `-i` and `-o` for clarity
   - Server Farm → Server Farm uses `-i eth2 -o eth2`

3. **Rate limiting syntax:**
   ```bash
   -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "PREFIX: "
   ```

4. **Anti-spoofing syntax:**
   ```bash
   -A FORWARD -i eth1 ! -s 192.168.10.0/24 -j LOG --log-prefix "LAN-SPOOF: "
   -A FORWARD -i eth1 ! -s 192.168.10.0/24 -j DROP
   ```

---

## Questions to Ask If Confused

If any requirement is unclear:
1. "Does this rule need rate limiting?" → Check the summary above
2. "What interface is this?" → Check the network topology
3. "Which direction is this traffic?" → Look at the arrow (→)
4. "Does this need logging?" → All DENY rules need logging, ALLOW rules don't

**Ask me if anything is unclear BEFORE you start!**

---

## Estimated Time

- Reading requirements: 10 minutes
- Writing script: 30-45 minutes
- Testing/debugging: 15 minutes

**Total: ~60 minutes**

Good luck! 🎯
