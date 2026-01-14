# Can You Secure a Corporate Network? Prove It. 🔥

Most security tutorials hold your hand. This one doesn't.

I've created a **corporate network firewall challenge** that tests if you actually understand firewalls - not just copy-paste commands.

**The scenario:** You're the security engineer. The network is live. Configure the firewall or the company is vulnerable.

**No solutions. No step-by-step. Just requirements and a ruleset validator.**

Sound intimidating? Good. That's the point.

---

## What You're Building

**📝 Your deliverable: A complete iptables ruleset saved to a file (challenge4-ruleset.txt)**

You'll configure a **3-zone corporate firewall** protecting:
- **Internet** ↔ **Server Farm** (web, mail, database, DNS servers)
- **Corporate LAN** ↔ **Server Farm** (employee access)
- **Corporate LAN** ↔ **Internet** (browsing, updates)

**18 specific requirements** covering:
- ✅ Access control (who can reach what?)
- ✅ Security logging (with rate limiting)
- ✅ Anti-spoofing protection
- ✅ Stateful connection tracking
- ✅ Network segmentation

**What you must create:**
1. A bash script with iptables commands (`challenge4-solution.sh`)
2. A saved ruleset file from iptables-save (`challenge4-ruleset.txt`)
3. Upload the ruleset file to Claude/ChatGPT for AI grading

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

## The 18 Requirements (Complete Specification)

### Part 1: Basic Setup (Requirements 1-3)

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

### Part 2: Internet ↔ Server Farm (Requirements 4-6)

**Allow these services from Internet to Server Farm:**

**4. HTTP (port 80) to Web Server only**
- Destination: 192.168.20.10
- No rate limiting needed

**5. HTTPS (port 443) to Web Server only**
- Destination: 192.168.20.10
- No rate limiting needed

**6. SMTP (port 25) to Mail Server only**
- Destination: 192.168.20.20
- No rate limiting needed

**7. Block everything else from Internet to Server Farm**
- Log denied traffic WITH rate limiting (5 logs per minute, burst 10)
- Then drop the traffic

**Allow these services from Server Farm to Internet:**

**8. HTTPS (port 443) from all servers**
- Source: 192.168.20.0/24
- For software updates

**9. DNS (port 53 TCP and UDP) from DNS Server only**
- Source: 192.168.20.40
- No rate limiting needed

---

### Part 3: Corporate LAN ↔ Server Farm (Requirements 10-14)

**Allow these services from Corporate LAN to Server Farm:**

**10. HTTPS (port 443) to Web Server**
- Employees need to access internal web portal

**11. IMAP (port 993) to Mail Server**
- Employees need to read email

**12. SSH (port 22) to ALL servers - IT Admin ONLY**
- Source: 192.168.10.5 (IT Admin workstation)
- Destination: 192.168.20.0/24 (any server)

**13. MySQL (port 3306) to Database Server - Web Server ONLY**
- Source: 192.168.20.10 (Web Server)
- Destination: 192.168.20.30 (Database Server)
- Note: This is Server Farm → Server Farm (same interface)

**14. Block everything else from Corporate LAN to Server Farm**
- Log denied traffic WITH rate limiting (5 logs per minute, burst 7)
- Then drop the traffic

**Block from Server Farm to Corporate LAN:**

**15. Servers should NOT initiate connections to Corporate LAN**
- Block ALL traffic from Server Farm to Corporate LAN
- Log violations WITH rate limiting (5 logs per minute, burst 7)
- Then drop the traffic

---

### Part 4: Corporate LAN ↔ Internet (Requirements 16-17)

**Allow from Corporate LAN to Internet:**

**16. HTTP (port 80) for all employees**
- Source: 192.168.10.0/24

**17. HTTPS (port 443) for all employees**
- Source: 192.168.10.0/24

**18. DNS (port 53 TCP and UDP) for all employees**
- Source: 192.168.10.0/24

**Block everything else from Corporate LAN to Internet:**
- Log denied traffic WITH rate limiting (5 logs per minute, burst 7)
- Then drop the traffic

**Block from Internet to Corporate LAN:**
- Internet should NOT reach Corporate LAN directly
- Block ALL traffic from Internet to Corporate LAN
- Log violations WITH rate limiting (5 logs per minute, burst 10)
- Then drop the traffic

---

### Part 5: Security Protections (Requirement 18)

**Anti-spoofing rules:**
- Block packets on eth1 that don't have source 192.168.10.0/24
- Block packets on eth2 that don't have source 192.168.20.0/24
- Log each violation (no rate limiting needed for spoofing logs)
- Place these rules EARLY (after ESTABLISHED/INVALID, before other rules)

---

## Clear Requirements Summary

### What MUST have rate limiting:
- Logs for denied Internet → Server Farm traffic (burst 10)
- Logs for denied Corporate LAN → Server Farm traffic (burst 7)
- Logs for denied Server Farm → Corporate LAN traffic (burst 7)
- Logs for denied Corporate LAN → Internet traffic (burst 7)
- Logs for denied Internet → Corporate LAN traffic (burst 10)

### What does NOT need rate limiting:
- ALLOW rules (none of them)
- Anti-spoofing logs (NEEDS LOGGING; NOT RATE LIMITING)

### What needs logging:
- All DENIED traffic (with rate limiting as specified above)
- Anti-spoofing violations (without rate limiting)

### What does NOT need logging:
- ALLOWED traffic (don't log successful connections)

---

## Why This Challenge Is Different

**Most firewall tutorials:**
- Give you the commands
- Explain each line
- Hold your hand through setup
- Test nothing

**This challenge:**
- Gives you **requirements**, not commands
- You figure out the implementation
- Clear success criteria (pass/fail)
- Tests real-world scenarios

**It's designed like a take-home security interview.**

---

## What You'll Learn

By completing this challenge, you'll master:

### **1. Stateful Firewalls**
```bash
# You'll implement connection tracking:
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```
Understanding WHY this rule comes first separates beginners from professionals.

### **2. Network Segmentation**
```
Internet → Can access Web/Mail servers only
Employees → Can access internal portal, NOT database directly
IT Admin → SSH access to all servers
Web Server → Database access, Employees CAN'T reach DB directly
```
This is how real companies protect sensitive data.

### **3. Security Logging (Without Breaking Your Disk)**
```bash
# Rate-limited logging prevents log flooding attacks:
iptables -A FORWARD -m limit --limit 5/min --limit-burst 10 -j LOG
```
You'll learn when to log, when to rate-limit, and why both matter.

### **4. Anti-Spoofing Protection**
```bash
# Block packets claiming to be from your network but arriving on wrong interface:
iptables -A FORWARD -i eth1 ! -s 192.168.10.0/24 -j DROP
```
This defends against IP spoofing attacks.

---

## Testing Your Firewall

**Verify your rules would handle these scenarios correctly:**

### Should be ALLOWED:
- ✅ Internet → Web Server port 443
- ✅ Employee (192.168.10.50) → Web Server port 443
- ✅ IT Admin (192.168.10.5) → Database Server port 22
- ✅ Web Server (192.168.20.10) → Database Server port 3306
- ✅ Employee (192.168.10.50) → Internet port 443

### Should be BLOCKED and LOGGED:
- ❌ Internet → Database Server port 3306
- ❌ Regular Employee (192.168.10.50) → Database Server port 22
- ❌ Mail Server (192.168.20.20) → Employee workstation port 445
- ❌ Internet → Employee workstation port 3389

### Should be BLOCKED and LOGGED (anti-spoofing):
- ❌ Packet on eth1 with source 10.0.0.1 (not 192.168.10.0/24)
- ❌ Packet on eth2 with source 172.16.0.1 (not 192.168.20.0/24)

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

## How Hard Is It?

**Beginner?** You'll struggle (that's the point). But the requirements are crystal clear, and you'll learn by debugging.

**Intermediate?** You'll finish in 45-60 minutes if you know iptables basics.

**Expert?** Prove it. Complete it perfectly on first try.

**Everyone:** You'll have a realistic corporate firewall ruleset for your portfolio.

---

## The Challenge Workflow

```
1. Write iptables script → 2. Save ruleset file → 3. Upload to AI → 4. Get graded
      (30-60 min)              (iptables-save)         (Claude)        (Score/100)
                                                                             ↓
                                                                      Fix & retry
                                                                      until 95+/100
```

**You MUST create an actual file with your iptables rules - this isn't a reading exercise!**

---

## How to Complete This Challenge

**⚠️ IMPORTANT: You must create an actual iptables ruleset file, not just read the requirements!**

The challenge has 7 clear steps:

### **Step 1: Get the Challenge**

⭐ **Star the repo for the complete requirements:**  
👉 [GitHub: AppSec-Exercises/Challenge-4-Corporate-Firewall](https://github.com/fosres/AppSec-Exercises)

```bash
git clone https://github.com/fosres/AppSec-Exercises.git
cd AppSec-Exercises/Week-3-Firewalls
cat Challenge_4_Corporate_Network_Firewall.md
```

### **Step 2: Read All 18 Requirements**

The challenge document includes:
- ✅ Network topology diagram (3 zones: Internet, Corporate LAN, Server Farm)
- ✅ 18 numbered requirements (what to allow/block)
- ✅ Clear specifications for rate limiting
- ✅ Clear specifications for logging
- ✅ Success criteria checklist

**Read everything before writing a single command!**

**Note:** A working solution exists [here](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/firewall/iptables_lab_4.txt), but **try it yourself first!** You'll learn much more from struggling through it than copying.

### **Step 3: Write Your iptables Script**

**Create a bash script with your firewall rules:**

```bash
# Create your solution file
vim challenge4-solution.sh
```

**Template to start with:**

```bash
#!/bin/bash
# Challenge 4: Corporate Network Firewall
# Your Name - Date

# Flush existing rules
sudo iptables -F
sudo iptables -X

# Set default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# ============================================
# PART 1: BASIC SETUP
# ============================================

# Rule 1: Allow established connections
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Rule 2: Drop invalid packets
sudo iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# ============================================
# PART 2: ANTI-SPOOFING
# ============================================

# Rule 3: Block spoofed packets on eth1
# TODO: Implement this

# ============================================
# CONTINUE WITH ALL 18 REQUIREMENTS...
# ============================================

echo "Firewall configured successfully!"
```

**Your job:** Implement all 18 requirements as iptables rules.

### **Step 4: Test Your Script (Optional)**

**If you have a VM/lab environment:**

```bash
# Make executable
chmod +x challenge4-solution.sh

# Run it
sudo ./challenge4-solution.sh

# Verify rules loaded
sudo iptables -L FORWARD -v -n
```

**Don't have a lab? That's fine! Skip to Step 5.**

### **Step 5: Save Your Ruleset to a File**

**This is REQUIRED for grading:**

**If you ran the script:**
```bash
# Save the active iptables rules
sudo iptables-save > challenge4-ruleset.txt
```

**If you don't have a lab:**
```bash
# Manually create the ruleset file by extracting just the iptables commands
# Remove "sudo" and "echo" lines, keep only the iptables commands
# Format should match iptables-save output
```

**Your `challenge4-ruleset.txt` should look like this:**

```
# Generated by iptables-save v1.8.9
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -m conntrack --ctstate INVALID -j DROP
# ... rest of your rules ...
COMMIT
```

### **Step 6: Get AI Grading**

**Upload your ruleset to Claude or ChatGPT for instant feedback:**

**Go to:** [Claude.ai](https://claude.ai) or [ChatGPT](https://chat.openai.com)

**Copy/paste this prompt:**

```
I completed the Corporate Network Firewall Challenge (Challenge 4). 
Please grade my iptables ruleset against all 18 requirements.

Challenge requirements:
[Paste the entire Challenge_4_Corporate_Network_Firewall.md file here]

My iptables ruleset:
[Paste your challenge4-ruleset.txt file here]

Please provide:
1. Score out of 100
2. Which requirements I passed/failed
3. Specific issues with my rules
4. Security problems or best practice violations
5. Suggestions for improvement

Be detailed and thorough in your grading.
```

**The AI will:**
- ✅ Check all 18 requirements systematically
- ✅ Verify rule ordering is correct
- ✅ Identify security issues
- ✅ Check rate limiting is applied correctly
- ✅ Verify logging is implemented properly
- ✅ Give you a detailed score breakdown
- ✅ Suggest specific fixes

**Example grading output:**
```
Score: 85/100

✅ Requirement 1: ESTABLISHED connections (PASS)
✅ Requirement 2: INVALID drop (PASS)
❌ Requirement 4: Missing rate limiting on LOG rule (FAIL)
⚠️  Requirement 7: Using entire subnet instead of specific IP (SECURITY ISSUE)
...

Issues found:
1. Line 12: LOG rule missing -m limit (will flood logs during attack)
2. Line 24: -d 192.168.20.0/24 too broad (should be 192.168.20.10)

Your score: 85/100 - Fix these issues for 100/100!
```

### **Step 7: Iterate Until Perfect**

**If your score is below 95/100:**

1. Read the AI's feedback carefully
2. Fix the specific issues identified  
3. Update your script
4. Save the new ruleset: `sudo iptables-save > challenge4-ruleset.txt`
5. Re-submit for grading

**Keep iterating until you achieve 95-100/100!**

**That's when you know you've mastered it.**

---

## Hints (Read These Before Starting!)

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

---

## Why You Should Star the Repo ⭐

**This isn't just a blog post - it's an entire hands-on curriculum:**

The repo includes:
- ✅ **Challenge 1:** Basic Linux firewall (beginner)
- ✅ **Challenge 2:** Multi-interface DMZ setup (intermediate)
- ✅ **Challenge 3:** PCI-DSS compliant firewall (advanced)
- ✅ **Challenge 4:** Corporate network (this one!)
- 🔜 **More challenges coming:** VPN integration, cloud firewalls, Kubernetes network policies

**Plus:**
- Clear, unambiguous requirements (no frustrating guesswork)
- Real-world scenarios (not toy examples)
- Interview-prep focused (these are actual take-home questions)
- Community solutions (learn from others' approaches)

**Star it to:**
- ✅ Bookmark for later
- ✅ Support open-source security education
- ✅ Get notified of new challenges
- ✅ Show appreciation (it's free!)

👉 **[Star the repo now →](https://github.com/fosres/AppSec-Exercises)**

---

## Common Mistakes (Don't Peek Until You Try!)

**⚠️ Seriously, attempt the challenge BEFORE reading these!**

<details>
<summary>Click to reveal common pitfalls...</summary>

**Mistake 1: Forgetting ESTABLISHED connections**
```bash
# Wrong: Each direction needs explicit rules
# Right: One ESTABLISHED rule handles return traffic
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

**Mistake 2: Wrong rule order**
```bash
# Wrong: DROP before ALLOW
-A FORWARD -i eth0 -o eth1 -j DROP  # Blocks everything!
-A FORWARD -i eth0 -o eth1 -p tcp --dport 443 -j ACCEPT  # Never reached

# Right: ALLOW before DROP
-A FORWARD -i eth0 -o eth1 -p tcp --dport 443 -j ACCEPT
-A FORWARD -i eth0 -o eth1 -j DROP
```

**Mistake 3: Forgetting rate limiting on LOG rules**
```bash
# Wrong: Attackers can flood your logs
-A FORWARD -j LOG

# Right: Rate-limited logging
-A FORWARD -m limit --limit 5/min --limit-burst 10 -j LOG
```

**Mistake 4: Too broad destination IPs**
```bash
# Wrong: Allows access to entire server network
-A FORWARD -d 192.168.20.0/24 -p tcp --dport 3306 -j ACCEPT

# Right: Only specific database server
-A FORWARD -d 192.168.20.30 -p tcp --dport 3306 -j ACCEPT
```

**Still stuck?** Check out [a working solution](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/firewall/iptables_lab_4.txt) to see one correct approach.

</details>

---

## Want to See a Working Solution?

**⚠️ WARNING: Try the challenge yourself FIRST before looking at solutions!**

You'll learn 10x more by struggling through it than by copying someone else's work.

**But if you're stuck, or want to compare your approach:**

👉 **[View my solution (100/100 score)](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/firewall/iptables_lab_4.txt)**

**How to use this solution:**

1. ✅ **Complete the challenge yourself first** (seriously!)
2. ✅ **Get your ruleset graded by AI**
3. ✅ **Compare your approach to mine**
4. ✅ **Learn from the differences**

**Remember:** There are multiple valid ways to solve this. My solution is ONE approach that scores 100/100, but yours might be different and equally valid!

**Use it for:**
- Checking your logic after you've attempted it
- Understanding alternative approaches
- Verifying your rule ordering
- Learning advanced techniques

**Don't use it for:**
- ❌ Copying without understanding
- ❌ Skipping the learning process
- ❌ Submitting as your own work

**The goal is mastery, not completion.** 🎯

---

## After You Complete This...

**You'll be able to:**
- ✅ Configure enterprise-style firewalls from scratch
- ✅ Explain stateful vs stateless filtering
- ✅ Design multi-zone network architectures
- ✅ Implement security logging without breaking things
- ✅ Ace firewall questions in security interviews

**Add to your resume:**
> "Configured enterprise-style corporate firewall with 3-zone segmentation, stateful filtering, anti-spoofing protection, and comprehensive security logging"

**Add to your portfolio:**
> Link to your GitHub solution (if you share it)

**Use in interviews:**
> "I completed a corporate firewall challenge that tested 18 real-world requirements including network segmentation, rate-limited logging, and anti-spoofing. Here's my approach..."

---

## The Community

**After completing the challenge:**

1. **Compare with my solution** (optional)
   - See my 100/100 scoring ruleset
   - Learn alternative approaches
   - Understand different techniques

2. **Share your solution** (optional)
   - Create a GitHub Gist
   - Write a blog post about your approach
   - Help others in the discussion

3. **Give feedback**
   - Was anything unclear?
   - Should requirements be more/less detailed?
   - What other challenges would you like?

4. **Star the repo** ⭐
   - Support the project
   - Get notified of new challenges
   - Help others discover it

---

## Ready? Here's Your Mission 🎯

**The challenge workflow:**

1. ⭐ **[Star the repo](https://github.com/fosres/AppSec-Exercises)** (get the requirements)
2. 📖 **Read all 18 requirements** carefully
3. 💻 **Write your iptables script** (all 18 requirements as rules)
4. 💾 **Save your ruleset** to `challenge4-ruleset.txt` using `iptables-save`
5. 🤖 **Upload to Claude/ChatGPT** for instant AI grading
6. 🔁 **Fix issues and re-submit** until you hit 95-100/100
7. 🎉 **Add to your portfolio!**

**You MUST create an actual iptables ruleset file - no shortcuts!**

**Estimated Time:**
- Reading requirements: 10 minutes
- Writing script: 30-45 minutes
- Testing/debugging: 15 minutes
- **Total: ~60 minutes**

**Start the challenge →** [Get the requirements](https://github.com/fosres/AppSec-Exercises)

**Stuck or want to compare?** [View a working solution](https://github.com/fosres/AppSec-Exercises/blob/main/netsec/firewall/iptables_lab_4.txt) (try it yourself first!)

---

## About This Series

This is part of my **48-week Security Engineering curriculum** focused on hands-on skills that actually matter in interviews.

**Other challenges in the repo:**
- Challenge 1: Basic Linux firewall
- Challenge 2: DMZ architecture
- Challenge 3: PCI-DSS compliance
- Challenge 4: Corporate network (this one)

**Coming soon:**
- VPN integration challenges
- Cloud firewall scenarios (AWS Security Groups)
- Kubernetes network policies
- Zero-trust architecture

**Follow me for more security engineering content!**

---

**Found this useful? ⭐ [Star the repo](https://github.com/fosres/AppSec-Exercises) and help others discover it!**

**Questions? Drop them in the comments below. 👇**

---

*P.S. - If you complete this challenge, you're better prepared than 80% of security engineering candidates. No joke.*
