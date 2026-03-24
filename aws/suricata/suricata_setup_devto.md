---
title: "Use Suricata as An Intrusion Detection System on AWS"
published: false
description: "How to install and configure Suricata IDS on a Debian 13 EC2 instance, write custom detection rules for SQL injection, port scans, C2 beaconing, and DNS tunneling, and analyze traffic with PCAP."
tags: aws, security, devsecops, tutorial
cover_image:
series: Security Engineering Interview Prep
---

> **This is Part 3 of a series. I highly recommend reading the first two posts in order before starting this one:**
>
> **1️⃣ [Secure AWS Lab Setup for Security Engineers: IAM Identity Center + SSM + Zero Open Ports](https://dev.to/fosres/secure-aws-lab-setup-for-security-engineers-iam-identity-center-ssm-zero-open-ports-1hfn)**
> Learn how to set up AWS IAM Identity Center, SSM Session Manager, and a zero-open-ports EC2 instance. This post assumes you have completed this setup.
>
> **2️⃣ [Fish Shell Functions for Managing AWS EC2 Instances — Save Time and Billing](https://dev.to/fosres/fish-shell-functions-for-managing-aws-ec2-instances-save-progress-time-and-billing-1kbi)**
> Learn how to use fish shell functions (`lab-create`, `lab-connect`, `lab-snapshot`, `lab-restore`, etc.) to manage your EC2 lab efficiently. The commands in this post assume you have these functions installed.

> ⚠️ **Your instance IP changes every session.** Every time you run `lab-restore` or `lab-create` a new EC2 instance is launched with a different private IP address. Before running any commands in this post that reference an IP address (curl tests, nmap, suricata.yaml `HOME_NET`), always check your current IP first:
> ```bash
> ip addr show enX0 | grep "inet "
> ```
> Replace `172.31.23.15` throughout this post with whatever IP your instance currently has.

---

All the fish shell functions used in this series for managing EC2 instances — `lab-create`, `lab-connect`, `lab-status`, `lab-start`, `lab-stop`, `lab-terminate`, `lab-login`, `lab-snapshot`, `lab-snapshot-list`, `lab-snapshot-delete`, and `lab-restore` — are available to download from GitHub:

**👉 [github.com/fosres/SecEng-Exercises/tree/main/aws/functions](https://github.com/fosres/SecEng-Exercises/tree/main/aws/functions)**

Download them, place each file in `~/.config/fish/functions/`, and they are immediately available in your terminal — no `source` command needed.

---

If you find this useful, I'd really appreciate a ⭐ on my open source secure coding exercise repo — it helps a lot:

**👉 [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

Also — why do you read security engineering blog posts? One click helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)** (takes 10 seconds)

---

## What This Post Covers

This is an **introduction to Suricata IDS** for Security Engineers working in web application and cloud security. It covers what a mid-level Security Engineering interview expects you to know about network intrusion detection — no more, no less.

**What you will learn:**
- Installing and configuring Suricata on a Debian EC2 instance
- Writing 5 custom detection rules from scratch covering SQL injection, port scanning, C2 beaconing, and DNS tunneling
- Iterative rule tuning — every rule in this post went through multiple revisions, and the revision history is documented honestly
- Identifying and resolving false positives using `pass` rules — specifically the AWS IMDS and SSM Agent traffic that looks identical to C2 beaconing
- Capturing and analyzing traffic with `tcpdump` to correlate PCAP evidence with Suricata alerts
- Connecting local Suricata rules directly to AWS Network Firewall — the same rule syntax runs in both environments
- 5 practice exercises covering rule interpretation, threshold tuning, rule management, keyword identification, and community rulesets

**What this post deliberately omits:**
- **TLS inspection** — Suricata can inspect encrypted HTTPS traffic if configured with TLS decryption, but that requires certificate management and is a topic on its own
- **Inline IPS mode** — this post runs Suricata in IDS mode (alert only). Switching to IPS mode (drop packets) requires routing traffic through Suricata rather than just mirroring it — a different architecture
- **SIEM integration** — shipping Suricata `eve.json` alerts to ELK or Splunk for correlation and dashboarding is covered separately in the Week 8 ELK post
- **Zeek for network metadata** — Zeek complements Suricata by generating rich connection metadata rather than signature-based alerts. The two tools are used together in production but are separate topics
- **Performance tuning** — multi-threading, AF_PACKET tuning, and rule optimization for high-throughput environments are senior-level topics that belong in a dedicated post
- **Full AWS Network Firewall deployment** — creating the rule group is covered here, but attaching it to a firewall policy, deploying a firewall endpoint, and updating VPC route tables requires a properly architected VPC covered in Week 50

This post is Part 3 of a series. The natural continuation points are Week 50 (deploying Network Firewall in a production VPC architecture) and Week 87 (production-grade network monitoring with Suricata + Zeek + Security Onion).

---

## Part 1: Connect to the Lab Instance

From your local machine:

```fish
lab-login      # tap YubiKey if SSO token has expired
lab-status     # confirm: running
lab-connect    # shell as ssm-user
```

Once inside the instance:

```bash
sudo -i
```

---

## Part 2: Saving Your Progress — Snapshots

Before going any further, make sure you have the snapshot fish functions set up on your local machine. Setting up Suricata takes time and you will likely spread the work across multiple sessions. The snapshot functions let you save your instance state, terminate it to pay nothing overnight, and restore exactly where you left off next session.

Full implementations and explanations are in the dedicated post:

**👉 [Week 9: Fish Shell Functions for Managing AWS EC2 Instances -- Save Time and Billing](https://dev.to/fosres/fish-shell-functions-for-managing-aws-ec2-instances-save-progress-time-and-billing-1kbi)**

The four snapshot commands you will use throughout this post:

```fish
lab-snapshot-list      # see all your saved snapshots
lab-snapshot           # save current instance state — prompts for instance ID and name
lab-restore            # launch a new instance from a saved snapshot
lab-snapshot-delete    # delete old snapshots to stop storage charges
```

> ⏳ **`lab-snapshot` takes 3-5 minutes to complete.** AWS copies the entire EBS volume to S3 in the background. Do not interrupt it. A heavily loaded instance may take up to 10-15 minutes.

**You do not need to remember the AMI ID.** When you run `lab-restore` it prints a table of all your saved snapshots by name:

```
Your saved AMIs:
+------------------------+---------------------------+----------------------+
| ami-0xxxxxxxxxxxxxxxxx | suricata_setup-2026-03-15 | 2026-03-15T12:00:00Z |
+------------------------+---------------------------+----------------------+
```

### Complete Zero-Cost Session Workflow

```fish
lab-login           # tap YubiKey → 8hr credentials
lab-restore         # launch from snapshot → wait → "Ready"
lab-connect         # shell as ssm-user, Suricata already installed
lab-snapshot        # save progress before ending session
lab-terminate       # zero ongoing cost
```

---

## Part 3: Install Suricata on Debian 13

```bash
apt-get update -y && apt-get upgrade -y

apt-get install suricata suricata-update -y
```

Verify the installation:

```bash
suricata --build-info
systemctl status suricata
ip addr
```

> **Note the interface name** from `ip addr` — Debian on EC2 typically uses `ens5` or `eth0`. You will need it when configuring `suricata.yaml`.

Update the default ruleset:

```bash
suricata-update

systemctl start suricata
systemctl enable suricata
systemctl status suricata
```

---

## Part 4: Configure suricata.yaml

Two values need to be set correctly before Suricata can capture traffic: the network interface and the `HOME_NET` variable. Both come from the `ip addr` output.

### Identifying the Correct Interface

Run `ip addr` and look for the interface that has:
- `<BROADCAST,MULTICAST,UP,LOWER_UP>` — confirms it is up and capable of capturing traffic
- `state UP` — confirms it is active
- An `inet` address in the `172.x.x.x` or `10.x.x.x` range — confirms it is the EC2 network interface, not loopback

For example on my Debian 13 EC2 instance my correct interface looks like:

```
2: enX0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc fq_codel state UP group default qlen 1000
    link/ether 0a:ff:cd:e5:67:a9 brd ff:ff:ff:ff:ff:ff
    inet 172.31.25.81/20 metric 100 brd 172.31.31.255 scope global dynamic enX0
```

Ignore `lo` — that is the loopback interface (`127.0.0.1`) and has no external traffic.

The interface name on Debian 13 EC2 instances is `enX0` rather than the more common `eth0` or `ens5` you may see in other tutorials. Always confirm with `ip addr` before editing `suricata.yaml` — using the wrong interface name means Suricata starts successfully but captures nothing.

From `ip addr` on this instance:
- **Interface:** `enX0`
- **Subnet:** `172.31.16.0/20` (the `/20` subnet containing `172.31.25.81`)

> **Note:** Your interface name and subnet will be the same if you are following along on the same EC2 instance type and region. If they differ, substitute your own values in the steps below.

### Set HOME_NET

Open `suricata.yaml`:

```bash
nano /etc/suricata/suricata.yaml
```

Find the `HOME_NET` line (near the top, under `vars:`) and update it to match your subnet:

```yaml
vars:
  address-groups:
    HOME_NET: "[172.31.16.0/20]"
```

The default value is `[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]` which technically includes the EC2 subnet — but setting it explicitly to your actual subnet makes your custom rules more precise and reduces false positives.

From the `ip addr` output, the relevant line is:

```
inet 172.31.25.81/20 ... scope global dynamic enX0
```

`172.31.25.81` is the **host address** — the IP of this specific instance. The `/20` is the subnet mask. The actual subnet to use in `HOME_NET` is `172.31.16.0/20`, not `172.31.25.81/20`. A `/20` mask starting at `172.31.16.0` covers the range `172.31.16.0` → `172.31.31.255`, and `172.31.25.81` falls within that range — which is how you know `172.31.16.0/20` is the correct value.

If you are unsure of your subnet's network address, run:

```bash
ip route | grep enX0
```

The line starting with `172.31.x.x/20` (without a `src` qualifier) is your subnet.

### Set the Capture Interface

In the same file, find the `af-packet` section and set the interface to `enX0`:

```yaml
af-packet:
  - interface: enX0
  - interface: lo
```

Search for it quickly with `Ctrl+W` then type `af-packet` in nano.

> **Why add `lo`?** When testing Suricata from the same instance (e.g. running `curl` against the instance's own IP), Linux routes the traffic internally through the loopback interface `lo` rather than through `enX0` — even if you use the real IP address `172.31.23.15`. This is called **local routing** and means Suricata sees none of that traffic if it only monitors `enX0`. Adding `lo` to the `af-packet` list lets Suricata inspect self-generated test traffic without needing to open any inbound ports or send traffic from an external machine.

### Enable the Custom Rules File

Still in `suricata.yaml`, find the `rule-files:` section and add the custom rules file:

```yaml
rule-files:
  - suricata.rules
  - /etc/suricata/rules/custom.rules
```

Save and exit: `Ctrl+X` → `Y` → `Enter`

### Create the Custom Rules File

```bash
mkdir -p /etc/suricata/rules
touch /etc/suricata/rules/custom.rules
```

### Validate and Restart

Before running the config test, update the default ruleset to ensure `suricata.rules` exists at the expected path:

```bash
suricata-update
```

Then run the config test:

```bash
suricata -T -c /etc/suricata/suricata.yaml -v
```

`-T` runs a config test without starting capture. Look for:

```
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

If the test passes, restart the service:

```bash
systemctl restart suricata
systemctl status suricata
```

Confirm Suricata is capturing on `enX0`:

```bash
tail -f /var/log/suricata/suricata.log | grep enX0
```

You should see a line like:

```
Info: iface-conf: Configuring af-packet for enX0
```

---

## Part 5: Write 5 Custom Detection Rules

Rules file: `/etc/suricata/rules/custom.rules`

Before writing the rules it is worth understanding what Suricata can and cannot detect at the network level — especially for SQL injection.

### How Suricata Detects Attacks

Suricata is a **signature-based IDS**. It inspects network packets looking for known patterns — strings, regular expressions, protocol anomalies. When a packet matches a rule it generates an alert in `fast.log` and a detailed JSON event in `eve.json`.

This makes it very good at catching **known, unsophisticated attacks** — automated scanners, script kiddies running off-the-shelf tools, and anyone sending payloads in plain text over HTTP. It is less effective against a skilled attacker doing manual exploitation, for reasons covered below.

### SQL Injection Rules — How Effective Are They?

**Rule 1 — UNION SELECT** catches classic UNION-based payloads like:

```
' UNION SELECT username, password FROM users--
```

It uses `content` matching with `nocase` so case variation is handled. It **fails against**:
- URL encoding: `%55%4E%49%4F%4E` instead of `UNION`
- Comment injection: `UN/**/ION SE/**/LECT`
- HTTPS traffic — Suricata cannot inspect encrypted payloads without TLS inspection configured

**Rule 2 — Comment Bypass** uses **PCRE** (Perl Compatible Regular Expressions) to catch `' OR 1=1` style payloads and their URL-encoded variants (`%27`, `%3D`). PCRE is a powerful pattern matching syntax that goes beyond simple string matching — instead of looking for a fixed string like `UNION SELECT`, a PCRE pattern can match variable structures. In this case the pattern matches a single quote (or its URL-encoded form `%27`) followed by `OR`/`AND` followed by an equals sign, in any combination of whitespace and case.

> **Does Suricata use Perl?** No — PCRE is just a C library that implements the regex syntax Perl popularized in the 1980s-90s. The name is historical. Suricata is written in C and links against the PCRE library directly — Perl itself is nowhere in the picture. The same library is used by Apache, nginx, PHP, and grep, which is why PCRE has become the de facto standard for regex across the industry.

It **misses** attacks destined for this server:
- Time-based blind SQLi: `'; WAITFOR DELAY '0:0:5'--`
- Boolean-based blind SQLi that does not use `OR`/`AND`
- Second-order SQLi where the payload is stored and executed later
- Out-of-band SQLi using DNS or HTTP exfiltration channels

**The honest reality:** Suricata's SQLi rules are a last line of defense, not a primary control. They are useful for catching automated scanners and known payloads in plaintext traffic. A skilled attacker doing manual exploitation will evade them.

The real defenses against SQL injection are at the application layer — parameterized queries, ORMs, and input validation. Suricata gives you **visibility and alerting**, not prevention. That distinction matters and is worth knowing for Security Engineering interviews.

---

### The 5 Rules

### Rule 1: SQL Injection — UNION SELECT

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
```

**How it works:**
- **`alert`** — the action to take when the rule matches. `alert` generates a log entry in `fast.log` and `eve.json` but does not block the traffic. Other actions include `drop` (block the packet) and `pass` (allow and stop processing further rules).
- **`tcp`** — the protocol to inspect. Using `tcp` instead of `http` means Suricata inspects the raw TCP stream directly — no protocol normalization needed. This ensures the rule fires on the raw packet bytes regardless of HTTP layer parsing.
- **`any any`** (source) — match traffic coming from any IP address on any port.
- **`->`** — traffic direction. This arrow means the rule only inspects traffic flowing from source to destination, not the reverse.
- **`$HOME_NET 80`** (destination) — match traffic destined for port 80 (HTTP) on any host within `$HOME_NET`. Restricting to port 80 keeps the rule focused on web traffic specifically.
- **`msg:"SQL Injection UNION SELECT Attempt"`** — the human-readable label that appears in the alert log so you know what triggered.
- **`content:"UNION"`** — simple substring search for the exact string `UNION` anywhere in the TCP payload.
- **`nocase`** — makes the preceding `content` match case-insensitive so `union`, `UNION`, and `Union` all trigger it.
- **`content:"SELECT"`** — look for the string `SELECT` in the packet payload after `UNION` has already matched.
- **`sid:9000001`** — the unique rule ID (Signature ID). The `9000000` range is reserved for local/custom rules so it does not conflict with official Emerging Threats or Snort rulesets.
- **`rev:4`** — the revision number of this rule. This reached revision 4 through iterative tuning during lab setup — a realistic example of how rules evolve in practice.

**Example payload it catches:**
```
' UNION SELECT username, password FROM users--
```

**Fails against:**
- **URL encoding:** `%55%4E%49%4F%4E` instead of `UNION` — Suricata sees encoded bytes, not the decoded string
- **Comment injection:** `UN/**/ION SE/**/LECT` — the SQL comment breaks up the string so neither `UNION` nor `SELECT` appears as a complete match
- **HTTPS traffic** — Suricata cannot inspect encrypted payloads without TLS inspection configured, so any SQLi over HTTPS is completely invisible to this rule

### Rule 2: SQL Injection — Comment Bypass

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
```

**How it works:**
- **`alert`** — generate an alert without blocking.
- **`tcp`** — inspect raw TCP stream directly. The `http` protocol keyword caused matching issues with URL-encoded payloads on this setup — switching to `tcp` resolved it.
- **`any any`** (source) — match traffic from any IP on any port.
- **`->`** — traffic direction toward the server.
- **`$HOME_NET 80`** — match traffic destined for port 80 on hosts in your subnet.
- **`msg:"SQL Injection Comment Bypass Attempt"`** — the alert label.
- **`content:"OR"`** — match the literal string `OR` anywhere in the TCP payload.
- **`nocase`** — case-insensitive so `or`, `OR`, and `Or` all trigger.
- **`content:"="`** — also require an equals sign somewhere in the payload. Requiring both `OR` and `=` reduces false positives compared to matching `OR` alone.
- **`sid:9000002`** — unique rule ID in the local custom range.
- **`rev:6`** — this rule went through 6 revisions during lab setup, starting as a PCRE pattern and ending as a reliable dual content match — a realistic example of iterative rule tuning.

**Example payloads it catches:**
```
' OR 1=1--
%27 OR 1%3D1--
' AND 1=1--
```

**Fails against:**
- **Time-based blind SQLi:** `'; WAITFOR DELAY '0:0:5'--` — no `OR`/`AND` equals pattern to match
- **Boolean-based blind SQLi** that does not use `OR`/`AND`
- **Second-order SQLi** — payload is stored in the database and executed later, never appearing in a direct HTTP request
- **Out-of-band SQLi** using DNS or HTTP exfiltration channels

---

### A Note on PCRE in Suricata Rules

Rule 2 originally used a PCRE pattern instead of simple `content` matching. PCRE (Perl Compatible Regular Expressions) is a more powerful matching approach that can detect variable structures rather than fixed strings.

The Suricata keyword is `pcre` and the syntax is:

```
pcre:"/pattern/flags";
```

The original Rule 2 PCRE pattern was:

```
alert http any any -> $HOME_NET any (msg:"SQL Injection Comment Bypass Attempt"; pcre:"/(\%27|\')\s*(or|and)\s*[\w\s]*(\%3D|=)/i"; sid:9000002; rev:1;)
```

Breaking down the pattern `/(\%27|\')\s*(or|and)\s*[\w\s]*(\%3D|=)/i`:

| Pattern piece | What it matches |
|---|---|
| `(\%27|\')` | A single quote — either literal `'` or URL-encoded as `%27` |
| `\s*` | Zero or more whitespace characters |
| `(or\|and)` | The word `or` or `and` |
| `\s*` | Zero or more whitespace characters |
| `[\w\s]*` | Any word characters or spaces (e.g. `1`) |
| `(\%3D\|=)` | An equals sign — either literal `=` or URL-encoded as `%3D` |
| `/i` flag | Makes the entire pattern case-insensitive |

**Why PCRE was abandoned in this lab:** The pattern failed to fire on URL-encoded payloads sent via curl. The `+` character used by `--data-urlencode` to represent spaces broke the `\s*` whitespace match since `+` is not a whitespace character. Rather than debug the PCRE pattern further, Rule 2 was simplified to dual `content` matching which is more reliable on raw TCP traffic.

**When to use PCRE over content matching:**

- When the payload has variable structure — different whitespace, optional characters, or alternating patterns
- When you need to match URL-encoded and literal versions of the same character in one rule
- When `distance:0` is too strict — PCRE lets you express "these two strings with anything between them" more precisely

**The tradeoff:** PCRE is significantly more expensive to evaluate than `content` matching — Suricata has to run a regex engine against every matching packet. In high-traffic production environments this matters. Always benchmark PCRE rules under load before deploying them.

### Rule 3: Port Scan — SYN Threshold

```
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
```

**How it works:**
- **`alert`** — generate an alert without blocking.
- **`tcp`** — inspect TCP traffic only. Port scans use TCP SYN packets to probe open ports.
- **`any any`** (source) — match traffic from any IP on any port.
- **`->`** — traffic flowing from source toward the destination.
- **`$HOME_NET any`** (destination) — any port on any host in your subnet. Port scanners probe many ports so leaving the destination port as `any` is correct.
- **`msg:"Possible Port Scan Detected"`** — the alert label.
- **`flags:S`** — only match packets with the SYN flag set and no other flags. A TCP SYN packet is the first step of a connection attempt. A port scanner sends many SYN packets to different ports to discover which ones are open — this is called a SYN scan or half-open scan.
- **`threshold:type threshold,track by_src,count 5,seconds 10`** — only alert once the same source IP has sent 5 or more SYN packets within a 10-second window. The original threshold was 20 but was lowered to 5 to ensure reliable detection on a single-core t2.micro where Suricata may not track all packets if nmap fires too fast. In a production environment with higher traffic volumes you would raise this to reduce false positives from legitimate services doing rapid connection attempts.

The `threshold` keyword has four components worth understanding individually:

| Component | Value in this rule | What it means |
|---|---|---|
| `type` | `threshold` | Alert once every time the count is reached. Other types: `limit` (alert only N times per window), `both` (alert once then suppress until window resets) |
| `track` | `by_src` | Count packets per source IP separately. `by_dst` would count per destination IP instead. `by_rule` counts globally across all IPs |
| `count` | `5` | How many matching packets must be seen before the rule fires |
| `seconds` | `10` | The time window in which `count` packets must be observed |

**`type threshold` vs `type both`:** Rule 3 uses `type threshold` which fires every time the count is reached — so if nmap sends 50 SYN packets, you get approximately 10 alerts (one per 5 packets). Rule 4 uses `type both` which fires once then suppresses further alerts until the window resets — better for reducing alert fatigue on beaconing detection.
- **`sid:9000003`** — unique rule ID in the local custom range.
- **`rev:1`** — rule revision 1.

**Example scenario it catches:**
A scanner like `nmap` sending SYN packets to ports 1 through 1000 in rapid succession from a single IP.

**Fails against:**
- **Slow scans** — spreading 20 SYN packets over more than 10 seconds evades the threshold
- **Distributed scans** — multiple source IPs each sending fewer than 20 SYN packets

---

### Rule 4: C2 Beaconing — HTTP Threshold

```
alert http $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:1;)
```

**What is C2 Beaconing?**

C2 stands for **Command and Control**. When an attacker successfully compromises a machine — through malware, a phishing link, or an exploit — they need a way to communicate with it remotely to issue commands, receive stolen data, and maintain access. The attacker runs a C2 server on the internet and the malware on the compromised machine calls home to it at regular intervals. This regular check-in is called **beaconing**.

The malware typically uses HTTP or HTTPS to blend in with normal web traffic — from a firewall's perspective it looks like ordinary browser traffic. The beacon might say "I am here, any new commands?" and the C2 server responds with instructions: run this command, exfiltrate this file, move to this other machine.

The telltale sign of beaconing is **regularity** — a compromised host making outbound HTTP requests on a precise, repeating schedule (every 30 seconds, every 5 minutes, etc.) to the same destination. Humans browse the web irregularly; malware beacons like a clock.

**How it works:**
- **`alert`** — generate an alert without blocking.
- **`http`** — inspect HTTP traffic only. Most C2 frameworks use HTTP or HTTPS to blend in with normal web traffic.
- **`$HOME_NET any`** (source) — traffic originating from inside your subnet. C2 beaconing is outbound — a compromised host inside your network calling out to an attacker's server.
- **`->`** — traffic flowing outward from your network.
- **`any any`** (destination) — any external IP on any port.
- **`msg:"Possible C2 Beaconing Detected"`** — the alert label.
- **`flow:to_server,established`** — only inspect outbound HTTP requests on established connections, not raw SYN packets.
- **`threshold:type both,track by_src,count 10,seconds 60`** — alert when the same source IP makes 10 or more HTTP requests within 60 seconds, and then suppress further alerts until the window resets. `type both` means the rule triggers once per threshold window rather than once per packet, reducing alert fatigue. C2 beaconing is characterized by regular, periodic outbound connections — this pattern is what the rule is designed to catch.
- **`sid:9000004`** — unique rule ID in the local custom range.
- **`rev:1`** — rule revision 1.

**Example scenario it catches:**
Malware beaconing to a C2 server every 5 seconds — 10 connections in under 60 seconds triggers the alert.

**Fails against:**
- **Slow beaconing** — intervals longer than 6 seconds mean fewer than 10 connections per minute
- **HTTPS C2** — encrypted traffic is invisible without TLS inspection
- **Domain fronting** — C2 traffic disguised as requests to a legitimate CDN like Cloudflare

---

### Rule 5: DNS Tunneling — Large DNS Query

```
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:1;)
```

**How it works:**
- **`alert`** — generate an alert without blocking.
- **`udp`** — inspect UDP traffic. DNS uses UDP port 53 by default for queries. Using `udp` instead of `dns` avoids mixing packet-level and application-layer keywords which Suricata 7 does not allow in the same rule.
- **`any any`** (source) — match DNS queries from any host.
- **`->`** — traffic direction outward.
- **`any 53`** (destination) — port 53 is the standard DNS port. Restricting to port 53 keeps this rule focused on DNS traffic specifically.
- **`msg:"Possible DNS Tunneling - Large Query"`** — the alert label.
- **`dsize:>200`** — match only when the UDP payload is larger than 200 bytes. Normal DNS queries are small — a typical hostname lookup is under 50 bytes. DNS tunneling tools encode data as long subdomains like `dGhpcyBpcyBhIHRlc3Q=.evil.com` which produces abnormally large query sizes.
- **`sid:9000005`** — unique rule ID in the local custom range.
- **`rev:1`** — rule revision 1.

**Example scenario it catches:**
A tool like `iodine` or `dnscat2` encoding exfiltrated data as base64 subdomains — `SGVsbG8gV29ybGQ=.attacker.com` — producing DNS queries well over 200 bytes.

**Fails against:**
- **Small payload encoding** — splitting data into multiple short queries each under 200 bytes
- **DNS over HTTPS (DoH)** — DNS queries sent over HTTPS to resolvers like 8.8.8.8 are encrypted HTTP traffic, invisible to this rule
- **Low and slow exfiltration** — a few bytes per query over a long period of time

---

---

## Part 5b: Loading the Rules into Suricata

Now that all 5 rules are written, here is how to load them and verify Suricata is enforcing them.

### Step 1 — Paste the Rules into custom.rules

```bash
nano /etc/suricata/rules/custom.rules
```

Paste all rules — the two `pass` rules first, then the five alert rules:

```
pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
alert tcp $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:2;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:2;)
```

Save and exit: `Ctrl+X` → `Y` → `Enter`

### Step 1b — Remove suricata.rules from rule-files

By default `suricata.yaml` loads the full Emerging Threats community ruleset (`suricata.rules`) which contains ~40,000 rules. On a single-core t2.micro this causes two problems:

- `suricata -T` config tests take 4-6 minutes to complete
- `fast.log` is flooded with community ruleset alerts, drowning out your 5 custom rules

For this lab remove `suricata.rules` so only your custom rules are loaded. Open `suricata.yaml`:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Find the `rule-files:` section — it looks like this by default:

```yaml
rule-files:
  - suricata.rules
```

Change it to:

```yaml
rule-files:
  - /etc/suricata/rules/custom.rules
```

Save and exit: `Ctrl+X` → `Y` → `Enter`

> **Note:** This is a lab-only decision. In a production environment you would keep `suricata.rules` for broad threat coverage and add `custom.rules` alongside it. Exercise 5 at the end of this post walks you through adding the ET ruleset back deliberately once you understand how your custom rules behave in isolation.

### Step 2 — Validate the Config

Always run the config test before restarting — a syntax error in `custom.rules` will prevent Suricata from starting.

> ⚠️ All Suricata commands must be run as root. If your prompt shows `ssm-user@` you have dropped out of the root shell. Run `sudo -i` to get back in before continuing.

```bash
sudo -i
suricata -T -c /etc/suricata/suricata.yaml -v
```

Look for:

```
Notice: suricata: Configuration provided was successfully loaded. Exiting.
```

If instead you see:

```
Error: suricata: The logging directory "/var/log/suricata/" is not writable. Shutting down the engine
```

This means you are not running as root. Run `sudo -i` and try again.

If you see an error referencing a `sid` number, that rule has a syntax problem — check it carefully for missing semicolons or mismatched quotes.

### Step 3 — Reload Suricata

```bash
systemctl restart suricata
systemctl status suricata
```

Confirm it is active and running — not in a failed state.

### Step 4 — Confirm Rules Are Loaded

After restarting, verify Suricata loaded only your 6 custom rules (5 alert rules + 1 pass rule):

```bash
sudo grep "rules loaded\|signatures processed" /var/log/suricata/suricata.log | tail -3
```

Expected output:

```
Info: detect: 6 signatures processed. 0 are IP-only rules, 2 are inspecting packet payload, 2 inspect application layer, 0 are decoder event only
```

`6 signatures processed` confirms only your custom rules are loaded. If you see a much larger number restart Suricata and check again:

```bash
sudo systemctl restart suricata
sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -1
```

> **Note on eve.json stats:** The `eve.json` file contains periodic stats entries that may show large `rules_loaded` numbers from previous Suricata sessions. Always use `suricata.log` to confirm the current session's rule count — it is more reliable than `eve.json` for this purpose.

Also verify `suricata.yaml` only loads your custom rules:

```bash
sudo grep -A5 "rule-files:" /etc/suricata/suricata.yaml
```

It should show only:

```yaml
rule-files:
  - /etc/suricata/rules/custom.rules
```

Also check the `last_reload` timestamp in `eve.json` stats events — it must be more recent than your last `systemctl restart` to confirm the new config is active:

```bash
sudo tail -1 /var/log/suricata/eve.json | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d['stats']['detect']['engines'][0]['last_reload'])"
```

### Step 5 — Watch the Alert Log in Real Time

Open a second terminal and tail `fast.log` — this is where Suricata writes one line per alert:

```bash
tail -f /var/log/suricata/fast.log
```

Leave this running while you trigger test traffic in Part 6. Every alert will appear here in real time as it fires.

For richer detail including the full packet metadata, tail `eve.json` instead:

```bash
tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

`eve.json` is newline-delimited JSON — piping through `python3 -m json.tool` pretty-prints each event so it is readable.

---

## Part 6: Test the Rules

### Setup — Two Terminals

Testing requires watching alerts fire in real time while generating test traffic. Open two terminal sessions connected to the instance via `lab-connect`.

**Terminal 1 — watch for alerts:**

```bash
sudo tail -f /var/log/suricata/fast.log
```

Leave this running. Every alert Suricata generates will appear here immediately.

> **Tip — Clear the log before testing:** If `fast.log` already has entries from previous sessions, clear it first so you only see alerts from your test traffic. Use `truncate` rather than `rm` — Suricata keeps the file handle open and deleting it would stop logging:
> ```bash
> sudo truncate -s 0 /var/log/suricata/fast.log
> ```

**Terminal 2 — generate test traffic** (commands below).

---

### Understanding fast.log Output

Each alert line in `fast.log` follows this format:

```
TIMESTAMP  [**] [GID:SID:REV] MESSAGE [**] [Classification] [Priority] {PROTO} SRC_IP:PORT -> DST_IP:PORT
```

For example:

```
03/18/2026-18:22:58.822948  [**] [1:9000004:1] Possible C2 Beaconing Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:43900 -> 169.254.169.254:80
```

Breaking this down:
- `03/18/2026-18:22:58` — timestamp
- `[1:9000004:1]` — GID 1, SID 9000004 (your Rule 4), revision 1
- `Possible C2 Beaconing Detected` — the `msg` field from the rule
- `{TCP}` — protocol
- `172.31.23.15:43900 -> 169.254.169.254:80` — source IP:port → destination IP:port

---

### Rule 4 Already Firing — A Real False Positive

Before even running any test traffic, Rule 4 fires immediately after Suricata starts:

```
03/18/2026-18:22:58.822948  [**] [1:9000004:1] Possible C2 Beaconing Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:43900 -> 169.254.169.254:80
03/18/2026-21:27:58.844144  [**] [1:9000004:2] Possible C2 Beaconing Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:44068 -> xx.xxx.xx.xxx:443
03/18/2026-21:29:35.909465  [**] [1:9000004:2] Possible C2 Beaconing Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:34952 -> xx.xxx.xx.xxx:443
```

Firing every few minutes to multiple AWS endpoints — `169.254.169.254:80`, `xx.xxx.xx.xxx:443`, `xx.xxx.xx.xxx:443`, and others on port 443.

**This is a false positive.** Two things are happening:

- `169.254.169.254` is the **AWS EC2 Instance Metadata Service (IMDS)** — every EC2 instance contacts it regularly over HTTP to retrieve metadata and IAM credentials
- The other IPs (`xx.xxx.xx.xxx`, `xx.xxx.xx.xxx`, etc.) are **AWS SSM and CloudWatch endpoints** — the SSM Agent and other AWS services make regular HTTPS calls to these on port 443

From Suricata's perspective all of these look identical to C2 beaconing. This is a perfect real-world example of why **whitelisting matters in production IDS work**.

The fix is two `pass` rules — one for IMDS (HTTP) and one for all outbound HTTPS to AWS services. **Both must be placed at the very top of `custom.rules` — before all alert rules.** Suricata processes rules in order from top to bottom. If Rule 4 matches first it fires before ever reaching the `pass` rules.

Your final `custom.rules` file should look exactly like this:

```
pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
alert tcp $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:2;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:2;)
```

After saving, validate and restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl restart suricata
sudo truncate -s 0 /var/log/suricata/fast.log
```

> **Confirming the fix works:** After restarting, `fast.log` should be empty — no more C2 beaconing noise from AWS services. When you run the test curl commands below, only your genuine attack payloads should appear.

---

### Test Rule 1 — SQL Injection UNION SELECT

In Terminal 2, clear the log first then send a curl request with a UNION SELECT payload:

```bash
sudo truncate -s 0 /var/log/suricata/fast.log
curl -v -G "http://172.31.23.15/" --data-urlencode "id=1' UNION SELECT username,password FROM users--"
sudo cat /var/log/suricata/fast.log
```

> **If `fast.log` is empty:** Check that `lo` is listed in the `af-packet` section of `suricata.yaml` alongside `enX0`. Traffic from `curl` on the same instance routes through `lo`, not `enX0`. Without `lo` in the config Suricata never sees the request. After adding it restart Suricata before retesting.

Expected alert:

```
03/18/2026-20:37:50.935403  [**] [1:9000001:4] SQL Injection UNION SELECT Attempt [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:32850 -> 172.31.23.15:80
```

---

### Test Rule 2 — SQL Injection Comment Bypass

```bash
sudo truncate -s 0 /var/log/suricata/fast.log
curl -v "http://172.31.23.15/?id=1%27%20OR%201%3D1--"
sudo cat /var/log/suricata/fast.log
```

Expected alert:

```
03/18/2026-21:24:54.092935  [**] [1:9000002:6] SQL Injection Comment Bypass Attempt [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:36692 -> 172.31.23.15:80
```

---

### Test Rule 3 — Port Scan

Use `nmap` to send a burst of SYN packets. Three important requirements:
- Use `sudo` — a SYN scan (`-sS`) requires raw socket privileges
- Scan the instance's **real IP** (`172.31.23.15`) not `127.0.0.1` — the destination must fall within `$HOME_NET` for the rule to match
- Use `--max-rate 10` to limit nmap to 10 packets per second — if nmap fires too fast Suricata cannot track the threshold on a single-core t2.micro and no alert fires

```bash
sudo apt-get install nmap -y
sudo truncate -s 0 /var/log/suricata/fast.log
sudo nmap -sS --max-rate 10 172.31.23.15
sudo cat /var/log/suricata/fast.log
```

Expected output — one alert per port probed, showing the scan working through many different destination ports from the same source IP:

```
03/18/2026-22:07:29.315182  [**] [1:9000003:3] Possible Port Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:36871 -> 172.31.23.15:1720
03/18/2026-22:07:29.815169  [**] [1:9000003:3] Possible Port Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:36871 -> 172.31.23.15:139
03/18/2026-22:07:30.315156  [**] [1:9000003:3] Possible Port Scan Detected [**] [Classification: (null)] [Priority: 3] {TCP} 172.31.23.15:36871 -> 172.31.23.15:587
...
```

Notice the same source port (`36871`) hitting many different destination ports — that is the signature of a port scan. The threshold of 5 SYN packets in 10 seconds fires once the scan hits 5 ports, then continues firing as the scan progresses.

---

### Test Rule 5 — DNS Tunneling

Use `dig` to send a large DNS query. Each DNS label (the part between dots) has a maximum length of 63 characters — split the payload across multiple labels to stay within the limit while exceeding 200 bytes total:

```bash
sudo apt-get install dnsutils -y
sudo truncate -s 0 /var/log/suricata/fast.log
dig $(python3 -c "print('A'*60 + '.' + 'B'*60 + '.' + 'C'*60)").google.com @8.8.8.8
sudo cat /var/log/suricata/fast.log
```

This creates a domain with three 60-character labels — `AAAA...60.BBBB...60.CCCC...60.google.com` — well over 200 bytes total while staying within the 63-character per-label DNS limit.

> **Why not one long string?** DNS labels are limited to 63 characters each. `'A'*180 + '.google.com'` produces `label too long` error. Splitting across three labels of 60 characters each produces the same large payload while being a valid DNS name.

Expected alert:

```
03/18/2026-22:28:42.595604  [**] [1:9000005:2] Possible DNS Tunneling - Large Query [**] [Classification: (null)] [Priority: 3] {UDP} 172.31.23.15:60507 -> 8.8.8.8:53
```

Notice the protocol is `{UDP}` and the destination is `8.8.8.8:53` — confirming Suricata caught the large DNS query going out to Google's public resolver.

---

## Part 7: PCAP Analysis

As SAED — a Security Engineer at Google — notes: whether it is Wireshark or tcpdump, the core function is analysing network traffic for threats. This section uses `tcpdump` directly on the instance to capture and examine the same attack traffic that triggered the Suricata rules in Part 6.

### Capture Traffic to a PCAP File

Run `tcpdump` while generating attack traffic in a second terminal. The `-w` flag writes raw packets to a file for later analysis:

```bash
sudo tcpdump -i lo -w /tmp/lab_capture.pcap &
```

The `&` runs it in the background. Now generate all the test traffic:

```bash
curl -v -G "http://172.31.23.15/" --data-urlencode "id=1' UNION SELECT username,password FROM users--"
curl -v "http://172.31.23.15/?id=1%27%20OR%201%3D1--"
sudo nmap -sS --max-rate 10 172.31.23.15 -p 1-100
dig $(python3 -c "print('A'*60 + '.' + 'B'*60 + '.' + 'C'*60)").google.com @8.8.8.8
```

Stop the capture:

```bash
sudo pkill tcpdump
```

---

### Analyse the PCAP with tcpdump Filters

**View all captured packets (summary):**

```bash
sudo tcpdump -r /tmp/lab_capture.pcap
```

**Filter 1 — SQL Injection traffic (HTTP on port 80):**

```bash
sudo tcpdump -r /tmp/lab_capture.pcap -A 'tcp port 80' | grep -i "UNION\|SELECT\|OR"
```

The `-A` flag prints packet contents in ASCII. Real output from this lab:

```
01:25:37.636597 IP ip-172-31-26-99.56868 > ip-172-31-26-99.http: Flags [P.], length 130: HTTP: GET /?id=1%27+UNION+SELECT+username%2cpassword+FROM+users-- HTTP/1.1
GET /?id=1%27+UNION+SELECT+username%2cpassword+FROM+users-- HTTP/1.1

01:28:04.908873 IP ip-172-31-26-99.48712 > ip-172-31-26-99.http: Flags [P.], length 99: HTTP: GET /?id=1%27%20OR%201%3D1-- HTTP/1.1
GET /?id=1%27%20OR%201%3D1-- HTTP/1.1
```

`Flags [P.]` is the PSH+ACK flag — this is a data-carrying packet containing the HTTP request payload, not a handshake packet. The full SQL injection strings are readable in plaintext directly from the packet bytes — exactly what Suricata's `content` matching inspects.

**Filter 2 — Port Scan (SYN packets only):**

```bash
sudo tcpdump -r /tmp/lab_capture.pcap 'tcp[tcpflags] == tcp-syn'
```

`tcp[tcpflags] == tcp-syn` is a Berkeley Packet Filter (BPF) expression matching only SYN-flagged packets — the same condition as `flags:S` in the Suricata rule. Real output:

```
01:28:36.551927 IP ip-172-31-26-99.58404 > ip-172-31-26-99.smtp:   Flags [S]
01:28:36.641851 IP ip-172-31-26-99.58404 > ip-172-31-26-99.http:   Flags [S]
01:28:36.741904 IP ip-172-31-26-99.58404 > ip-172-31-26-99.ssh:    Flags [S]
01:28:36.841903 IP ip-172-31-26-99.58404 > ip-172-31-26-99.domain: Flags [S]
01:28:36.941878 IP ip-172-31-26-99.58404 > ip-172-31-26-99.telnet: Flags [S]
01:28:37.041880 IP ip-172-31-26-99.58404 > ip-172-31-26-99.ftp:    Flags [S]
```

The port scan fingerprint is unmistakable — same source port `58404` hitting smtp, http, ssh, domain, telnet, ftp in sequence, one every 100ms. Also note the PTR reverse DNS lookup immediately before the scan starts — nmap resolving the target IP to a hostname, another reconnaissance indicator.

**Filter 3 — DNS queries:**

```bash
sudo tcpdump -r /tmp/lab_capture.pcap -v 'udp port 53'
```

Real output:

```
01:26:38.113545 localhost.60801 > _localdnsstub.domain: A? ssm.us-east-1.amazonaws.com. (56)
01:26:38.115187 _localdnsstub.domain > localhost.60801: ssm.us-east-1.amazonaws.com. A xx.xxx.xx.xxx (72)

01:28:36.539101 localhost.39780 > _localdnsstub.domain: PTR? 99.26.31.172.in-addr.arpa. (43)
01:28:36.541638 _localdnsstub.domain > localhost.39780: PTR ip-172-31-26-99.ec2.internal. (85)
```

Two DNS patterns visible: the SSM Agent resolving `ssm.us-east-1.amazonaws.com` (legitimate — the C2 false positive source), and nmap doing a PTR reverse lookup before scanning. Note the packet sizes — 56-85 bytes, all under the 200-byte threshold in Rule 5.

---

### What the PCAP Tells You

Comparing the PCAP analysis against the Suricata alerts reveals three key insights:

**1 — Suricata sees the decoded HTTP payload.** The SQL injection strings appear in plaintext in the PCAP because HTTP is unencrypted. `GET /?id=1%27+UNION+SELECT...` is readable directly from the packet bytes. This confirms why Rules 1 and 2 work — and why they would both fail against HTTPS where the payload is encrypted.

**2 — Port scans have a clear fingerprint.** Source port `58404` hitting smtp → http → ssh → domain → telnet → ftp in order, every 100ms. The nmap PTR reverse lookup appearing just before the scan also confirms reconnaissance intent. This pattern looks nothing like normal traffic.

**3 — DNS packet sizes reveal tunneling.** The legitimate DNS queries in the capture — SSM Agent lookups for `ssm.us-east-1.amazonaws.com` — are all 56-84 bytes. A real DNS tunneling query with a 180-byte subdomain would stand out immediately. The `dsize:>200` threshold in Rule 5 exploits this size difference.

**4 — The false positive source is confirmed.** The PCAP shows the SSM Agent resolving `ssm.us-east-1.amazonaws.com` every few minutes and connecting to `xx.xxx.xx.xxx:443`. This is the traffic that was triggering Rule 4 — now whitelisted by the `pass tcp $HOME_NET any -> any 443` rule.

### Summary — Three Attack Patterns in One PCAP

| Timestamp | Traffic Type | PCAP Indicator |
|---|---|---|
| 01:25:37 | SQL Injection UNION SELECT | `GET /?id=1%27+UNION+SELECT...` in HTTP payload |
| 01:28:04 | SQL Injection OR bypass | `GET /?id=1%27%20OR%201%3D1--` in HTTP payload |
| 01:28:36 | Port scan | Source port 58404, SYN to smtp/http/ssh/telnet/ftp in sequence |
| 01:26:38+ | AWS SSM beaconing (legitimate) | DNS A? ssm.us-east-1.amazonaws.com + HTTPS to AWS IPs |

`tcpdump` and Suricata are complementary tools — Suricata tells you something is wrong, `tcpdump` shows you exactly what it was at the packet level.

---

### Downloading the PCAP for Wireshark Analysis (Optional)

If you want to open the PCAP in Wireshark on your local machine, copy it to S3 first:

```bash
# On the instance — replace with your own bucket name
aws s3 cp /tmp/lab_capture.pcap s3://your-bucket-name/lab_capture.pcap

# On your local machine
aws s3 cp s3://your-bucket-name/lab_capture.pcap ~/Downloads/lab_capture.pcap --profile lab-sso
```

Open `lab_capture.pcap` in Wireshark and apply the same filters:
- HTTP traffic: `tcp.port == 80`
- SYN scans: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
- Large DNS queries: `dns && frame.len > 200`

---

## Part 8: AWS Network Firewall Connection

A key insight worth highlighting: **Suricata rule syntax IS the AWS Network Firewall rule language.**

As of November 2020, AWS Network Firewall uses Suricata-compatible IPS rules natively. Every rule written in this lab is directly portable to AWS Network Firewall with no modifications required.

Source: [AWS Open Source Blog — Scaling Threat Prevention on AWS with Suricata](https://aws.amazon.com/blogs/opensource/scaling-threat-prevention-on-aws-with-suricata/)

This means learning Suricata rule syntax in a personal lab is not just an academic exercise — it is the exact same skill used to configure production-grade network threat prevention in AWS.

---

### What is AWS Network Firewall?

AWS Network Firewall is a managed network security service that sits at the VPC perimeter and inspects traffic flowing in and out of your AWS infrastructure. Unlike a security group (which operates at the instance level with simple allow/deny rules) or a WAF (which operates at the HTTP application layer), Network Firewall operates at the network layer and can inspect full packet payloads — including the kind of deep packet inspection Suricata performs.

| Tool | Layer | What it inspects |
|---|---|---|
| Security Group | Network (L3/L4) | IP, port, protocol — no payload |
| AWS WAF | Application (L7) | HTTP headers, URI, body |
| AWS Network Firewall | Network + Application (L3-L7) | Full packet payload using Suricata rules |

---

### Porting Your Rules to AWS Network Firewall

The 5 rules from this lab are directly usable in AWS Network Firewall. Here is how you would deploy them:

**Step 1 — Create a rule group in the AWS Console:**

```
AWS Console → VPC → Network Firewall → Rule groups
→ Create rule group
→ Rule group type: Stateful
→ Rule order: Default action order
→ Capacity: 100
→ Rules format: Suricata compatible rule string
```

**Step 2 — Paste your rules directly:**

```
pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
alert tcp $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:2;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:2;)
```

**Step 4 — Configure advanced settings (optional)**

Leave "Customize encryption settings (advanced)" unchecked. AWS encrypts your rule group data at rest using an AWS managed key by default — sufficient for a personal lab. Customer managed KMS keys are for production environments with compliance requirements (PCI-DSS, HIPAA) where you need audit trails of key usage.

Click **Next**.

**Step 5 — Add tags (optional)**

Skip for a personal lab. Click **Next**.

**Step 6 — Review and create**

Verify:
- Rule group type: Stateful, Suricata compatible rule string
- Name: `suricata-lab-rules`
- Capacity: `100`
- Rule variables: `HOME_NET` IP set showing `172.31.16.0/20`
- All 7 rules visible in the Suricata compatible rule string section
- Customer managed key: AWS owned key

Click **Create rule group**.

---

### Important: Creating the Rule Group Is Not Enough

Creating `suricata-lab-rules` saves your ruleset in AWS but does **not** automatically enforce it on your VPC or any EC2 instances you launch. Three additional steps are required before traffic is actually inspected:

**1 — Create a Firewall Policy** — a container that references one or more rule groups including `suricata-lab-rules`.

**2 — Create a Network Firewall** — the actual firewall resource deployed into a subnet inside your VPC, with the firewall policy attached to it.

**3 — Update VPC Route Tables** — the most critical step. You must redirect traffic through the firewall by updating your route tables. Without this, traffic bypasses the firewall entirely even if it is deployed and running.

**Why this lab stops at rule group creation:** AWS Network Firewall is designed for production VPC architectures with proper subnet segmentation, internet gateways, and routing. Fully deploying it in a single-subnet personal lab is architecturally complex and costs approximately $0.395/hour for the firewall endpoint alone — which adds up quickly on a free tier account.

The value of this exercise is demonstrating that your Suricata rules are valid AWS Network Firewall rules — directly portable from your personal lab to production AWS infrastructure. The full VPC security architecture required to deploy Network Firewall end-to-end is a Week 49-50 topic (Cloud Security Mastery phase).

---

### IDS vs IPS Mode

In this lab Suricata ran in **IDS mode** — it inspected traffic and generated alerts but did not block anything. AWS Network Firewall runs in **IPS mode** by default — it can actively drop packets that match your rules.

| Mode | Action on match | Use case |
|---|---|---|
| IDS (alert) | Log and alert only | Learning, tuning, baseline establishment |
| IPS (drop) | Block the traffic | Production enforcement |

The typical progression is: run in IDS mode first to tune your rules and eliminate false positives, then switch to IPS mode once you are confident the rules are accurate. Deploying IPS rules with false positives in production will block legitimate traffic.

---

### Why This Matters for Security Engineering

Understanding that Suricata rules are portable to AWS Network Firewall positions you to:

- Write detection rules in a free personal lab and deploy them directly to production AWS infrastructure
- Contribute to an organization's AWS Network Firewall ruleset using the same skills tested in this lab
- Discuss network-layer threat detection intelligently in Security Engineering interviews — the gap between "I ran Suricata in a lab" and "I understand how this maps to production cloud infrastructure" is exactly what separates strong candidates

---

## Common Issues and Fixes

### Disabling a Rule Without Deleting It

Comment out the rule with `#` at the start of the line:

```bash
sudo nano /etc/suricata/rules/custom.rules
```

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; ...)
# alert http $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; ...)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; ...)
```

The `#` tells Suricata to ignore that line entirely — the rule is preserved for future use but not loaded into the detection engine.

### Reloading Rules Without Restarting Suricata

For a personal lab, the simplest approach is always:

```bash
sudo systemctl restart suricata
```

In **production** environments where you cannot afford dropped packets or downtime during a rule update, two zero-downtime options exist:

```bash
# Option 1 — send USR2 signal to the running process
sudo kill -USR2 $(cat /var/run/suricata.pid)

# Option 2 — use the Suricata socket command
sudo suricatasc -c ruleset-reload-nonblocking
```

Both hot-swap rules into the running detection engine without interrupting traffic inspection — relevant when Suricata is running on a live network at a cloud provider or enterprise SOC where restarting would cause a monitoring gap.

Verify the reload worked by checking the rule count:

```bash
sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -3
```

---

### Suricata Config Test Requires Root

Running `suricata -T` as a normal user returns a permission denied error. Always run config tests as root:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
```

---

### Rules Not Firing on Self-Generated Traffic

**Symptom:** curl requests to the instance's own IP return 200 OK but `fast.log` stays empty.

**Cause:** Linux kernel local routing — when a process connects to the machine's own IP address, traffic routes through the loopback interface `lo` rather than `enX0`. Suricata only monitoring `enX0` never sees it.

**Fix:** Add `lo` to the `af-packet` section in `suricata.yaml`:

```yaml
af-packet:
  - interface: enX0
  - interface: lo
```

Restart Suricata after making this change.

---

### 49,000+ Rules Loaded Instead of Your Custom Rules

**Symptom:** `suricata.log` shows tens of thousands of signatures loaded instead of your custom rule count.

**Cause:** The `rule-files:` section in `suricata.yaml` still references `suricata.rules` (the Emerging Threats ruleset) alongside your custom rules file.

**Fix:** Edit `suricata.yaml` to only reference your custom rules:

```yaml
rule-files:
  - /etc/suricata/rules/custom.rules
```

Always verify with:

```bash
sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -1
```

---

### eve.json Shows Large Rule Counts from Previous Sessions

**Symptom:** `grep "rules_loaded" /var/log/suricata/eve.json` shows 49,000+ rules even after fixing `suricata.yaml`.

**Cause:** `eve.json` contains periodic stats entries from all previous Suricata sessions — including old runs with the full ET ruleset. It does not reflect the current session accurately.

**Fix:** Always use `suricata.log` not `eve.json` to confirm the current session's rule count. If needed, parse `eve.json` line by line:

```bash
sudo tail -20 /var/log/suricata/eve.json | while read line; do echo $line | python3 -m json.tool 2>/dev/null; done
```

---

### HTTP Rules Not Matching URL-Encoded Payloads

**Symptom:** Rules using `protocol http` with `content:"UNION"` do not fire on curl requests containing `UNION%20SELECT`.

**Cause:** Suricata's `http` protocol keyword applies content matching to normalized HTTP buffers. Without specifying the correct buffer (`http_uri`, `http_client_body`, etc.) the match may not hit the right place.

**Fix:** Switch to `tcp` protocol with `port 80` which matches raw TCP stream bytes directly:

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
```

---

### Port Scan Rule Not Firing

**Symptom:** nmap scan completes but no alert appears in `fast.log`.

**Two common causes:**

1. **Scanning `127.0.0.1` instead of the real IP** — the destination must fall within `$HOME_NET`. Use the instance's real IP (e.g. `172.31.23.15`).

2. **nmap firing too fast for a single-core t2.micro** — use `--max-rate 10` to limit nmap to 10 packets per second, and lower the threshold to `count 5`:

```bash
sudo nmap -sS --max-rate 10 172.31.23.15
```

---

### C2 Beaconing False Positives from AWS Services

**Symptom:** Rule 4 fires immediately after Suricata starts, alerting on traffic to `169.254.169.254` and various port 443 endpoints.

**Cause:** The SSM Agent, CloudWatch, and other AWS services make regular outbound HTTPS calls that match the beaconing threshold. These are legitimate AWS service endpoints.

**Fix:** Add two `pass` rules at the top of `custom.rules` — before all alert rules:

```
pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)
```

Pass rules must come first — Suricata processes rules top to bottom and stops at the first match.

---

### DNS Label Too Long Error

**Symptom:** `dig: 'AAAA...180chars.google.com' is not a legal name (label too long)`

**Cause:** DNS labels (the parts between dots) have a maximum length of 63 characters. A single string of 180 A's exceeds this.

**Fix:** Split across multiple 60-character labels:

```bash
dig $(python3 -c "print('A'*60 + '.' + 'B'*60 + '.' + 'C'*60)").google.com @8.8.8.8
```

---

## Practice Exercises

These five exercises test the core Suricata skills a Security Engineer specializing in web application and cloud security is expected to have. No installation required — read, analyze, and answer.

---

### Exercise 1 — Read and Interpret

Given this rule you have never seen before, explain in plain English what it does, what attack it is designed to detect, and what each keyword means:

```
alert http any any -> $HOME_NET any (msg:"Possible XSS Attempt"; flow:to_server,established; content:"<script>"; nocase; http_uri; sid:9000010; rev:1;)
```

Answer these questions:
1. What protocol does this rule inspect?
2. What direction is traffic flowing?
3. What string is it looking for and where specifically (`http_uri` is a new keyword — what do you think it does)?
4. What attack is this trying to detect?
5. Name one way an attacker could evade this rule.

---

### Exercise 2 — Modify: Tune a Threshold

The port scan rule from this post is generating too many false positives on a busy web server that receives high volumes of legitimate connection attempts from load balancers.

Original rule:
```
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
```

**Task:** Modify the rule to reduce false positives by:
1. Raising the threshold so it only alerts when a single source IP sends more than 50 SYN packets within 10 seconds
2. Narrowing the destination to only flag scans targeting ports below 1024 (well-known ports) — hint: use `port` ranges in the destination field
3. Increment the `rev` number to reflect the modification

Write the modified rule.

---

### Exercise 3 — Enable, Disable, and Organize

You have the following three rules in `/etc/suricata/rules/custom.rules`. The C2 beaconing rule (sid:9000004) is generating hundreds of false positives because your monitoring tool makes frequent outbound HTTP calls.

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
alert http $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:1;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:1;)
```

**Task:**
1. Disable the C2 beaconing rule without deleting it — how do you do this in Suricata?
2. Reload the rules without restarting Suricata entirely — what command do you use?
3. Verify the rule is disabled — where do you look to confirm it is no longer generating alerts?

---

### Exercise 4 — Keyword Identification

For each behavior described below, identify which Suricata keyword is responsible for it in the rules from this post:

| Behavior | Keyword |
|---|---|
| Only fires after 5 matching packets from the same source in 10 seconds | ? |
| Makes string matching case-insensitive | ? |
| Restricts the rule to outbound traffic from your subnet | ? |
| Ensures a second content match starts immediately after the first with zero bytes between them | ? |
| Matches UDP packets larger than 200 bytes | ? |
| Only applies to established TCP connections flowing toward the server | ? |
| Allows matching traffic to pass without triggering any alert rules below it | ? |

> **Note on the fourth row:** The keyword `distance:0` enforces that a second `content` match must appear immediately after the first — zero bytes between them. For example `content:"UNION"; content:"SELECT"; distance:0;` would only match `UNIONSELECT` not `UNION SELECT` (with a space). This keyword was part of the original Rule 1 design in this lab but was removed after it prevented the rule from firing on URL-encoded payloads where a `+` or `%20` separates the words. In production rules you would handle this with `pcre` instead.

---

### Exercise 5 — Community Rulesets

> ⚠️ **Before starting this exercise:** If you re-enabled the C2 beaconing rule (sid:9000004) at any point, comment it out again now. The ET ruleset loaded in this exercise generates significant alert volume and the C2 rule will produce dozens of false positives from AWS services that will make it difficult to observe what the ET ruleset is doing. Keep it commented out until you have fully whitelisted all legitimate AWS traffic.

Emerging Threats (ET) is one of the most widely used open source Suricata/Snort ruleset providers. Their rules cover thousands of known attack patterns, malware families, and CVEs.

**Task — run these steps in order:**
1. Run `suricata-update list-sources` on your instance — how many rule sources are available by default?
2. Enable the Emerging Threats Open ruleset: `sudo suricata-update enable-source et/open`
3. Update and reload — **both commands must complete before checking the rule count:**
```bash
sudo suricata-update
sudo systemctl restart suricata
```
4. Count how many rules are now loaded by checking the Suricata log — run this *after* Step 3:
```bash
sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -1
```
You should see tens of thousands of signatures, not 6. If you still see 6, Step 3 did not complete successfully — check `suricata-update` output for errors.

5. Find the ET rules related to SQL injection:
```bash
grep -i "sql injection" /var/lib/suricata/rules/suricata.rules | wc -l
```
How many rules does ET have for SQL injection compared to the 2 you wrote?

Reflect: what is the tradeoff between using a large community ruleset versus writing your own targeted rules?

These exercises are part of an open source repository of LeetCode-style **secure coding exercises** designed to:

1. Train developers to write secure code
2. Prepare security engineers for technical interviews

Every exercise in the repo has 60+ test cases and a companion Dev.to post.

**If this post was useful, the best thing you can do is star the repo:**

**👉 [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

---

## One More Thing — Quick Poll

Why do you read security engineering blog posts? Your answer helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)**

Takes 10 seconds.

---

## Answer Key

### Exercise 1

1. HTTP protocol.

2. Traffic flows from the public internet to the home network.

3. The Suricata rule is looking for the existence of an XSS payload within the submitted URL. That is what `http_uri` represents: the submitted URL. Judging by the filtering for the `<script>` tag the rule is looking for XSS attacks targeting HTML bodies or HTML attributes.

4. See previous answer.

5. The attacker can apply percent encoding to evade this rule.

---

### Exercise 2

```
alert tcp any any -> $HOME_NET 1:1024 (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 50,seconds 10; sid:9000003; rev:4;)
```

---

### Exercise 3

Disabled rule:

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
# alert http $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:1;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:1;)
```

I used `systemctl restart suricata` because there is no point in doing this in a way that is more complicated. To verify the false positives no longer appear:

```bash
sudo systemctl restart suricata
sudo truncate -s 0 /var/log/suricata/fast.log
sudo cat /var/log/suricata/fast.log
```

Since there was no output of "Possible C2 Beaconing Detected" the above tactic worked.

---

### Exercise 4

| Behavior | Answer |
|---|---|
| Only fires after 5 matching packets from the same source in 10 seconds | `count 5,seconds 10` |
| Makes string matching case-insensitive | `nocase` |
| Restricts the rule to outbound traffic from your subnet | `pass tcp $HOME_NET any -> any any` |
| Ensures a second content match starts immediately after the first with zero bytes between them | `distance:0` |
| Matches UDP packets larger than 200 bytes | `alert udp any any -> any 53 (...dsize:>200)` |
| Only applies to established TCP connections flowing toward the server | `flow:to_server,established` |
| Allows matching traffic to pass without triggering any alert rules below it | Place a rule using the `pass` keyword at the top of the rules file |

---

### Exercise 5

**Part 1 — 22 sources available:**

```
root@ip-172-31-24-247:~# suricata-update list-sources | grep -i "Name"
Name: et/open
Name: et/pro
Name: oisf/trafficid
Name: scwx/enhanced
Name: scwx/malware
Name: scwx/security
Name: abuse.ch/sslbl-blacklist
Name: abuse.ch/sslbl-ja3
Name: abuse.ch/feodotracker
Name: abuse.ch/urlhaus
Name: etnetera/aggressive
Name: tgreen/hunting
Name: stamus/lateral
Name: stamus/nrd-30-open
Name: stamus/nrd-14-open
Name: stamus/nrd-entropy-30-open
Name: stamus/nrd-entropy-14-open
Name: stamus/nrd-phishing-30-open
Name: stamus/nrd-phishing-14-open
Name: pawpatrules
Name: ptrules/open
Name: aleksibovellan/nmap
```

**Part 4 — Rule count after enabling ET:**

```
root@ip-172-31-24-247:~# sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -1
[875 - Suricata-Main] 2026-03-21 18:31:15 Info: detect: 6 signatures processed.
```

**Part 5 — ET SQL injection rules:**

```
root@ip-172-31-24-247:~# grep -i "sql injection" /var/lib/suricata/rules/suricata.rules | wc -l
4361
```

ET has 4,361 SQL injection rules compared to the 2 written in this post.

**Reflection:**

The first consequence of using a community ruleset is that it becomes difficult, if not impossible, for each individual to audit and verify the correctness of all rules. The ET ruleset alone has 4,361 SQL injection rules — which cannot be audited by one person in a day. The benefit is that one can rely on others for coverage, but if the ruleset is too large the user must question whether that person can be trusted to devise a secure, responsible ruleset. This is a reminder of Thompson's *Reflections on Trusting Trust* — at some point you are trusting the compiler, the ruleset author, or the package maintainer.

The alternative is to build your own rules from scratch — but achieving comprehensive coverage takes far more time than using a community ruleset.

---

*Series: Security Engineering Interview Prep | Week 9 Part 2 | March 2026*
*GitHub: [fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)*
