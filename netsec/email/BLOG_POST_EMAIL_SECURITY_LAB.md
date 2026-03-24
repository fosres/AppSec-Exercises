---
title: "Week 9 Lab: How Security Engineers Actually Analyze Email Security (No Python)"
published: false
description: "Five hands-on exercises using the real tools Security Engineers use every day to investigate phishing — MXToolbox, dig, urlscan.io, VirusTotal, and AbuseIPDB."
tags: security, phishing, emailsecurity, blueteam
---

# Week 9 Lab: How Security Engineers Actually Analyze Email Security

**Time:** 2 hours  
**Difficulty:** Beginner–Intermediate  
**Tools Required:** A terminal, a browser. Nothing to install.  
**Skills:** Email header forensics, DNS enumeration, threat intelligence lookups, IOC triage

---

## The Honest Setup

Most tutorials about email security hand you a Python script and tell you to parse headers with `re.search()`. That is not what a Security Engineer does on the job.

When a suspicious email lands in your SOC queue — because an employee clicked "Report Phishing," or your email gateway flagged something, or your SIEM fired an alert — you open a browser and a terminal. You use tools that were built specifically for this job. You read output and make a decision.

This lab gives you five exercises built around those exact tools. Each one maps to a real task in a real phishing investigation workflow. By the end you will have triaged a realistic phishing email from start to finish, the way a Security Engineer would actually do it.

---

## Background: What You Need to Know First

Before the exercises, read these. Each one is short.

**RFC 7208 §1–3 (SPF)** — https://datatracker.ietf.org/doc/html/rfc7208#section-2  
Focus on the qualifier meanings: `+Pass`, `-Fail`, `~SoftFail`, `?Neutral`. Understand why `~SoftFail` is not an enforcement mechanism — it means "probably forged, but accept anyway."

**RFC 7489 §3–5 (DMARC)** — https://datatracker.ietf.org/doc/html/rfc7489#section-3  
Focus on the three policy values: `p=none` (monitor only, no enforcement), `p=quarantine` (send to spam), `p=reject` (block the message). Nearly half of Fortune 500 domains still use `p=none`. That is why phishing works.

**Cloudflare: What is email security?** — https://www.cloudflare.com/learning/email-security/  
A 10-minute prose overview of SPF, DKIM, DMARC, and Business Email Compromise (BEC). Read this before the RFCs if the RFC prose feels dense.

---

## The Scenario

Your SOC queue has a ticket. An employee at `your-company.com` forwarded a suspicious email to `phishing-reports@your-company.com`. The subject line is:

> **"ACTION REQUIRED: Your PayPal account has been limited — verify now"**

The employee did not click any links. Your job is to determine: is this a real phishing email, or a legitimate PayPal notification that triggered a false alarm?

Below is the raw email header block. You will use it in Exercises 1–3.

```
Delivered-To: employee@your-company.com
Received: from mail-oi1-f226.google.com (mail-oi1-f226.google.com [209.85.167.226])
        by mx.your-company.com with ESMTPS id k12si4520836oib.91.2024.01.15.08.22.31
        for <employee@your-company.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jan 2024 08:22:31 -0800 (PST)
Received: from smtp-relay.paypa1-secure.com (smtp-relay.paypa1-secure.com [185.220.101.47])
        by mail-oi1-f226.google.com with ESMTP id s7si3214321oic.44.2024.01.15.08.22.30
        for <employee@your-company.com>;
        Mon, 15 Jan 2024 08:22:30 -0800 (PST)
Received: from localhost (localhost [127.0.0.1])
        by smtp-relay.paypa1-secure.com with ESMTP id xR7dK2mP9q
        Mon, 15 Jan 2024 16:22:28 +0000 (UTC)
Authentication-Results: mx.your-company.com;
        spf=fail (google.com: domain of service@paypal.com does not designate
        185.220.101.47 as permitted sender)
        smtp.mailfrom=service@paypal.com;
        dkim=none;
        dmarc=fail (p=REJECT) header.from=paypal.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=paypa1-secure.com; s=selector1;
        h=from:to:subject:date:message-id;
        b=Xk9mP2qR8vL5nT3wY7cB1jH6sD4aF0eU2iO9kN8mP1qR
From: "PayPal Security" <service@paypal.com>
Reply-To: verify-account@paypa1-secure.com
Return-Path: <bounce@paypa1-secure.com>
To: employee@your-company.com
Subject: ACTION REQUIRED: Your PayPal account has been limited -- verify now
Date: Mon, 15 Jan 2024 16:22:27 +0000
Message-ID: <xR7dK2mP9q@smtp-relay.paypa1-secure.com>
X-Mailer: PHPMailer 6.1.5 (https://github.com/PHPMailer/PHPMailer)
```

---

## Exercise 1: Read the Headers Manually

**Tool:** Your own eyes  
**Time:** 15 minutes  
**What a Security Engineer actually does:** Before touching any external tool, a good analyst reads the raw headers top to bottom and notes anomalies. External tools confirm what you spotted. They do not replace the reading.

### What to do

Read the header block above carefully. For each field below, write down what you find and whether it looks legitimate or suspicious. Do this before you scroll to the analysis notes.

| Field | What it says | Suspicious? |
|---|---|---|
| `From:` | | |
| `Return-Path:` | | |
| `Reply-To:` | | |
| `DKIM-Signature d=` | | |
| `Authentication-Results spf=` | | |
| `Authentication-Results dmarc=` | | |
| First `Received:` (originating IP) | | |
| `X-Mailer:` | | |

### Questions to answer

1. The `From:` header says `service@paypal.com`. Does the email actually come from PayPal's infrastructure? How do you know from the headers alone?
2. The `Reply-To:` and `Return-Path:` both point to `paypa1-secure.com`. What is the difference between that domain name and `paypal.com`? What attack technique is this?
3. The DKIM signature is present but signed by `d=paypa1-secure.com`, not `d=paypal.com`. What does that tell you?
4. `Authentication-Results` shows `dmarc=fail (p=REJECT)`. What does `p=REJECT` mean? Why did this email still reach the employee's inbox despite `p=REJECT`?
5. The originating IP in the second `Received:` header is `185.220.101.47`. What kind of infrastructure does that IP range belong to? (Hint: search it before Exercise 4.)
6. `X-Mailer: PHPMailer 6.1.5` — what does the presence of this header suggest about how this email was sent?

---

## Exercise 2: Paste the Headers Into MXToolbox

**Tool:** MXToolbox Email Header Analyzer — https://mxtoolbox.com/EmailHeaders.aspx  
**Time:** 10 minutes  
**What a Security Engineer actually does:** After the manual read, paste headers into MXToolbox to get an annotated relay chain and a visual SPF/DKIM/DMARC summary. This confirms your manual findings and catches relay hops you might have missed.

### What to do

1. Go to https://mxtoolbox.com/EmailHeaders.aspx
2. Paste the entire header block from the scenario above into the input box
3. Click **Analyze Header**

### Questions to answer

1. How many relay hops does MXToolbox show? Trace the path: where did the email originate, and what path did it take to reach the recipient?
2. MXToolbox highlights delayed hops in yellow or red. Is there any suspicious timing between hops?
3. What does MXToolbox show for the SPF result? Does it match what you read manually in Exercise 1?
4. Find the originating IP (`185.220.101.47`) in the MXToolbox output. Click through to the blacklist check — is this IP listed on any spam or abuse databases?

### Also try: Google Admin Toolbox

Google's header analyzer is at https://toolbox.googleapps.com/apps/messageheader/  
Paste the same headers. Compare the output to MXToolbox. Google's tool is better at visualizing relay timing delays, which are sometimes a sign that email was held in a queue on a botnet node before being forwarded.

---

## Exercise 3: Investigate the Suspicious Domain and URLs

**Tools:** PhishTank, urlscan.io, VirusTotal  
**Time:** 20 minutes  
**What a Security Engineer actually does:** Every domain and URL in a suspicious email gets submitted to a sandbox before anyone opens it. You never click a link in a reported phishing email directly.

### Part A — Get a real phishing URL from PhishTank

PhishTank (https://phishtank.org) is operated by Cisco Talos and is the canonical public database of community-verified phishing URLs. Every entry has been voted on by multiple analysts. Crucially, it tracks whether each URL is still **online** or has been taken down — which means you can pick a confirmed-offline URL that is safe to investigate without any risk of accidentally hitting a live credential-harvesting page.

1. Go to https://phishtank.org/phish_archive.php
2. Set the filters as follows:
   - **Target:** PayPal
   - **Valid:** Valid phishes
   - **Online:** Offline
3. Click **Search**
4. Pick any entry from the results and click through to its detail page

On the detail page you will find:
- The full phishing URL
- A screenshot of the page taken when it was live
- The submission timestamp and verification timestamp
- The community votes that confirmed it as a phish
- The PhishTank ID (a permanent reference number for the entry)

**Record the URL and PhishTank ID** — you will use them in Parts B and C.

### Part B — urlscan.io

Now take the phishing URL from Part A and look it up on urlscan.io.

1. Go to https://urlscan.io
2. In the search bar, paste just the **domain** portion of your PhishTank URL (e.g. if the URL is , search for )
3. If prior scans exist, open the most recent one

**Questions to answer:**

1. What does the urlscan.io screenshot show? Does it match the PhishTank screenshot, or has the page changed?
2. What IP address does the domain resolve to? What country and ASN does it belong to?
3. Look at the **Summary** tab — what verdict labels does urlscan.io apply?
4. Look at the **DOM** tab — does urlscan.io detect a login form? Any password fields?
5. Look at the **Network** tab — what external resources does the page load? Attackers often pull in legitimate PayPal CDN assets (logos, fonts, CSS) to make the fake page look authentic.

**If no urlscan.io results exist for this domain:**

This is a realistic outcome — many phishing domains are taken down before anyone submits them to urlscan.io. In a real investigation this means you pivot: go to VirusTotal and AbuseIPDB directly using the domain and IP instead. Note what the absence of a scan tells you about the domain's lifespan.

### Part C — VirusTotal

1. Go to https://www.virustotal.com
2. Search for the phishing **domain** from your PhishTank URL
3. Then separately search for the **IP address** you found in Part B

**Questions to answer:**

1. How many of VirusTotal's 90+ vendors flag this domain as malicious or phishing?
2. Click the **Relations** tab. What other domains, IPs, or files are associated with it? Does this reveal a broader phishing infrastructure — sibling domains registered by the same actor, or the same IP hosting multiple phishing pages?
3. Click the **Community** tab. Are there any analyst comments describing this campaign?
4. Now search for the originating IP `185.220.101.47` from the scenario headers — what does VirusTotal tell you about this IP? Does it have prior malicious associations?

---

## Exercise 4: DNS Email Policy Auditing With `dig`

**Tool:** `dig` (built into Linux and macOS; Windows users use `nslookup` or install `dig` via BIND tools)  
**Time:** 20 minutes  
**What a Security Engineer actually does:** When assessing an organization's email security posture — either as part of a security review, an M&A assessment, or investigating a suspicious sender — Security Engineers run `dig` queries directly. No web UI, no Python. Just DNS.

### Part A — Audit the attacker's domain

Run these commands in your terminal. Replace `paypa1-secure.com` with the actual typosquatted domain.

```bash
# Does the domain have an SPF record?
dig TXT paypa1-secure.com

# Does the domain have a DMARC record?
dig TXT _dmarc.paypa1-secure.com

# What mail servers does it advertise?
dig MX paypa1-secure.com

# Who registered this domain and when?
whois paypa1-secure.com
```

**Questions to answer:**

1. Does `paypa1-secure.com` have an SPF record? If so, what does it permit? Does `+all` appear anywhere — and why would that be dangerous?
2. Does it have a DMARC record? What is the policy (`p=` value)?
3. How recently was this domain registered? Fresh registrations under 30 days old are a major phishing indicator.
4. What registrar was used? Phishing domains frequently use registrars known for low identity verification.

### Part B — Audit a legitimate domain's email posture

Now audit the real PayPal and a few other major domains. This gives you baseline intuition for what "good" email security posture looks like.

```bash
# PayPal's actual SPF record
dig TXT paypal.com | grep "v=spf1"

# PayPal's DMARC policy
dig TXT _dmarc.paypal.com

# Check a DKIM selector (PayPal uses several; try selector1 and selector2)
dig TXT selector1._domainkey.paypal.com

# Now check a domain with weak posture for comparison
dig TXT _dmarc.example.com
```

**Questions to answer:**

1. What is PayPal's DMARC policy? Is it `p=none`, `p=quarantine`, or `p=reject`?
2. Does PayPal publish a `rua=` (aggregate report) address in their DMARC record? What is that address used for?
3. Run the same DMARC check on 3 other major brands of your choosing. Which ones have `p=reject`? Which ones are still on `p=none`? Why does `p=none` leave users vulnerable even when SPF and DKIM are configured?
4. What does it mean when `dig TXT _dmarc.somedomain.com` returns `NXDOMAIN` (no record found)?

### Part C — The `+all` SPF misconfiguration

This is one of the most dangerous SPF misconfigurations that still appears in the wild.

```bash
# This query looks for domains with dangerously permissive SPF records
# Try a few domains and see if any use +all
dig TXT _spf.some-marketing-vendor.com
```

---

## Exercise 5: Check the Sending IP on AbuseIPDB

**Tool:** AbuseIPDB — https://www.abuseipdb.com  
**Time:** 10 minutes  
**What a Security Engineer actually does:** The originating IP in a phishing email is an IOC (Indicator of Compromise). Security Engineers check it against abuse databases to determine if it is a known malicious sender, a Tor exit node, a VPN endpoint, or a compromised host.

### What to do

1. Go to https://www.abuseipdb.com
2. Search for `185.220.101.47` (the originating IP from the scenario)
3. Read the full report

### Questions to answer

1. What is the abuse confidence score for this IP (0–100)? What does a high score mean?
2. How many reports has this IP accumulated? Over what time period?
3. What categories of abuse are reported? (AbuseIPDB uses category codes: 18 = Brute Force, 4 = DDoS Attack, 14 = Port Scan, etc.)
4. Look at the **ISP** and **Usage Type** fields. What kind of infrastructure is this IP? (Hint: `185.220.0.0/16` is a well-known Tor exit node range.)
5. If you were writing an incident report, how would you summarize the significance of this IP?

### Now check Shodan

Shodan is https://www.shodan.io — a search engine for internet-exposed infrastructure.

Search for `185.220.101.47` on Shodan.

1. What open ports does Shodan show on this host?
2. What services are running? (SMTP? SSH? HTTP?)
3. Does Shodan show any banners or software versions that suggest what this host is used for?

Shodan and AbuseIPDB together answer the question: **what is this IP, and has it been seen doing bad things before?** These are the first two reputation checks in any phishing triage workflow.

---

## Putting It All Together: Write Your Incident Summary

A Security Engineer does not just run tools — they document findings. After completing Exercises 1–5, write a short incident summary using this template:

```
PHISHING EMAIL INCIDENT SUMMARY
================================
Date reported: [date]
Reported by: [employee role, not name]
Subject line: ACTION REQUIRED: Your PayPal account has been limited

SENDER ANALYSIS
---------------
Claimed sender (From:):     service@paypal.com
Actual envelope sender:     bounce@paypa1-secure.com
Attacker domain:            paypa1-secure.com
Domain age:                 [from whois]
Originating IP:             185.220.101.47
IP classification:          [from AbuseIPDB / Shodan]

AUTHENTICATION RESULTS
----------------------
SPF:   fail  — originating IP not in paypal.com's SPF record
DKIM:  none  — no valid PayPal DKIM signature present
       (attacker-signed d=paypa1-secure.com, meaningless for claimed sender)
DMARC: fail  — PayPal enforces p=REJECT; message failed alignment

ATTACK TECHNIQUE
----------------
Display name spoofing: From: shows "PayPal Security" <service@paypal.com>
Typosquatting: paypa1-secure.com (digit 1 replacing letter l)
Reply-To hijacking: replies go to attacker-controlled domain

IOC REPUTATION
--------------
paypa1-secure.com: [VirusTotal vendor count] vendors flagged as phishing
185.220.101.47:    [AbuseIPDB confidence score]%, Tor exit node

VERDICT
-------
[ ] Malicious — confirmed phishing campaign
[ ] Suspicious — insufficient evidence, monitor
[ ] Clean — false positive

RECOMMENDED ACTIONS
-------------------
1.
2.
3.
```

Fill in every field from your investigation. This is the artifact that gets attached to the incident ticket.

---

## What You Actually Learned

The five exercises in this lab cover the core manual triage workflow every Security Engineer uses when a phishing email lands in their queue:

- **Exercise 1** — Read headers manually. Train your eye to spot spoofed `From:`, mismatched `Return-Path:`, and DMARC failures before any tool touches the data.
- **Exercise 2** — MXToolbox annotates the relay chain and confirms your SPF/DKIM/DMARC reading. Google Admin Toolbox surfaces timing anomalies.
- **Exercise 3** — urlscan.io sandboxes the attacker domain and takes a live screenshot. VirusTotal aggregates multi-vendor threat intel and surfaces associated infrastructure.
- **Exercise 4** — `dig` queries let you audit any domain's email security posture directly from DNS. This is the command-line skill that shows up in penetration testing, M&A security reviews, and red team reporting.
- **Exercise 5** — AbuseIPDB and Shodan classify the originating IP. Tor exit nodes, known spam hosts, and bulletproof hosting are immediate red flags.

No Python was needed because none of these tasks require Python. Python enters the picture in the automation layer — when you have triage these same five steps for 500 reported emails per day and need to write a SOAR playbook to do it automatically. That is a different job function, and a later exercise.

---

## Answer Key

*Complete the exercises before reading this section.*

---

### Exercise 1: Header Analysis

**Completed table:**

| Field | What It Says | Suspicious? |
|---|---|---|
| `From:` | `"PayPal Security" <service@paypal.com>` | Yes — display name spoofing; routing fields contradict this |
| `Return-Path:` | `<bounce@paypa1-secure.com>` | Yes — actual envelope sender is the attacker's domain |
| `Reply-To:` | `verify-account@paypa1-secure.com` | Yes — replies go to attacker-controlled domain, not PayPal |
| `DKIM-Signature d=` | `paypa1-secure.com` | Yes — signed by attacker's domain, not `paypal.com` |
| `Authentication-Results spf=` | `fail` | Yes — originating IP not in PayPal's SPF record |
| `Authentication-Results dmarc=` | `fail (p=REJECT)` | Yes — message failed DMARC alignment under a reject policy |
| First originating IP (`Received:`) | `185.220.101.47` via `smtp-relay.paypa1-secure.com` | Yes — not a PayPal IP; belongs to a Tor exit node range |
| `X-Mailer:` | `PHPMailer 6.1.5` | Yes — bulk phishing kits commonly use PHPMailer |

**Question answers:**

1. No. The `From:` header can be set to anything by the sender — it is not verified at the transport layer. The `Authentication-Results` header, written by the receiving mail server, shows `spf=fail`, meaning the sending IP (`185.220.101.47`) is not in PayPal's authorized sender list. The email did not originate from PayPal's infrastructure.

2. `paypa1-secure.com` replaces the letter `l` with the digit `1`. This is **typosquatting** — registering a domain that looks visually identical to a legitimate one at a glance. The attack technique applied here specifically is **homograph/lookalike domain abuse**.

3. A DKIM signature only proves that the signing domain (`d=paypa1-secure.com`) authorized the message. It says nothing about `paypal.com`. The attacker legitimately controls `paypa1-secure.com` and can produce a valid DKIM signature for it — that signature is meaningless for the claimed `From:` address.

4. `p=REJECT` means PayPal's DMARC policy instructs receiving mail servers to reject any message that fails DMARC alignment — i.e., messages where the `From:` domain does not align with either the SPF envelope sender or the DKIM signing domain. The email reached the inbox because the receiving MTA either had a local policy override, was configured to quarantine rather than reject, or the email arrived via a forwarding path that altered the DMARC evaluation chain.

5. `185.220.101.47` falls in the `185.220.0.0/16` range, which is operated by the Tor Project as exit node infrastructure. Email originating from a Tor exit node is a significant red flag — legitimate senders do not route through Tor.

6. PHPMailer is a widely used open-source PHP library for sending email. Its presence in the `X-Mailer` header indicates the email was sent programmatically via a PHP script rather than a commercial mail transfer agent. Phishing kits are frequently built on top of PHPMailer. Version 6.1.5 is also several releases behind current, which is consistent with a recycled phishing kit.

---

### Exercise 3: PhishTank + urlscan.io + VirusTotal

**Why start with PhishTank:**

PhishTank gives you a confirmed-offline URL — community-verified as phishing, and confirmed taken down. That makes it safe to investigate without risk of hitting a live credential-harvesting page. It also gives you a PhishTank ID, which is a permanent reference you can include in an incident report to cite the source of your IOC.

**What the urlscan.io Network tab reveals:**

Sophisticated phishing pages load legitimate resources from PayPal's actual CDN — real logos, real fonts, real CSS — to pass visual inspection. The Network tab in urlscan.io shows you every external request the page makes. Seeing `cdn.paypal.com` in the network requests of a malicious page is not evidence the page is legitimate — it's evidence the attacker is good at their job.

**What "no urlscan results" means in practice:**

If no scan exists for your PhishTank domain, that tells you something real: the domain was so short-lived that no one submitted it for scanning before it was taken down. Short-lived domains are a deliberate attacker technique — register, blast, abandon — specifically to evade reputation-based blocking. The absence of data is itself a data point.

**Why three tools instead of two:**

PhishTank verifies and archives. urlscan.io captures live page behavior and infrastructure. VirusTotal aggregates multi-vendor reputation and surfaces associated infrastructure via the Relations tab. Each answers a different question. A Security Engineer uses all three because any one of them can be missing data that another has.

---

### Exercise 4 Part C: Reading an SPF Record

`+all` at the end of an SPF record means "any server on the internet is authorized to send email on behalf of this domain." It completely defeats SPF enforcement. When you see this in a production environment, it is a **critical finding** that should be remediated immediately.

**How to read a well-formed SPF record:**

```
"v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.0/24 -all"
```

- `include:_spf.google.com` — Google Workspace servers are authorized to send
- `include:sendgrid.net` — SendGrid is authorized (transactional and marketing email)
- `ip4:203.0.113.0/24` — this specific on-premises IP range is authorized
- `-all` — everything else is a hard fail; reject it

The `-all` at the end is the enforcement mechanism. `~all` (SoftFail) means "accept but mark." `+all` means "accept everything." A domain with `+all` has effectively no SPF protection.

---

## Further Reading

- RFC 7208 (SPF) — https://datatracker.ietf.org/doc/html/rfc7208
- RFC 6376 (DKIM) — https://datatracker.ietf.org/doc/html/rfc6376
- RFC 7489 (DMARC) — https://datatracker.ietf.org/doc/html/rfc7489
- Cloudflare: What is a phishing attack? — https://www.cloudflare.com/learning/access-management/phishing-attack/
- Google Safe Browsing Transparency Report — https://transparencyreport.google.com/safe-browsing/overview
- SANS ISC Phishing Analysis Diary — https://isc.sans.edu/diary/ (search "phishing analysis")
- *Complete 48-Week Security Engineering Curriculum*, Week 9, pp. 48–50 (phishing analysis lab)
