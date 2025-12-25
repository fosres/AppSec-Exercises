# Week 2: DNS Analysis Lab with `delv`
**Security Engineering Interview Prep - Week 2**  
**Lab Duration:** 2 hours  
**Prepared for:** Tanveer Salim

> **Why `delv`?** Unlike `dig`, the `delv` (Domain Entity Lookup & Validation) tool performs DNSSEC validation by default, making it ideal for security-focused DNS analysis. It automatically follows the chain of trust and validates DNS responses.[^1]

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Explain the DNS resolution process (recursive vs iterative queries)
2. Use `delv` to query different DNS record types with automatic DNSSEC validation
3. Understand and interpret DNSSEC validation output
4. Analyze DNS response times and TTL values
5. Identify authoritative name servers and trace the chain of trust
6. Recognize common DNS security vulnerabilities
7. Validate DNS responses using DNSSEC chain of trust

---

## Prerequisites

- Completed Week 1 (TCP/IP Fundamentals)
- Understanding of port 53 (TCP/UDP)
- Basic command-line familiarity
- `delv` command installed (part of BIND9 utilities)

**Windows Users:** Install BIND tools or use WSL (Windows Subsystem for Linux)

---

## Background: DNS Fundamentals

### What is DNS?

DNS (Domain Name System) translates human-readable domain names (e.g., `example.com`) into IP addresses (e.g., `93.184.216.34`) that computers use to communicate. It functions as the "phone book of the internet."[^1]

### DNS Resolution Process

**Recursive Query:** Your DNS resolver does all the work to find the answer for you. It queries multiple servers if needed until it gets the final IP address.[^1]

**Iterative Query:** The DNS server responds with the best answer it has (often a referral to another server), and your client must follow up with additional queries.[^1]

**Example Flow:**
1. Client queries local DNS resolver for `www.example.com`
2. Resolver queries root name server → Returns referral to `.com` TLD server
3. Resolver queries `.com` TLD server → Returns referral to `example.com` authoritative server
4. Resolver queries `example.com` authoritative server → Returns IP address
5. Resolver caches result and returns IP to client

### Common DNS Record Types[^1][^2]

| Record Type | Purpose | Example |
|-------------|---------|---------|
| **A** | Maps domain to IPv4 address | `example.com` → `93.184.216.34` |
| **AAAA** | Maps domain to IPv6 address | `example.com` → `2606:2800:220:1:248:1893:25c8:1946` |
| **CNAME** | Canonical name (alias) | `www.example.com` → `example.com` |
| **MX** | Mail exchange server | `example.com` → `mail.example.com` |
| **TXT** | Text records (SPF, DKIM, etc.) | `example.com` → `"v=spf1 include:_spf.google.com ~all"` |
| **NS** | Name server records | `example.com` → `ns1.example.com` |
| **SOA** | Start of Authority | Contains zone metadata (serial, refresh, retry) |

### Why `delv` for Security Analysis?

**`delv` (Domain Entity Lookup & Validation)** is a DNS lookup tool specifically designed for DNSSEC validation. Unlike `dig`, which requires explicit flags for security features, `delv` performs DNSSEC validation by default.[^1]

**Key Advantages of `delv`:**
1. **Automatic DNSSEC Validation:** Validates responses against the chain of trust without requiring flags
2. **Security-First Design:** Built specifically for security analysis and DNSSEC debugging
3. **Clear Trust Indicators:** Shows "fully validated" or "unsigned" status prominently
4. **Detailed Validation Chain:** Displays each step in the DNSSEC validation process
5. **Better for AppSec:** Emphasizes security validation over raw DNS data

**Comparison:**
```bash
# dig requires explicit +dnssec flag
dig cloudflare.com +dnssec

# delv validates by default
delv cloudflare.com
```

### DNS Security Concerns[^2]

1. **Cache Poisoning:** Attacker injects false DNS data into resolver's cache
2. **DNS Tunneling:** Exfiltrating data through DNS queries/responses
3. **DDoS Amplification:** Using DNS servers to amplify attack traffic (53-byte query → 4000-byte response)
4. **DNSSEC:** Cryptographic signatures to verify DNS data authenticity

---

## Lab Setup

### Installing delv

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install bind9-dnsutils
```

**macOS (using Homebrew):**
```bash
brew install bind
```

**CentOS/RHEL:**
```bash
sudo yum install bind-utils
```

**Verify installation:**
```bash
delv -v
```

Expected output: `delv 9.x.x`

### Understanding delv Output

Unlike `dig`, `delv` output focuses on validation status. As you work through the exercises, observe the different types of messages that appear at the beginning of the output. These indicate the security status of the DNS response.

---

## Exercise 1: Basic DNS Queries with DNSSEC Validation (30 minutes)

### Task 1.1: Query A Records with Validation

Query the A record for `cloudflare.com` (uses DNSSEC):

```bash
delv cloudflare.com A
```

**Analysis Questions:**
1. What IP address(es) did you receive?

104.16.132.229

2. What is the TTL (Time To Live) value?

300 seconds
3. Does the output show "; fully validated" or "; unsigned answer"?

It shows "; fully validated".

4. What does "fully validated" mean in terms of security?

It means by DNSSEC-validating DNS recursive resolver was able to

validate the entire DNSSEC-chain of trust for cloudflare.com.

5. Compare the first line of output with what you might see from `dig` - what's different?

`dig` does not automatically validate for DNSSEC as `delv` does.


### Task 1.2: Compare Signed vs Unsigned Domains

Query both a DNSSEC-enabled and non-DNSSEC domain:

```bash
# DNSSEC-enabled domain
delv cloudflare.com A

# Non-DNSSEC domain (many don't use DNSSEC yet)
delv example.com A
```

**Analysis Questions:**
1. What validation status do you see for each domain?

For a DNSSEC-enabled domain you will see " ; fully validated".

For a domain not protected by DNSSEC you will see " ; unsigned answer"

2. Why is DNSSEC adoption still incomplete?

Most organizations deem DNSSEC adoption too hard to be worth it.

Only around 26% of network service providers and enterprises have

adopted it by July 2024.

3. What security risks exist for unsigned domains?

An attacker can trick a Certificate Authority into misissuing

a TLS certificate to the attacker's server. DNSSEC was invented

to mitigate this. Unsigned domains are also vulnerable to

DNS Cache Poisoning--where the attacker corrupts DNS records in

DNS caches.

### Task 1.3: Query Multiple Record Types

Query different record types for `cloudflare.com`:

```bash
# A record (IPv4)
delv cloudflare.com A

# AAAA record (IPv6)
delv cloudflare.com AAAA

# MX record (Mail servers)
delv cloudflare.com MX

# NS record (Name servers)
delv cloudflare.com NS

# TXT record (Text records)
delv cloudflare.com TXT
```

**Analysis Questions:**
1. Are all record types signed with DNSSEC for this domain?

Yes.

2. How many mail servers does Cloudflare have? What are their priorities?

4 mailservers.

These mailservers have the highest priority:

```
cloudflare.com.         1775    IN      MX      5 mxa-canary.global.inbound.cf-emailsecurity.net.
cloudflare.com.         1775    IN      MX      5 mxb-canary.global.inbound.cf-emailsecurity.net.
```
3. List all authoritative name servers for `cloudflare.com`

Here are the records for each:

```
cloudflare.com.         86240   IN      NS      ns3.cloudflare.com.
cloudflare.com.         86240   IN      NS      ns4.cloudflare.com.
cloudflare.com.         86240   IN      NS      ns5.cloudflare.com.
cloudflare.com.         86240   IN      NS      ns6.cloudflare.com.
cloudflare.com.         86240   IN      NS      ns7.cloudflare.com.
```

4. What TXT records did you find? Look for SPF, DKIM, or DMARC records?

Here are the full results when I submitted the query for TXT records:

```
[I] fosres@fosres ~> delv cloudflare.com TXT
; fully validated
cloudflare.com.         100     IN      TXT     "MS=ms70274184"
cloudflare.com.         100     IN      TXT     "_neqmkgaq1lq9it5s8qmetrhbnu121wb"
cloudflare.com.         100     IN      TXT     "ZOOM_verify_7LFBvOO9SIigypFG2xRlMA"
cloudflare.com.         100     IN      TXT     "asv=894f6d1f9f83bcf44e4b1bc40bc1c4aa"
cloudflare.com.         100     IN      TXT     "apple-domain-verification=DNnWJoArJobFJKhJ"
cloudflare.com.         100     IN      TXT     "status-page-domain-verification=r14frwljwbxs"
cloudflare.com.         100     IN      TXT     "canva-site-verification=oOyaVnHC-OiFoR1BPvetNA"
cloudflare.com.         100     IN      TXT     "docker-verification=c578e21c-34fb-4474-9b90-d55ee4cba10c"
cloudflare.com.         100     IN      TXT     "miro-verification=bdd7dfa0a49adfb43ad6ddfaf797633246c07356"
cloudflare.com.         100     IN      TXT     "facebook-domain-verification=h9mm6zopj6p2po54woa16m5bskm6oo"
cloudflare.com.         100     IN      TXT     "onetrust-domain-verification=bd5cd08a1e9644799fdb98ed7d60c9cb"
cloudflare.com.         100     IN      TXT     "uber-domain-verification=58086039-150a-42a4-a4be-b4032921aa0f"
cloudflare.com.         100     IN      TXT     "logmein-verification-code=b3433c86-3823-4808-8a7e-58042469f654"
cloudflare.com.         100     IN      TXT     "creatopy-domain-verification=97d2ca50-9b6f-4a21-9bdb-fbb630e4cec7"
cloudflare.com.         100     IN      TXT     "google-site-verification=C7thfNeXVahkVhniiqTI1iSVnElKR_kBBtnEHkeGDlo"
cloudflare.com.         100     IN      TXT     "google-site-verification=ZdlQZLBBAPkxeFTCM1rpiB_ibtGff_JF5KllNKwDR9I"
cloudflare.com.         100     IN      TXT     "liveramp-site-verification=EhH1MqgwbndTWl1AN64hOTKz7hc1s80yUpchLbgpfY0"
cloudflare.com.         100     IN      TXT     "stripe-verification=5096d01ff2cf194285dd51cae18f24fa9c26dc928cebac3636d462b4c6925623"
cloudflare.com.         100     IN      TXT     "stripe-verification=bf1a94e6b16ace2502a4a7fff574a25c8a45291054960c883c59be39d1788db9"
cloudflare.com.         100     IN      TXT     "drift-domain-verification=f037808a26ae8b25bc13b1f1f2b4c3e0f78c03e67f24cefdd4ec520efa8e719f"
cloudflare.com.         100     IN      TXT     "cisco-ci-domain-verification=27e926884619804ef987ae4aa1c4168f6b152ada84f4c8bfc74eb2bd2912ad72"
cloudflare.com.         100     IN      TXT     "atlassian-domain-verification=WxxKyN9aLnjEsoOjUYI6T0bb5vcqmKzaIkC9Rx2QkNb751G3LL/cus8/ZDOgh8xB"
cloudflare.com.         100     IN      TXT     "_saml-domain-challenge.2dc00405-79cd-457b-b288-a119c6f0c7b7.71996d53-d178-4ba9-bef4-7f7e46edab74.cloudflare.com=1c8736fd-84b2-4197-985f-3fb2852f2457"
cloudflare.com.         100     IN      TXT     "v=spf1 ip4:199.15.212.0/22 ip4:173.245.48.0/20 include:_spf.google.com include:spf1.mcsv.net include:spf.mandrillapp.com include:mail.zendesk.com include:stspg-customer.com include:_spf.salesforce.com -all"
cloudflare.com.         100     IN      RRSIG   TXT 13 2 300 20251221044451 20251219024451 34505 cloudflare.com. NvY9zfTlkkd5BntJSgvM7cehPoJYONW5SYUKgPDzGosjXI+W28axV/PZ Q+xi50FHlFlVpRAsgXuVmU4O3pDZuA==
```

5. Compare the TTL values across different record types. Why might they differ?

The TTL for the A record for cloudflare.com is significantly

shorter than the TTL value for the NS records for cloudflare.com.

The reason for that is to accomodate for changes in situations.

A user may be traveling to several cities in the same day. CloudFlare,

being a site crucial for several services, needs to offer several

Points of Presence closes to the user wherever they are--even if

the user drastically changes their location within a day. This explains

why the TTL for the A record is shorter--in case the user's location

significantly changes response times do not lag.

The TTL records for the NS records, however, is much longer. That

is because DNS records for cloudflare.com do not change too often

--the location of the DNS Nameservers for cloudflare.com are likely

to stay the same by the end of next year. Due to a lack of need

of frequent update it makes sense the TTL value for cloudflare's.com

NS records are much longer.

### Task 1.4: Using the -t Flag for Record Types

Alternative syntax using `-t`:

```bash
delv -t A cloudflare.com
delv -t AAAA cloudflare.com
delv -t MX cloudflare.com
```

**Question:** How does the output differ from specifying the record type after the domain name?

It is honestly not too different than specifying the record type

after the domain. Here are the equivalent queries you can make with

`delv`:

```
delv A cloudflare.com A
delv cloudflare.com AAAA
delv cloudflare.com MX
```

---

## Exercise 2: DNSSEC Chain of Trust Validation (30 minutes)

### Task 2.1: Trace DNSSEC Validation Chain

Use the `+rtrace` flag to see the complete DNSSEC validation process:

```bash
delv @8.8.8.8 cloudflare.com A +rtrace
```

This command displays each step in the DNSSEC validation chain from root to the final answer.

**Analysis Questions:**
1. How many distinct zones are involved in the validation chain?

Here is the output of the command:

```
;; fetch: cloudflare.com/A
;; fetch: cloudflare.com/DNSKEY
;; fetch: cloudflare.com/DS
;; fetch: com/DNSKEY
;; fetch: com/DS
;; fetch: ./DNSKEY
; fully validated
cloudflare.com.         300     IN      A       104.16.132.229
cloudflare.com.         300     IN      A       104.16.133.229
cloudflare.com.         300     IN      RRSIG   A 13 2 300 20251222001533 20251219221533 34505 cloudflare.com. aPhd+7BUOm55njK5UIBB/VWLuWsqY0Md52e5cJTEQS0UAGXb/vV4GuA2 bAUTRhAkx5x92ESkND9VbWF+dvB9jQ==

```

There are three distinct zones:

1. `.`

2. `.com`

3. `cloudflare.com`

2. What types of DNSSEC-related records do you see? (Hint: Look for records ending in KEY or SIG)

There is one RRSIG record. I show it below:

```
cloudflare.com.         300     IN      RRSIG   A 13 2 300 20251222001533 20251219221533 34505 cloudflare.com. aPhd+7BUOm55njK5UIBB/VWLuWsqY0Md52e5cJTEQS0UAGXb/vV4GuA2 bAUTRhAkx5x92ESkND9VbWF+dvB9jQ==

```

3. What is a DS (Delegation Signer) record and where does it appear in the chain?[^2]

The Delegation Signer record is a record containing the cryptographic

message digest of a child DNS zone's Key Signing Public Key. This

Delegation Signer Record is itself signed by the parent DNS Zone's

Zone Signing Private Key and is stored as a separate RRSIG record

in the parent DNS zone records. The Delegation

Signer Record proves to DNSSEC-validating recursive resolvers that

the child zone's Key Signing Public Key is authentic.

4. What is an RRSIG (Resource Record Signature) and what does it sign?

RRSIG records are digital signatures of RRsets of DNS records signed

by the DNS zone's Zone Signing Private Key.

5. Draw a diagram showing the chain of trust from root → TLD → domain

SKIPPING DUE TO IRRELEVANCE FOR GENERAL SECURITY ENGINEERING

INTERVIEWS.

6. At which point in the chain does validation begin?

It starts with the domain's DNS records.

Consider the chain-of-trust validation for gentoo.org:

```
[I] fosres@fosres ~/P/g/A/networking (main)> delv gentoo.org +vtrace
;; fetch: gentoo.org/A
;; validating gentoo.org/A: starting
;; validating gentoo.org/A: attempting positive response validation
;; fetch: gentoo.org/DNSKEY
;; validating gentoo.org/DNSKEY: starting
;; validating gentoo.org/DNSKEY: attempting positive response validation
;; fetch: gentoo.org/DS
;; validating gentoo.org/DS: starting
;; validating gentoo.org/DS: attempting positive response validation
;; fetch: org/DNSKEY
;; validating org/DNSKEY: starting
;; validating org/DNSKEY: attempting positive response validation
;; fetch: org/DS
;; validating org/DS: starting
;; validating org/DS: attempting positive response validation
;; fetch: ./DNSKEY
;; validating ./DNSKEY: starting
;; validating ./DNSKEY: attempting positive response validation
;; validating ./DNSKEY: verify rdataset (keyid=20326): success
;; validating ./DNSKEY: marking as secure (DS)
;; validating org/DS: in fetch_callback_dnskey
;; validating org/DS: keyset with trust secure
;; validating org/DS: resuming validate
;; validating org/DS: verify rdataset (keyid=61809): success
;; validating org/DS: marking as secure, noqname proof not needed
;; validating org/DNSKEY: in fetch_callback_ds
;; validating org/DNSKEY: dsset with trust secure
;; validating org/DNSKEY: verify rdataset (keyid=26974): success
;; validating org/DNSKEY: marking as secure (DS)
;; validating gentoo.org/DS: in fetch_callback_dnskey
;; validating gentoo.org/DS: keyset with trust secure
;; validating gentoo.org/DS: resuming validate
;; validating gentoo.org/DS: verify rdataset (keyid=58098): success
;; validating gentoo.org/DS: marking as secure, noqname proof not needed
;; validating gentoo.org/DNSKEY: in fetch_callback_ds
;; validating gentoo.org/DNSKEY: dsset with trust secure
;; validating gentoo.org/DNSKEY: verify rdataset (keyid=57312): success
;; validating gentoo.org/DNSKEY: marking as secure (DS)
;; validating gentoo.org/A: in fetch_callback_dnskey
;; validating gentoo.org/A: keyset with trust secure
;; validating gentoo.org/A: resuming validate
;; validating gentoo.org/A: verify rdataset (keyid=63217): success
;; validating gentoo.org/A: marking as secure, noqname proof not needed
; fully validated
gentoo.org.             400     IN      A       146.75.109.91
gentoo.org.             400     IN      A       151.101.1.91
gentoo.org.             400     IN      A       151.101.65.91
gentoo.org.             400     IN      A       151.101.129.91
gentoo.org.             400     IN      A       151.101.193.91
gentoo.org.             400     IN      A       151.101.213.91
gentoo.org.             400     IN      RRSIG   A 14 2 600 20260101014901 20251218005226 63217 gentoo.org. PFc8XSkp3spkOQtqSZtctCBIzS0mYxPLHWJRoqlyoiUyEgfJmIkhuTL7 Tyxdz2ZzWmiQ3RpsqF7JvsGs5H/RPLm7yL9dmu9CwqutU7mmSgnt43E+ D7leWET8ObUo6XjJ
```

### Task 2.2: Understand Trust Anchor

Check the root trust anchor:

```bash
# View trust anchor configuration
cat /etc/bind.keys
# Or on some systems:
cat /etc/trusted-key.key
```

**Analysis Questions:**
1. What is a trust anchor?
2. Why does DNSSEC validation start with the root zone?
3. How is the root zone's public key distributed and trusted?

### Task 2.3: Query Specific Name Servers

Query different recursive resolvers using `@`:

```bash
# Query Google's public DNS (8.8.8.8)
delv @8.8.8.8 cloudflare.com A

# Query Cloudflare's public DNS (1.1.1.1)
delv @1.1.1.1 cloudflare.com A

# Query Quad9 (DNSSEC-validating, malware-blocking)
delv @9.9.9.9 cloudflare.com A
```

**Analysis Questions:**
1. Do all resolvers show "fully validated" for DNSSEC-signed domains?
2. What happens if you query a non-validating resolver?
3. Why is it important to use a DNSSEC-validating resolver?

### Task 2.4: Test DNSSEC Validation Failure

Try querying a known DNSSEC-broken domain (if available):

```bash
# This is a test domain specifically for DNSSEC validation failures
delv dnssec-failed.org
```

**Security Questions:**
1. What error message do you see?
2. How would `delv` protect you from a cache poisoning attack?
3. What should you do if you encounter a validation failure?

---

## Exercise 3: CNAME and Alias Analysis (20 minutes)

### Task 3.1: Follow CNAME Chains with Validation

Many domains use CNAME records for aliasing:

```bash
delv www.github.com A
```

**Analysis Questions:**
1. Is `www.github.com` a CNAME? If so, what does it point to?
2. What is the final A record IP address?
3. Is the CNAME record signed with DNSSEC?
4. Why do companies use CNAME records for www subdomains?

### Task 3.2: Analyze CDN CNAME Chains

Check a domain that uses a CDN:

```bash
# Example: Website using Cloudflare
delv www.example.com
```

**Analysis Questions:**
1. How many CNAME records are in the chain?
2. Can you identify the CDN provider from the CNAME target?
3. Are all records in the CNAME chain validated?
4. What happens if one link in the CNAME chain fails DNSSEC validation?

### Task 3.3: Identify Subdomain Takeover Risk

Query these test scenarios:

```bash
# Check if CNAME points to non-existent service
delv blog.example.com
delv assets.example.com
```

**Security Questions:** 
1. What happens if a CNAME points to a service that no longer exists (e.g., old Heroku app, deleted GitHub Pages, expired Azure blob)?
2. How could an attacker exploit abandoned CNAME records?[^2]
3. How would DNSSEC validation help detect (or not detect) subdomain takeover?
4. What tools would you use to automatically scan for subdomain takeover vulnerabilities?

---

## Exercise 4: Email Security with MX and TXT Records (15 minutes)

### Task 4.1: Analyze Mail Server Configuration

Query MX records for a DNSSEC-enabled domain:

```bash
delv cloudflare.com MX
delv google.com MX
```

**Analysis Questions:**
1. How many MX records are returned?
2. What are the priority values? (Lower number = higher priority)
3. What happens if the highest-priority server is unavailable?
4. Is the MX record validated with DNSSEC?
5. Query the A records for the mail servers listed. Do they resolve and validate?

### Task 4.2: SPF Record Analysis for Email Security

Many domains use TXT records for SPF (Sender Policy Framework):

```bash
delv google.com TXT
delv cloudflare.com TXT
```

**Security Questions:**
1. Can you identify the SPF record in the output? (Starts with `v=spf1`)
2. What does the SPF record specify?
3. Why is SPF important for email security and preventing spoofing?
4. What does `~all` (soft fail) vs `-all` (hard fail) mean in an SPF record?
5. Is the TXT record signed with DNSSEC?

### Task 4.3: DMARC Record Analysis

Check for DMARC records (found in `_dmarc` subdomain):

```bash
delv _dmarc.cloudflare.com TXT
delv _dmarc.google.com TXT
```

**Analysis Questions:**
1. What DMARC policy is specified? (`p=none`, `p=quarantine`, or `p=reject`)
2. What is DMARC and how does it relate to SPF and DKIM?
3. How does DNSSEC validation of DMARC records improve email security?

---

## Exercise 5: Advanced DNS Security Analysis (25 minutes)

### Task 5.1: Verify DNSSEC Signature Validity

Compare validated and unsigned responses:

```bash
# Fully validated domain
delv cloudflare.com A

# Check validation with verbose output
delv cloudflare.com A +vtrace
```

The `+vtrace` flag shows detailed validation steps. Observe carefully what additional information appears.

**Analysis Questions:**
1. What additional information does `+vtrace` reveal compared to the basic query?
2. How many cryptographic signatures are validated in the chain?
3. What signature algorithm is used? (Look for algorithm names in the output)
4. Can you find when the RRSIG signatures expire?
5. What would happen if the signature was expired?
6. How does this verbose output help with troubleshooting DNSSEC issues?

### Task 5.2: Detect DNSSEC Configuration Issues

Test domains with intentional DNSSEC failures (if available):

```bash
# Test with DNSSEC validation
delv dnssec-failed.org

# Compare with dig (which doesn't validate by default)
dig dnssec-failed.org
```

**Security Analysis:**
1. What error does `delv` show for a broken DNSSEC configuration?
2. How does this protect against DNS spoofing attacks?[^2]
3. Would `dig` (without validation) still return an answer?
4. Why is automatic validation critical for security?

### Task 5.3: Analyze DNS Amplification Attack Vectors

Understanding response sizes for DDoS amplification:

```bash
# Normal A record query
delv google.com A

# Larger response with TXT records
delv google.com TXT

# DNSKEY records (even larger)
delv google.com DNSKEY
```

**Security Questions:**
1. Estimate the size difference between query and response
2. How could attackers abuse this size difference in a DNS amplification DDoS attack?[^2]
3. What is the amplification factor for DNSKEY queries?
4. How do modern DNS servers mitigate amplification attacks?
5. Why did many servers stop responding to ANY queries?

### Task 5.4: DNS Tunneling Pattern Recognition

Compare normal vs suspicious query patterns:

```bash
# Normal query
delv google.com A

# What DNS tunneling might look like (hypothetical, don't run against real servers)
# delv aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllll.malicious.com TXT
```

**Security Questions:**
1. What makes a DNS query suspicious for tunneling?
2. Research and list 3-4 characteristics commonly seen in DNS tunneling patterns[^2]
3. Why might attackers prefer TXT or NULL record types for tunneling?
4. How would you detect DNS tunneling in network logs?
5. What legitimate uses exist for long TXT record queries?
6. What network monitoring tools could help detect this?

### Task 5.5: Test Resolver DNSSEC Enforcement

Compare validating vs non-validating resolvers:

```bash
# Google DNS (validates DNSSEC)
delv @8.8.8.8 cloudflare.com

# Test with a non-validating resolver (if you have one)
delv @<non-validating-ip> cloudflare.com
```

**Security Analysis:**
1. Does the non-validating resolver still return results for broken DNSSEC?
2. What security risk does using a non-validating resolver create?
3. How can you verify your ISP's DNS resolver validates DNSSEC?
4. Why should organizations enforce DNSSEC validation at the resolver level?

---

## Challenge Exercise: Build a DNSSEC Validation Tool (Optional)

If you have extra time, create a Python script that mimics `delv`'s security-first approach:

1. Queries multiple record types for a domain
2. Performs DNSSEC validation (or checks if domain supports DNSSEC)
3. Displays results with validation status prominently
4. Identifies potential security issues
5. Measures and displays query times

**Starter Code:**

```python
#!/usr/bin/env python3
"""
DNSSEC-aware DNS query tool
Inspired by delv's security-first design
"""
import dns.resolver
import dns.dnssec
import time
import sys

def query_dns_with_validation(domain, record_type='A', nameserver=None):
	"""
	Query DNS and check for DNSSEC support
	
	Returns:
		tuple: (answers, query_time_ms, has_dnssec)
	"""
	start = time.time()
	
	try:
		resolver = dns.resolver.Resolver()
		if nameserver:
			resolver.nameservers = [nameserver]
		
		# Query the record
		answers = resolver.resolve(domain, record_type)
		query_time = (time.time() - start) * 1000
		
		# Check for DNSSEC (simplified - real validation is complex)
		has_dnssec = False
		try:
			# Try to get RRSIG records
			rrsig = resolver.resolve(domain, 'RRSIG')
			has_dnssec = True if rrsig else False
		except:
			pass
		
		return answers, query_time, has_dnssec
		
	except dns.resolver.NXDOMAIN:
		print(f"Domain {domain} does not exist")
		return None, None, None
	except dns.resolver.NoAnswer:
		print(f"No {record_type} record found for {domain}")
		return None, None, None
	except Exception as e:
		print(f"Error: {e}")
		return None, None, None

def main():
	domain = input("Enter domain to analyze: ")
	record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
	
	print(f"\n{'='*60}")
	print(f"DNSSEC-Aware DNS Analysis for: {domain}")
	print(f"{'='*60}\n")
	
	for rtype in record_types:
		answers, query_time, has_dnssec = query_dns_with_validation(domain, rtype)
		
		if answers:
			# Display validation status prominently (like delv)
			validation_status = "DNSSEC-SIGNED" if has_dnssec else "UNSIGNED"
			print(f"\n{rtype} Records [{validation_status}] (Query: {query_time:.2f}ms):")
			print("-" * 60)
			
			for rdata in answers:
				print(f"  {rdata}")
			
			# Security warning for unsigned records
			if not has_dnssec and rtype in ['A', 'AAAA', 'MX']:
				print(f"  ⚠️  WARNING: No DNSSEC validation - vulnerable to spoofing")

if __name__ == "__main__":
	main()
```

**Required Package:**
```bash
pip3 install dnspython
```

**Enhancement Ideas:**
1. Add actual DNSSEC signature validation (using `dns.dnssec` module)
2. Display full chain of trust
3. Highlight security warnings prominently
4. Add command-line arguments for different nameservers
5. Export results to JSON with security assessment

---

## Post-Lab Assessment

### Knowledge Check

1. Explain the difference between `dig` and `delv` - why would a security engineer prefer `delv`?
2. What does "; fully validated" mean in `delv` output?
3. How does DNSSEC prevent DNS cache poisoning attacks?[^2]
4. What is a DNSSEC chain of trust and what are its components (root → TLD → domain)?
5. What security risks exist for domains that don't use DNSSEC?
6. Explain the difference between DNSKEY, DS, and RRSIG records
7. What is a DNS amplification attack and how does DNSSEC affect it?[^2]

### Command Mastery

Can you execute these commands from memory?

- [ ] Query A record with DNSSEC validation for a domain
- [ ] Display the full DNSSEC validation chain (+rtrace)
- [ ] Query specific DNS server (e.g., 8.8.8.8)
- [ ] Show verbose validation output (+vtrace)
- [ ] Query all record types (A, AAAA, MX, NS, TXT)
- [ ] Check MX records with validation status
- [ ] Verify DNSSEC signatures for TXT records

### DNSSEC Validation Understanding

**Scenario 1:** You query a domain with `delv` and the first line of output indicates the response is not cryptographically validated.

**Questions:**
1. What message did you see?
2. What security risks does this pose?
3. Should you trust this response?
4. How does this differ from what you'd see for a DNSSEC-enabled domain?

**Scenario 2:** You query a domain with `delv` and instead of getting DNS records, you receive an error indicating the resolution failed.

**Questions:**
1. What might have caused this error?
2. Could this indicate a DNSSEC validation failure?
3. How would you troubleshoot this?
4. What would you try running next to gather more information?

### Real-World Security Scenario

**Incident:** During a security assessment, you analyze DNS query logs and notice unusual patterns for queries going to a single external domain: `data-exfil.suspicious.com`. The queries show abnormal characteristics compared to typical DNS traffic.

**Analysis Questions:**
1. What specific query characteristics would you look for to identify potential data exfiltration?[^2]
2. What attack technique might this indicate?[^2]
3. Would `delv` help detect this attack? Why or why not?
4. What tools would you use to investigate this further?
5. How would you block this at the DNS resolver level?
6. What log sources would contain evidence of this activity?
7. How does DNSSEC validation relate to this threat? Does it help or not?
8. What baseline metrics would you establish to detect future similar attacks?

---

## Additional Resources

### Required Reading

1. **Cloudflare Learning - What is DNS?**  
   https://www.cloudflare.com/learning/dns/what-is-dns/  
   (Focus: DNS fundamentals, record types, how DNS works)

2. **Cloudflare Learning - DNSSEC**  
   https://www.cloudflare.com/learning/dns/dns-security/  
   (Focus: DNS security threats and DNSSEC)

### Reference Materials

- `man delv` - Complete delv manual
- `man named` - BIND name server documentation
- RFC 1035 - Domain Names Implementation and Specification
- RFC 4033, 4034, 4035 - DNSSEC specifications
- OWASP DNS Security Cheat Sheet

### Practice Domains

Safe domains to practice DNS queries (with varying DNSSEC support):

**DNSSEC-Enabled Domains:**
- `cloudflare.com` (excellent DNSSEC implementation)
- `icann.org` (DNSSEC standards organization)
- `.gov` domains (many use DNSSEC)

**Non-DNSSEC Domains (for comparison):**
- `example.com` (IANA reserved domain)
- Many commercial sites (DNSSEC adoption still growing)

**Test Domains:**
- `dnssec-failed.org` (intentionally broken DNSSEC for testing)
- Your own domains (if applicable)

---

## Next Steps

**Week 3 Preview:** TLS/SSL Deep Dive
- TLS handshake process
- Certificate chains and validation (similar to DNSSEC chain of trust!)
- Using `openssl s_client` for certificate analysis
- SSL Labs security assessment
- Understanding certificate transparency logs

**Homework:** 
1. Document your Week 2 learnings in your security engineering journal
2. Add `delv` commands to your security toolkit cheat sheet
3. Practice explaining DNSSEC validation to a non-technical audience
4. Identify 5 domains you frequently visit and check their DNSSEC status

---

## References

[^1]: Internet Systems Consortium (ISC). "delv - DNS lookup and validation utility." BIND 9 Documentation. https://bind9.readthedocs.io/en/latest/manpages.html#delv-dns-lookup-and-validation-utility (Accessed December 2025)

[^2]: Complete 48 Week Security Engineering Curriculum, Week 2: DNS and TLS, pp. 5-6 (December 2025)

---

**Lab Completion Checklist:**

- [ ] Installed and tested `delv` command
- [ ] Completed all 5 exercises (Basic Queries, Chain of Trust, CNAME Analysis, Email Security, Advanced Security)
- [ ] Answered all analysis questions
- [ ] Queried at least 5 different domains with DNSSEC validation
- [ ] Traced DNSSEC chain of trust for 3 domains (+rtrace)
- [ ] Analyzed MX, TXT, and DMARC records for email security
- [ ] Compared DNSSEC-enabled vs unsigned domains
- [ ] Understood difference between "fully validated" and "unsigned answer"
- [ ] Documented findings and commands in notes
- [ ] Reviewed Cloudflare DNS and DNSSEC learning materials
- [ ] Can explain DNSSEC chain of trust (root → TLD → domain)
- [ ] Understand how `delv` protects against cache poisoning

**Time Spent:** _____ hours  
**Self-Rating (1-10):** _____ on DNS fundamentals  
**Self-Rating (1-10):** _____ on DNSSEC validation understanding

---

*Prepared for Week 2 of 48-Week Security Engineering Interview Prep*  
*Last Updated: December 2025*
