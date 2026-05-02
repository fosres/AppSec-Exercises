# I Studied 14 Real Security Engineering Interview Problems. Here Is Everything I Learned.

*By Tanveer Salim (fosres) — Security Engineer in training, Intel IPAS alumnus, STRIDE threat modeler.*

*All diagrams, challenge PDFs, and exercises live at [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises). Star it if this is useful.*

---

## The Horror Story: When AI Cannot Save You

*The following is a fictional composite scenario inspired by real supply chain attacks — CircleCI (January 2023), Codecov (April 2021), and SolarWinds (December 2020). It did not necessarily happen to any specific company. It absolutely could.*

---

Imagine it is 2 AM on a Tuesday. The on-call engineer at a major AI company — let us call them NeuralCorp — gets paged. Their threat detection pipeline is firing on something unusual: a container image that passed all CI/CD scans is exhibiting anomalous network behavior in production. It is calling out to an IP address in Eastern Europe at 30-second intervals.

The engineer pulls the image digest. It matches the signed artifact in the registry. Cosign says the signature is valid. The SLSA provenance says it was built by their trusted GitHub Actions pipeline from a legitimate commit. Every automated check passed.

But the container is exfiltrating data.

What happened?

Three weeks earlier, a NeuralCorp engineer's laptop was compromised via a spear-phishing email disguised as a GitHub security notification. The attacker did not steal signing keys — those were OIDC-bound and expired after 10 minutes. Instead they stole the engineer's GitHub session token. They waited. They studied the commit patterns of low-review PRs — infrastructure utility scripts that senior engineers rubber-stamp. They crafted a single-line change to a base Docker image layer that added a dormant outbound callback. It looked like a cleanup commit. It passed SAST because it had no obvious vulnerability signatures. It passed the dependency scanner because no new packages were added. Trivy scanned the image layers but the malicious code was obfuscated inside a legitimate system binary that was already on the scanner's allowlist.

The pipeline signed it. SLSA attested it. Binary Authorization admitted it.

The AI company's proprietary model weights began streaming out at 3 KB/s — below every rate-limiting threshold — for 18 days before detection.

---

**The lesson is not that these security systems failed. They worked exactly as designed.**

The lesson is that no security system — including AI-powered ones — provides perfect protection. Security is defense in depth. The systems we build reduce attack surface, raise attacker cost, and create detection opportunities. They do not eliminate human error, social engineering, or sufficiently sophisticated adversaries.

**AI will not solve your cloud security problems.** AI can assist with threat detection, anomaly scoring, log analysis, and SAST. But AI cannot replace a security engineer who understands *why* each layer of defense exists, *what* it can and cannot detect, and *how* to design systems that fail safely when individual controls are bypassed.

That is what the following 14 challenges are about.

---

## What These Challenges Are

I am working through Saed Farah's 40 Real Security Engineering Problems framework — the same problems that appear in security engineering interviews at companies like Anthropic, Stripe, Coinbase, GitLab, and Cloudflare. Each challenge is a 45-minute whiteboard design exercise: blank canvas, problem statement, clarifying questions, architecture diagram, then STRIDE threat model.

**Saed's words:** *"If you want to break into security engineering in 2025, learn these by doing. Not by memorising definitions. Not by watching a hundred videos. By understanding how systems actually work."*

Every solution in this post is my own — drawn on a blank canvas, narrated out loud, then graded and corrected. The mistakes are real. The gaps are honest. The "What I Got Wrong" sections are where the real learning happened.

**The pattern I kept missing:** Repudiation. Every single challenge. The R in STRIDE is always about the audit log — append-only Kafka, digital signatures, offsite backups. I missed it for the first four challenges before it clicked. If you are studying for security interviews, write that on your hand before you walk in.

---

## Challenge 1 — Secure Authentication System for 1 Billion Users

### Problem Statement

Design a secure authentication system for 1 billion users supporting password authentication, OAuth 2.0, and MFA. The system must achieve 99.99% availability with sub-100ms authentication latency and geographic distribution.

### Requirements

**99.99% availability** = 52.56 minutes of downtime per year maximum.

**Argon2id for password hashing** — not bcrypt, not MD5, not SHA-256 alone. Argon2id won the Password Hashing Competition. Memory-hard by design — GPU cracking attacks are exponentially more expensive. Parameters: minimum 64MB memory, 3 iterations, parallelism factor 4.

**Constant-time comparison** — password verification must take the same amount of time whether the password is correct or not. Timing oracles allow attackers to determine password validity through response time measurement.

**Geographic distribution** — three regions minimum (US-East, EU-West, Asia-Pacific). Users authenticate against the nearest region. Cross-region failover is automatic on health check failure.

### Architecture

```
[Client] → [Global Load Balancer (BGP anycast)]
                    ↓
         [Auth Service Fleet — stateless, 3 regions]
              ↓          ↓          ↓
    [Redis Sessions] [PostgreSQL] [Redis MFA Ephemeral]
         [Credentials + TOTP]
                    ↓
         [Kafka — append-only audit log]
                    ↓
         [DMZ trust boundary]
```

**Key components:**

- **Stateless Auth Services** — any instance can handle any request. State lives in Redis and PostgreSQL, not in the service
- **Redis Sessions** — hot session store with TTL-based expiry
- **PostgreSQL** — durable credential storage (Argon2id hashes), TOTP secrets encrypted at rest
- **Redis MFA Ephemeral** — challenge codes with short TTL. SET NX for atomic replay prevention
- **Kafka Audit Log** — every auth event, success or failure, appended permanently

### STRIDE

**S:** Credential stuffing — attacker uses leaked username/password pairs from other breaches. Mitigation: Argon2id (makes large-scale verification expensive), per-IP rate limiting, anomaly detection on failed login velocity. Session token theft via XSS — Mitigation: HttpOnly cookies.

**T:** Credential database tampering — attacker modifies stored Argon2id hashes to inject known-value hashes. Mitigation: digital signatures on all credential records, HSM-backed encryption of TOTP secrets.

**R:** Attacker performs auth bypass and denies it. Mitigation: append-only Kafka audit log, digital signatures on every record, offsite backups. Every auth event permanently recorded with timestamp, IP, device, and outcome.

**I:** Argon2id hash exposure if database is breached. The hash is useless without cracking — that is the point. TLS on all connections prevents credential interception in transit.

**D:** Auth service flooding — rate limiter per IP, geographic load balancing. TOTP brute force — 6-digit code = 1,000,000 possibilities, but 5 attempts before lockout reduces effective space to 5.

**E:** Admin credential theft gives access to credential database. Mitigation: FIDO2 U2F for all admin accounts, least-privilege IAM roles, HSM-backed key management.

**Score: 8/10 architecture, 5.5/6 STRIDE**

---

## Challenge 2 — OAuth 2.0 Login for 50,000 Third-Party Apps

### Problem Statement

Build an OAuth 2.0 authorization server for a platform with 50,000 third-party application integrations. Support secure token issuance, rotation, and revocation.

### Requirements

**~175–290 peak RPS** for token operations.

**Why Authorization Code + PKCE — not Implicit flow:**

The Implicit flow passes the access token directly in the URL fragment: `https://app.com/callback#access_token=xyz`. This token appears in:
- Browser history
- Server access logs (if the full URL is logged)
- Referrer headers sent to third parties

Authorization Code + PKCE solves this: the URL contains only a short-lived code, not the token. The code is exchanged for a token via a back-channel server-to-server call. The token never appears in a URL.

PKCE (Proof Key for Code Exchange) adds a code verifier/challenge pair that prevents authorization code interception attacks — even if a malicious app intercepts the code, it cannot exchange it without the verifier.

**Refresh token family revocation:** when a refresh token is replayed (used more than once), the entire token family is revoked. This detects stolen refresh tokens — the legitimate client's next refresh attempt fails, alerting them to the compromise.

### Architecture

```
[Client App] → [Auth Server] → [Token Endpoint (PKCE validation)]
                    ↓
         [Client Registry — 50K apps, redirect URI allowlist]
         [Token Store — Redis (access tokens) + PostgreSQL (refresh tokens)]
         [Token Revocation — real-time, propagated to all regions]
                    ↓
         [Resource Server — validates tokens locally via JWKS cache]
                    ↓
         [Kafka Audit Log]
```

**Strict redirect URI exact matching** — any mismatch rejects the authorization request immediately. Wildcard redirect URIs are never permitted.

### STRIDE

**S:** Authorization code interception — attacker intercepts the code from the redirect URI. Mitigation: PKCE code verifier/challenge pair — the code is useless without the verifier.

**T:** Token store tampering — attacker modifies token records to extend expiry or escalate scopes. Mitigation: digital signatures on all token records, HSM-backed signing keys.

**R:** Attacker uses a token for malicious actions and denies it. Mitigation: append-only audit log records every token issuance, use, and revocation with client ID and scope.

**I:** Token leakage in URL — Implicit flow. Mitigation: Authorization Code + PKCE eliminates tokens from URLs. TLS on all channels.

**D:** Token endpoint flooding — rate limiting per client ID and per IP.

**E:** Client credential theft gives attacker ability to issue tokens on behalf of a legitimate app. Mitigation: client secret rotation, short token lifetimes, scope restrictions per client.

**Score: 8/10 architecture, 5.5/6 STRIDE**

---

## Challenge 3 — Zero Trust Access Model for 10,000 Employees, 50,000 Devices

### Problem Statement

Design a Zero Trust network access model for a large enterprise with 10,000 employees and 50,000 devices. No implicit trust based on network location.

### Requirements

**Three Zero Trust principles:**
1. Never trust, always verify — every request authenticated regardless of origin
2. Assume breach — design as if the network is already compromised
3. Least privilege — minimum access required for each function

**25,000 peak RPS** for policy decisions.

**60-second decision cache TTL** — the Policy Engine caches decisions for 60 seconds to reduce latency. Tradeoff: a revoked access decision remains valid for up to 60 seconds after revocation. Acceptable for most enterprise scenarios; unacceptable for high-security environments where immediate revocation is required.

### Architecture

```
[User + Device] → [Application Access Proxy]
                          ↓
                  [Policy Engine] ← [Identity Provider (SSO)]
                          ↓       ← [Device Trust Service]
                          ↓       ← [Risk Scoring Pipeline]
                  [60s Decision Cache]
                          ↓
              [CASB]    [PAM]    [Protected Resources]
                          ↓
                  [Kafka Audit Log]
```

**Policy Engine** — the brain. Three signal inputs: Identity (who are you?), Device Trust (is your device healthy?), Risk Score (is this request anomalous?). All three must pass before access is granted.

### STRIDE

**S:** Session token theft allowing impersonation. Mitigation: short token lifetime, continuous risk scoring flags anomalous session behavior (impossible travel, device fingerprint mismatch).

**T:** Policy tampering — attacker modifies access policies to grant themselves elevated access. Mitigation: policy stored as version-controlled IaC, digital signatures, peer review required.

**R:** Attacker accesses resources and denies it. Mitigation: append-only audit log, every Policy Engine decision recorded with signal inputs and outcome.

**I:** Policy Engine decision cache exposes which resources a user can access. Mitigation: cache encrypted, access restricted to Policy Engine only.

**D:** Policy Engine DDoS — 25,000 RPS exhausts decision capacity. Mitigation: 60-second cache dramatically reduces Policy Engine load, geographic distribution.

**E:** Compromised admin modifies risk scoring thresholds to make their own malicious behavior score as low-risk. Mitigation: risk scoring configuration requires dual approval, all changes logged immutably.

**Score: 8/10 architecture, 5/6 STRIDE**

---

## Challenge 4 — MFA Service That Works Reliably Worldwide

### Problem Statement

Design an MFA service supporting SMS OTP, push notifications, TOTP, and FIDO2 hardware keys for users worldwide. The service must achieve 99.95% availability across 150+ countries.

### Requirements

**99.95% uptime** = 262.98 minutes (~4 hours 23 minutes) of downtime per year maximum.

**Factor ranking weakest to strongest:**

*SMS OTP (weakest)* — SIM swapping allows an attacker to take control of the victim's phone number. Telephone networks transmit SMS in plaintext over carrier infrastructure. Despite these weaknesses, SMS is the most widely deployed MFA because it requires no app installation.

*Push Notifications* — safer than SMS since the push channel is TLS-protected. Vulnerable to MFA fatigue attacks — repeatedly sending push requests until the victim taps approve out of frustration. Used against Uber in 2022. Mitigation: number matching.

*TOTP* — better than push because the secret can be stored offline. Vulnerable to real-time phishing proxies that intercept codes within the 30-second window.

*FIDO2/U2F (strongest)* — challenge-response cryptographically bound to the specific domain. A phishing site with a different domain cannot produce a valid response. Immune to real-time MITM attacks that defeat TOTP.

**Clock skew** — TOTP accepts ±1 step (±30 seconds), producing a 90-second total validity window. Codes marked consumed on first use prevents replay within this window.

### Architecture

```
[Client] → [Rate Limiter] → [Load Balancer] → [MFA Gateways (stateless fleet)]
                                                        ↓
                        [Fallback Orchestrator: FIDO2→TOTP→Push→SMS]
                                    ↓           ↓          ↓        ↓
                              [TOTP Validator] [Push] [SMS Aggregator] [FIDO2]
                                                        ↓
                              [Challenge Store (Redis, SET NX anti-replay)]
                              [Backup Code Store]
                              [Audit Log (Kafka, append-only)]
```

**Multi-provider SMS:** Twilio → AWS SNS → regional carrier fallback. Guarantees delivery across 150+ countries.

**Overlap window > longest peer cert cache TTL** — same principle as certificate rotation.

### STRIDE

**S:** SMS phishing — attacker tricks victim into delivering MFA code. TOTP real-time proxy — attacker intercepts code within 30-second window. U2F is theoretically vulnerable to DNS cache poisoning misdirecting user to attacker's server. DNSSEC on the domain mitigates this. MFA fatigue — number matching and per-account push rate limiting mitigate.

**T:** Challenge Store tampering — attacker modifies expected challenge responses, bypassing authentication. Mitigation: digital signatures on all Challenge Store records. HSM-backed storage for TOTP secrets.

**R:** Attacker bypasses MFA and denies it. Mitigation: append-only Kafka audit log with digital signatures and offsite backups — every factor attempt, success, failure, and enrollment change permanently recorded.

**I:** TOTP secret database breach exposes all users' enrollments simultaneously. Mitigation: encrypt TOTP secrets at rest with HSM-backed keys.

**D:** SMS gateway flooding — attacker triggers mass SMS sends to exhaust provider credits. Mitigation: per-account SMS send limits, anomaly detection on SMS volume. Rate Limiter + Load Balancer in front of MFA Gateway fleet.

**E:** Attacker phishes MFA code, accesses account, deletes original MFA method, replaces with attacker-controlled method, locks real user out. If victim is sysadmin — attacker gains ability to alter MFA system rules. Mitigation: MFA method changes require re-authentication with existing factor first.

**Score: 9/10 architecture, 5.5/6 STRIDE**

---

## Challenge 5 — Secure Session Management for a Mobile Banking App (20M Users)

### Problem Statement

Design the session management layer for a mobile banking application with 20 million active users across iOS and Android. Support multi-device sessions, inactivity timeouts, and geographic anomaly detection.

### Requirements

**Peak RPS calculation:** 10,000 concurrent users × 5 requests/second = **50,000 peak session validation RPS**.

**Sliding expiration** — the TTL resets on every valid request. The session expires after a period of *inactivity*, not a period from login. Contrast with fixed expiration where the session expires at a fixed time regardless of activity.

**Session fixation** — the attacker *plants* a token before the victim authenticates:
1. Attacker visits login page, receives pre-auth session token `abc123`
2. Attacker tricks victim into loading login page with that token embedded
3. Victim logs in with their own credentials — server associates `abc123` with victim's account
4. Attacker uses `abc123` — they already know it

**Mitigation:** issue a brand new session token on every successful login, invalidating any pre-login token.

**Replication lag** — when a session is revoked on the Redis primary, replicas have not yet received the update. A request hitting a replica milliseconds after revocation still sees the session as valid. Mitigation: synchronous replication on the revocation write path.

### Architecture

```
[Mobile Client]
        ↓
[Session Service] ← [Device Fingerprint Service]
        ↓         ← [Geolocation / Anomaly Detector]
[Redis Cluster (sliding TTL)] — "New token on login, pre-login tokens invalidated"
[Revocation List]
[Refresh Token Store (PostgreSQL)]
[Audit Log (Kafka)]
```

**Impossible travel detection** — session last seen in Los Angeles, next request from Tokyo 5 minutes later. Physically impossible. Flag for step-up MFA.

### STRIDE

**S:** Credential theft via phishing — attacker impersonates user. Session hijacking via XSS or SQL injection against Session Store. Device/geolocation spoofing via VPN. Session fixation — attacker plants known token. Mitigation: MFA, HttpOnly cookies, parameterized queries, new token on login.

**T:** SQL injection against Session Store or Refresh Token Store — attacker modifies session credentials or refresh tokens. Revocation List corruption — attacker removes their session from the list. Mitigation: parameterized queries, digital signatures on all records, refresh token family revocation on replay.

**R:** Attacker deletes session activity from audit pipeline. Mitigation: append-only Kafka, digital signatures, offsite backups.

**I:** MITM attacks disclosing session tokens in transit. Private Zone compromise exposing all session data. Mitigation: TLS/mTLS everywhere, encryption at rest.

**D:** Excessive requests exhausting Session Service. Mitigation: rate limiter, geographic load balancer, least-connections distribution. Redis exhaustion via millions of fake sessions — per-IP session creation rate limiting.

**E:** Attacker steals admin session credentials, escalates to admin access, modifies revocation list rules, disables append-only audit policy. Mitigation: FIDO2 U2F for admins, append-only policy enforced at Kafka broker level (not application level) — even admin credentials cannot disable it.

**Score: 8.5/10 architecture, 6/6 STRIDE — first perfect STRIDE**

---

## Challenge 6 — DDoS Detection and Mitigation Pipeline

### Problem Statement

Design a DDoS protection system for a platform receiving 500 Gbps of normal traffic. The system must detect and mitigate attacks within 30 seconds of onset.

### Requirements

**Three DDoS attack categories:**

*Volumetric (Layer 3/4)* — overwhelm available bandwidth. Example: DNS amplification — small requests to open resolvers spoofing victim's IP, resolvers send large responses amplifying 50–70x.

*Protocol (Layer 3/4)* — exploit protocol state machines. Example: SYN flood — thousands of SYN packets without completing handshake, exhausting server connection table.

*Application layer (Layer 7)* — exhaust server compute. Example: HTTP flood (legitimate-looking requests at high volume), Slowloris (partial requests held open indefinitely).

**BGP anycast** — multiple servers share the same IP. The internet routes traffic to the nearest PoP automatically. A 500 Gbps attack spread across 50 PoPs becomes 10 Gbps per PoP — within individual capacity.

**BGP blackholing** — drops ALL traffic to the target IP, legitimate and malicious alike. Last resort only — you stop the attack by taking yourself offline.

**30-second detection window** — split between Traffic Analyzer (10 seconds) and BGP propagation (20 seconds). BGP propagation is a hard physical constraint — cannot be accelerated.

### Architecture

```
[Internet / Attacker]
        ↓
[BGP Anycast PoPs / CDN Edge — volumetric absorption]
        ↓
[Rate Limiter Fleet (per-IP, per-ASN)]
        ↓
[Traffic Analyzer (10s sliding window detection)]
        ↓              ↓
[Scrubbing Center]   [WAF Layer]
(L3/L4 attacks)    (L7 attacks)
        ↓
[Origin Server — allowlists CDN egress IPs only]
        ↓
[Alert + Auto-mitigation Trigger]
  → [PagerDuty — human override required for BGP blackholing]
        ↓
[Audit Log]
```

**Three-attack, three-mitigation mapping:**
- Volumetric → Anycast + CDN edge absorption
- Protocol (SYN flood) → SYN cookies
- Application layer → WAF + Rate Limiter
- Last resort → BGP blackholing (human approval required)

### STRIDE

**S:** IP address spoofing makes attack traffic appear legitimate. Mitigation: BCP38 ingress filtering at carrier level drops spoofed packets. Reflection and amplification — attacker spoofs victim's IP, amplifiers send large responses to victim. BGP hijacking redirects traffic to attacker-controlled servers — mitigation: RPKI (Resource Public Key Infrastructure) cryptographically signs IP prefix announcements. DNS cache poisoning — mitigation: DNSSEC.

**T:** Scrubbing center policy tampering, WAF rule manipulation, Origin Server allowlist modification, audit log tampering. Mitigation: append-only Kafka, digital signatures, backups. WAF management access via PAM with JIT credentials.

**R:** Attacker disables monitoring to hide DDoS activity. Mitigation: append-only audit log, digital signatures, offsite backups. Every detection event and mitigation action permanently recorded.

**I:** Private Zone compromise reveals detection thresholds — attacker reverse-engineers thresholds to craft attacks staying just below detection. mTLS between all Private Zone components. Never expose confidence scores publicly.

**D:** Despite load balancer fleet, volumetric attacks can still overwhelm individual nodes. Slowloris exhausts connections. Mitigation: idle connection timeout, geographic load balancing. NAT Gateway capacity exhaustion from high outbound traffic.

**E:** Stolen admin credentials → modify scrubbing center rules, disable WAF rules, alter mitigation triggers. Scrubbing center management interface compromise — attacker disables mitigation rules entirely. Mitigation: management interfaces on separate network segment, PAM-controlled JIT access, dual approval for rule changes.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 7 — Secure Service-to-Service Communication (500 Services, 3 Clusters)

### Problem Statement

Design mutual TLS infrastructure for a microservices platform with 500 services across 3 Kubernetes clusters. Every service-to-service call must be authenticated, encrypted, and authorized.

### Requirements

**mTLS vs regular TLS** — in regular TLS only the server presents a certificate. In mTLS both parties present certificates and verify each other. Every service proves its identity cryptographically on every connection. Eliminates IP-based trust entirely.

**SPIFFE** — Secure Production Identity Framework for Everyone. Provides cryptographic workload identity independent of network location. A service's identity is its SPIFFE URI (`spiffe://k8s.example.com/ns/payments/sa/payment-processor`), not its IP address. Works for any software system — not just microservices, not just Kubernetes.

**Certificate rotation with zero downtime** — overlap window where both old and new certificates are valid simultaneously. Duration must exceed the longest peer certificate cache TTL across all 500 services.

**Intermediate CA pattern** — root CA kept offline (air-gapped). Intermediate CA issues service certificates. If intermediate CA is compromised: revoke it with the root CA and issue a new one. If only a root CA existed and it was compromised: full cluster rebuild required.

### Architecture

```
Data Plane Layer:
[Pod 1: App Container + Envoy Sidecar] ←mTLS→ [Pod N: App Container + Envoy Sidecar]
(×500 services across 3 clusters)

Control Plane Layer:
[Service Mesh Control Plane (Istio)] — distributes certs + policies to all sidecars
        ↓       ↑
[SPIFFE Identity Issuer (SPIRE)] — attests workload identity
[Authorization Policy] — deny-by-default, service-level access control
[Certificate Authority] — Root CA offline, Intermediate CA online
[Certificate Store (Vault PKI — HSM-backed)]
[Certificate Rotation Scheduler] — overlap window > longest cache TTL
[Observability Pipeline] → [Audit Log (Kafka)]
```

**The security guarantee:** no service can communicate with another without (1) proving its SPIFFE identity, (2) having permission in AuthorizationPolicy, and (3) successfully completing mTLS. All three must pass simultaneously.

### STRIDE

**S:** Stolen mTLS certificate — short 24hr lifetimes limit damage window. Service identity spoofing via DNS manipulation — DNSSEC mitigates. Rogue sidecar injection — admission controller restricts which images can run as sidecar proxies, Cosign signature verification required.

**T:** Certificate Store tampering — HSM-backed Vault PKI, private keys never leave hardware boundary. Authorization Policy tampering — version-controlled IaC with signed commits, peer review required. Audit log tampering — append-only Kafka, digital signatures, offsite backups.

**R:** Attacker conducts malicious inter-service activity then deletes evidence. Append-only Kafka, digital signatures, offsite backups. Every certificate operation and policy enforcement event permanently recorded.

**I:** Admin compromise — mTLS on all inter-service communication, PAM-controlled JIT access. Private key exposure in Kubernetes secrets — SPIRE delivers SVIDs via Unix domain socket, never written to disk.

**D:** Pod and Control Plane flooding — rate limiters, load balancers. Certificate Store poisoning with expired certificates — strong auth on Certificate Store, least-privilege service accounts for write access.

**E:** Overly permissive AuthorizationPolicy — deny-by-default posture, policy changes require CI/CD peer review. Admin credential theft — FIDO2 U2F for all admin access.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 8 — TLS Termination and Certificate Rotation (10,000 Nodes)

### Problem Statement

Design certificate lifecycle management for a fleet of 10,000 load balancers and edge nodes. Certificates must renew automatically, rotate with zero downtime, support OCSP stapling, and alert on any expiry within 14 days.

### Requirements

**OCSP stapling** — instead of the browser calling the CA's OCSP server on every connection, the load balancer pre-fetches the OCSP response and caches it locally. Stapled to every TLS handshake — no extra round trip for users. Cache refreshed every 4 hours.

**Certificate Store vs Certificate Inventory Database:**
- *Certificate Store* — where actual certificate material lives (private keys, signed certs, chains). HashiCorp Vault PKI, HSM-backed
- *Certificate Inventory Database* — where certificate metadata lives (node assignment, expiry date, rotation status). What the alerting pipeline queries for 14-day expiry warnings

**SNI (Server Name Indication)** — allows a single load balancer node to serve multiple domains with different certificates. Client announces target hostname during TLS ClientHello before the certificate is presented. Security implication: SNI is sent in plaintext — a network observer can see which domain a client is connecting to over HTTPS.

**Auto-Renewal Agent sequence:**
1. Generate CSR → submit to CA
2. CA signs → agent receives signed certificate
3. Write to Certificate Store + update Certificate Inventory Database
4. Deploy new certificate alongside old — overlap window begins
5. Overlap window expires → old certificate removed

### Architecture

```
[Internet] → [Load Balancer Fleet (10,000 nodes, SNI routing)]
                    ↓ (Auto-Renewal Agent per node)
             [Certificate Authority (Intermediate CA, Let's Encrypt)]
             [Certificate Store (Vault PKI, HSM-backed)]
             [Certificate Inventory Database]
             [OCSP Stapling Cache per node (refreshed 4 hours)]
                    ↓
             [Alerting Pipeline] → [PagerDuty + Auto-Renewal Agent trigger]
                                 → [Rollback Mechanism]
             [Audit Log (Kafka, append-only)]
```

**PagerDuty + Auto-Renewal Agent dual trigger** — when expiry < 14 days: simultaneous human notification AND automated renewal. Automated remediation without waiting for human action.

### STRIDE

**S:** SYN flood spoofing — SYN cookies. CA private key theft enabling forged certificates — FIPS 140-2 Level 3 HSM for CA private key. DNS cache poisoning of ACME validation — DNSSEC on domain. BGP hijacking rerouting traffic to attacker-controlled servers — RPKI mitigates. Certificate Transparency logs detect fraudulent certificates issued for the domain.

**T:** Certificate Store tampering — HSM-backed Vault PKI. Certificate Inventory Database tampering to suppress expiry alerts. Audit log tampering. Mitigation: digital signatures on all records, append-only logs, tested backups.

**R:** Attacker conducts malicious certificate operations — issues fraudulent certs, blocks renewals — then deletes audit evidence. Append-only Kafka, digital signatures, offsite backups. Every certificate operation permanently recorded.

**I:** Admin compromise exposing Certificate Store, Inventory Database, and OCSP cache. Attacker learns which certs are approaching expiry and times forged renewal. Mitigation: strong auth/authz, Certificate Transparency logs detect any fraudulent cert within minutes.

**D:** DDoS overwhelming load balancers — Slowloris exhausts connections, mitigation: idle timeout + geographic load balancing. CA private key theft blocking legitimate renewals — HSM prevents theft. BGP hijacking as DoS — RPKI mitigates.

**E:** CA private key theft — attacker becomes the CA, signs arbitrary certificates, denies legitimate renewals. HSM storage. Admin credential theft — FIDO2 U2F, least-privilege delegation.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 9 — Network Segmentation Strategy (AWS VPC)

### Problem Statement

Create a network segmentation strategy for a SaaS platform on AWS with separate production, staging, and development environments. Define VPC design, subnet tiers, security group rules, and east-west traffic inspection.

*Note: this was my first purely AWS infrastructure challenge. All previous challenges were protocol and distributed systems design. The learning curve was steeper here.*

### Requirements

**The Library of Congress mental model:**
- *Lobby (Public Subnet)* — visitors can enter, front desk (ALB) directs them, staff exit (NAT Gateway) for outbound only
- *Reading rooms (Private App Subnet)* — only after front desk verification
- *Secure vault (Private Data Subnet)* — authorized staff only, no visitor access ever

**Three VPC isolation policy:**
- Development ↔ Staging: allowed both directions
- Staging → Production: read-only, specific endpoints only
- Development → Production: BLOCKED entirely (no arrow = no path)

**No SSH — SSM Session Manager only:** SSH requires open port 22 — permanent attack surface. SSM Session Manager: no inbound port open, IAM-authenticated, fully logged to CloudTrail.

**VPC Flow Logs → S3 → Athena:** Flow logs capture every network connection. Athena queries them with SQL for forensic analysis. GuardDuty analyzes in real time.

### Architecture

```
Production VPC          Staging VPC          Development VPC
├── Public Subnet       ├── Public Subnet    ├── Public Subnet
│   ├── ALB             │   ├── ALB          │   ├── ALB
│   └── NAT GW          │   └── NAT GW       │   └── NAT GW
├── Private App         ├── Private App      ├── Private App
│   └── EC2/ECS         │   └── EC2/ECS      │   └── EC2/ECS
│   "No SSH. SSM only"  │                    │
└── Private Data        └── Private Data     └── Private Data
    └── RDS/Redis           └── RDS/Redis        └── RDS/Redis

All VPCs:
- SG: ALB←443 internet. App←ALB SG only. Data←App SG only.
- VPC Flow Logs → S3 → Athena (forensic queries)
- Network Firewall (Suricata rules) — east-west inspection

Transit Gateway:
Dev↔Staging: allowed | Staging→Prod: read-only | Dev→Prod: NO ARROW
```

### STRIDE

**S:** IP address spoofing between components — SYN cookies, AWS security groups are identity-based (not purely IP-based). Rogue instance in Staging calling Production — Transit Gateway routing rules block this explicitly.

**T:** Security group rule manipulation by overprivileged IAM role — AWS Config detects and alerts on security group modifications. Suricata rule tampering — version-controlled IaC, signed commits.

**R:** Attacker deletes CloudTrail or Flow Log records. VPC Flow Logs disabled by attacker with IAM permissions — this is the critical R threat specific to AWS: AWS Config detects Flow Log disablement and alerts immediately. Append-only logs, digital signatures, offsite backups.

**I:** MITM between components — mTLS on all inter-service communication. Production data accessible from Staging via misconfigured Transit Gateway — strict API gateway controls on read-only endpoint, least-privilege IAM roles for Staging.

**D:** Security group misconfiguration causing self-inflicted outage — IaC for all security group rules with automated testing. NAT Gateway capacity exhaustion — CloudWatch alerts on bandwidth utilization.

**E:** Staging compromise leading to Production access via misconfigured Transit Gateway — Transit Gateway route tables restrict Staging→Production to one specific read-only endpoint. IAM permission boundaries enforce that Development IAM roles cannot access Production resources regardless of assigned permissions.

**Score: 8.5/10 architecture, 5/6 STRIDE**

---

## Challenge 10 — Secure API Gateway (200 Microservices, 10M req/min)

### Problem Statement

Design an API gateway layer for a platform with 200 backend microservices serving 10 million API requests per minute. The gateway must validate JWTs, enforce per-user and per-client rate limits, detect abuse patterns, and add traffic metadata without adding more than 5ms of latency.

### Requirements

**Scale:** 10M requests/minute = **166,666 requests/second**.

**5ms latency budget breakdown:**
- WAF inspection: ~0.5–1ms
- JWT local validation: ~0.2ms
- Redis rate limit check: ~1ms
- Routing decision: ~0.1ms
- Metadata enrichment: ~0.2ms
- **Total: ~2–3ms** — within budget

**JWT local validation** — at 166,666 req/s, a remote JWT validation service becomes a bottleneck immediately. The correct approach: each gateway instance caches the Auth Server's JWKS public keys locally. JWT validation is a local cryptographic operation — sub-millisecond, no network call. Tradeoff: stale key window after rotation (5–15 minutes).

**Two-tier rate limiting:**
- *Pre-auth (not logged in):* rate limit by IP address — the only available signal
- *Post-auth (logged in):* rate limit by user ID extracted from JWT — each user has their own independent quota

Redis key structure:
```
rate:ip:{ip_address}      → pre-auth sliding window counter
rate:user:{user_id}       → post-auth sliding window counter
rate:client:{client_id}   → per-client sliding window counter
```

**Fail closed on Redis outage** — if Redis goes down, return 503 rather than allowing unlimited requests.

### Architecture

```
[Client] → [Rate Limiter (Redis)] → [Load Balancers] → [WAF] →
── Trust Boundary ──
[API Gateway Cluster (stateless)]
  ├── JWT Validator (local, JWKS cached)
  ├── Auth Service (opaque token introspection only)
  ├── Redis Cluster (per-user/per-client rate limits)
  ├── Request Metadata Enrichment (X-User-ID, X-Risk-Score, X-Request-ID)
  └── Abuse Detection Engine (velocity, anomaly, pattern)
        ↓
[Backend Service Router] → [200 Backend Microservices]
        ↓
[Audit Log (Kafka, append-only)]
```

**Metadata injected as headers:**
```
X-User-ID, X-User-Scopes, X-Risk-Score
X-Geo-Location, X-Request-ID, X-Client-ID
```

### STRIDE

**S:** IP spoofing to bypass per-IP rate limits — SYN cookies at TCP layer. Stolen credentials enabling spoofed requests — strong password + FIDO2 U2F. JWT algorithm confusion — attacker submits token with `alg: none` or switches RS256 to HS256, exploiting libraries that trust the algorithm claim in the token header. Mitigation: strict algorithm whitelist, reject any token with unexpected algorithm. JWKS key substitution — gateway only accepts keys from trusted JWKS endpoint, never from token header.

**T:** JWT payload manipulation — attacker modifies claims (user ID, scopes, role). RS256 signature verification makes any payload modification immediately detectable. Redis rate limit counter tampering — restricted access via least-privilege service accounts.

**R:** Attacker conducts malicious API activity and deletes audit evidence. Append-only Kafka, digital signatures, offsite backups. Every request permanently recorded with timestamp, client ID, user ID, endpoint, risk score, response code.

**I:** MITM between gateway and backends — TLS/mTLS everywhere. JWT claims containing PII logged in access logs — scrub or hash PII fields before writing to logs, never log the full JWT token.

**D:** Request flooding — rate limiter + load balancer. Redis failure disabling rate limiting — fail closed (503 until Redis recovers). Local in-memory fallback provides rough limiting during outage.

**E:** JWT scope escalation — client requests endpoints beyond their token scopes. Gateway validates requested endpoint against JWT scopes before routing — mismatch returns 403 at gateway. Policy tampering after server compromise — IaC with signed commits, FIDO2 U2F for admins.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 11 — Safe Secrets Storage and Rotation (500 Microservices, 10,000 Secrets)

### Problem Statement

Build a centralized secrets management service for a platform with 500 microservices consuming 10,000 secrets. Secrets must be HSM-backed, automatically rotated without service downtime, and audited on every access.

### Requirements

**The secret zero problem** — how does the first microservice authenticate to the secrets manager without already having a secret? Solutions: SPIFFE/SPIRE SVIDs, AWS IAM roles, or Vault AppRole.

**Envelope encryption:**
```
Root Key (HSM) — never leaves hardware
        ↓ wraps
KEK (KMS)
        ↓ wraps
DEK (memory only)
        ↓ encrypts
Secret value (stored as ciphertext in Secret Store)
```

The Secret Store contains **ciphertext only** — never plaintext. A full database dump gives an attacker only useless ciphertext.

**Dynamic secrets** — generated on demand with TTL. Unique username per service per request (e.g. `vault_payment_svc_20260419_abc123`). Auto-revoked on expiry. No long-lived passwords anywhere.

**Break-glass access** — emergency override. M-of-N approval (no single person can activate unilaterally). Time-bound (1–4 hours). Full audit trail written **before** access is granted — prerequisite, not side effect. Mandatory post-incident review on every activation.

### Architecture

```
Public Zone:
[Microservices (500)] → [Service Identity (SPIFFE/IAM)]
[Emergency Situation] → [M-of-N Approval] → [Break-glass Access]

Private Zone:
[Secrets Manager API]
  ├── [HSM Cluster — Root Key, FIPS 140-2 Level 3]
  ├── [KMS — key hierarchy management]
  ├── [Secret Store — ciphertext only]
  ├── [Dynamic Secrets Engine — per-request TTL credentials]
  └── [Auto-rotation Scheduler — overlap window]
        ↓
[Audit Log (Kafka, append-only)]
```

### STRIDE

**S:** Attacker spoofs microservice identity to steal another service's secrets — mTLS authentication since microservices are talking to each other. Attacker social engineers admins into granting emergency break-glass access — no purely technical defense here. Admins must be trained to calmly assess the behavior and resist exploitation. M-of-N approval is a partial technical mitigation — attacker must compromise M separate admin accounts simultaneously. FIDO2 U2F hardware keys make this attack remote-impossible.

**T:** Attacker tampers audit logs, Secret Store, HSM key rotations, KMS keys, Dynamic Secrets Engine, and auto-rotation policies. Defense: tested backups, append-only log policy, digital signing of sensitive records.

**R:** Attacker edits or deletes activity from Audit Log. Append-only policy — no delete permissions exist. Tested backups for recovery. Digital signing of all records.

**I:** Attacker eavesdrops on inter-service communication — mTLS defends against both eavesdropping and identity spoofing. Sensitive records encrypted at rest. HSM/KMS for private key management. Plaintext secrets in logs — structured logging with explicit secret field scrubbing, never log actual secret values.

**D:** Excessive requests overwhelming Secrets Manager API — rate limiters and load balancers. HSM Cluster failure making all 10,000 secrets simultaneously inaccessible — HSM in active-active cluster across multiple availability zones.

**E:** Attacker steals M admin credentials and simulates M-of-N approval — gains unlimited Private Zone access, can read/write/edit anything, lock out any user, steal any microservice's secrets. Mitigation: FIDO2 U2F hardware keys make coordinated remote social engineering attacks extremely difficult. Least privilege delegation restricts each admin's access scope.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 16 — Real-Time Threat Detection System (100K Endpoints, 500 Microservices, 1TB/day)

### Problem Statement

Build a real-time threat detection pipeline ingesting 1TB/day of logs from 100,000 endpoints and 500 microservices. Detect multi-stage attacks within 60 seconds. Support custom detection rules. Scale to 50MB/sec peak ingest without data loss.

### Requirements

**1TB/day = ~11.5MB/sec average, 50MB/sec peak.**

**This system is never finished** — attackers continuously evolve TTPs. Every detection rule is a response to a technique they already used. Detection engineering is permanent ongoing work.

**Kafka is not the audit log here** — different role than previous challenges. Here Kafka is the ingestion pipeline: buffering (absorbs spikes without dropping logs), durability (7-day retention, replication factor 3, replay capability), and parallelism (100 partitions, 100 Flink workers processing simultaneously).

**The 60-second window** — split between Flink stream processing (detection: target under 10 seconds) and any downstream response. Short sliding windows required — 10-second or less. A 5-minute rolling average catches attacks but misses the 60-second SLA.

**Log flood as evasion, not just DoS** — attacker generating millions of benign-looking log events from compromised endpoints is not just trying to crash the system. They are deliberately creating noise to hide real malicious activity. Per-source rate limiting closes both the DoS and evasion path simultaneously — volume spike is itself a detection signal.

### Architecture

```
[Endpoints (100K)] + [Microservices (500)]
        ↓
[Log Collectors — Filebeat/Fluentd per host and per service]
        ↓
[Kafka — 10 brokers, 100 partitions, replication factor 3, 50MB/sec peak]
"Per-source rate limiting — volume spike = detection signal"
        ↓
[Stream Processor (Apache Flink) — parsing, enrichment, correlation]
        ↓               ↓
[Detection Rule      [Elasticsearch — hot storage 90 days]
 Engine (Sigma)]          ↓
        ↓            [S3 + Glacier — cold storage 7 years]
[Alert Engine             ↓
 (dedup+enrich+       [Kibana / SIEM Dashboard]
  severity)]
        ↓
[SOAR — automated playbooks]
        ↓              ↓
[PagerDuty]    [Forensics Store]
        ↓
[Append-only Audit Log]
```

**Alert Engine purpose** — without it, 10,000 raw alerts/day overwhelm SOAR with duplicates. Alert Engine deduplicates, enriches (MITRE ATT&CK mapping, asset owner, severity score), and routes (low → ticket, high → SOAR + page).

### STRIDE

**S:** Microservice identity spoofing to bypass inspection — mTLS authentication. Admin credential theft enabling access to Kibana — strong password + FIDO2 U2F. Compromised microservice sending forged log events to frame another service — cryptographic signing of log events at source before sending to Kafka.

**T:** Audit log tampering, cold storage tampering, Elasticsearch record tampering, Forensics Store tampering — append-only policy, digital signatures, tested backups. Detection Rule Engine tampering — attacker modifies Sigma rules to whitelist their own TTPs. Mitigation: version-controlled IaC with signed commits, peer review required for all rule changes.

**R:** Attacker edits activity in Audit Log. Append-only Kafka, tested backups, digital signing of records.

**I:** Eavesdropping on inter-component traffic — mTLS everywhere. Sensitive records encrypted at rest. Sensitive data captured in logs — log scrubbing pipeline detects and redacts sensitive patterns before reaching Elasticsearch or S3.

**D:** Attacker floods system with excessive requests — even benign requests overwhelm pipeline. Rate limiters and load balancers in front of Log Collectors. Per-source rate limiting at Kafka ingestion layer — each endpoint has a maximum log volume quota. Volume spike is itself a detection signal — the flood becomes self-defeating.

**E:** Admin credential theft → view all Private Zone components, reassign permissions, craft requests to avoid detection, corrupt policies. Strong authentication (password + FIDO2 U2F). SIEM admin access allowing attacker to disable detection rules — detection rule changes require dual approval, immutable audit log entries.

**Score: 8.5/10 architecture, 5.5/6 STRIDE**

---

## Challenge 20 — Secure CI/CD Pipeline (300 Engineers, 100 Deployments/Day)

### Problem Statement

Design a secure software delivery pipeline for 300 engineers pushing 100 deployments per day. Every artifact must be scanned, signed, and verified before reaching production. Secrets must never appear in pipeline logs. Every deployment must be auditable and reversible.

### Requirements

**Why sign container images:** unsigned images allow arbitrary code execution on the host. An attacker who can push an unsigned image and get it deployed has effectively achieved RCE on production infrastructure.

**Sigstore trio:**
- *Cosign* — signs and verifies container image signatures
- *Fulcio* — CA issuing short-lived certificates (10 minutes) bound to pipeline OIDC identity. No long-lived keys
- *Rekor* — append-only public transparency log recording every signature event permanently

**Staging after signing** — staging receives the signed artifact and runs integration tests. By testing the signed artifact, what you test is exactly what gets deployed. Any modification invalidates the signature.

**100 deployments/day baseline** — a known operational signal. Sudden spike to 500/day is anomalous and worth alerting on even if every individual deployment passes all checks.

**OIDC eliminates secrets in logs** — pipeline authenticates via short-lived OIDC tokens. No hardcoded credentials exist to accidentally capture in build logs.

### Architecture

```
Public Zone:
[Engineers] → [Source Control]

Private Zone:
[SAST Scanner (Semgrep)] ← PR Comment back to engineer
        ↓
[Dependency Scanner (Snyk/Dependabot)]
        ↓
[Build System] — compiles, creates container image
        ↓
[Container Image Scanner (Trivy/Grype)]
        ↓
[Signing Service (Cosign + Sigstore/Fulcio/Rekor)]
        ↓
[Staging Environment Gate — integration + security regression tests]
        ↓
[Production Admission Control]
  → [PagerDuty Alert] — unsigned image = immediate alert
  → [Deployment Audit Log]
        ↓
[Deployed App (Production)]
  ↕ [Rollback Mechanism]
  ↕ [Secrets Manager — No secrets in env vars, OIDC auth only]
```

### STRIDE

**S:** Developer credential theft — attacker pushes malicious code as legitimate engineer. Strong password + FIDO2 U2F required for all engineers. Cosign+Sigstore private key injection — attacker injects known private keys to later sign malicious builds. Strict auth/authz restricting access. Dependency confusion — attacker publishes malicious public package with same name as internal private package. Mitigation: pin exact dependency versions and checksums, private artifact proxy serving only approved packages.

**T:** Source code tampering, SAST rule tampering, Container Image Scanner rule tampering, Cosign signing policy tampering, signature algorithm downgrade (weakening from RS256 to HS256 or none — disabling signature verification entirely), Audit Log tampering, Secrets Manager records tampering. Mitigation: strong auth (password + FIDO2 U2F), strict authorization, least privileges, digital signing of all records, tested backups.

**R:** Attacker edits or deletes activity from Audit Log. Append-only policy, tested backups, digital signing of records.

**I:** Eavesdropping between pipeline components — TLS/mTLS. Secrets accidentally in pipeline logs — OIDC authentication means no long-lived secrets exist to be captured. Log scrubbing as secondary defense.

**D:** Attacker overwhelms pipeline with excessive deployment requests after compromising engineer account — rate limiter enforced. PagerDuty alert fires if deployment count significantly exceeds 100/day baseline — volume deviation is a detection signal.

**E:** Attacker steals admin credentials → tampers policies → corrupts Production Admission Control (allows any image through) → alters Audit Log policies (disables append-only) → hides all malicious activity → hijacks tested backups (deletes legitimate backups, replaces with attacker's own). Once the attacker controls backups there is no point of return. Strong authentication and authorization checks are not optional.

**Score: 8.5/10 architecture, 6/6 STRIDE — second perfect STRIDE**

---

## Challenge 22 — Image Integrity Checks for Container Builds (5,000 Images, 50 Teams)

### Problem Statement

Design a container supply chain security system ensuring every image running in production was built by a trusted pipeline, has not been tampered with, and has a verifiable build provenance. 5,000 images across 50 teams on Kubernetes.

### Requirements

**Cosign signatures alone are not enough** — a signature proves the image was not tampered with after signing. It does not prove how it was built. An attacker who compromises a developer's GitHub account can push malicious code, trigger the pipeline, and produce both a valid Cosign signature and valid SLSA provenance — because the build genuinely ran in GitHub Actions.

**SLSA Build Provenance** — signed by the pipeline's OIDC identity, not a human key. Records: exact image digest, source commit SHA, pipeline identity, build timestamp, build environment. Bound to the specific build execution — cannot be retroactively applied to a different image.

**Realistic attack paths against GitHub Actions:**
1. Compromising GitHub's infrastructure (extremely unlikely)
2. Compromising a developer's GitHub account (realistic — mitigated by FIDO2 U2F + branch protection requiring second reviewer)
3. Compromising a pipeline secret — eliminated by OIDC authentication (no long-lived secrets in pipelines)

**Binary Authorization / Admission Controller** — intercepts every Kubernetes pod scheduling request. Verifies: (1) valid Cosign signature AND (2) valid SLSA provenance. Both must pass. The final gate — no image runs without verified attestations, period.

**5,000 images baseline** — known operational signal. Volume spike is a detection signal.

### Architecture

```
Public Zone:
[CI Build System] ↔ [SLSA Build Provenance Generator]
(run simultaneously — provenance bound to build execution)

Private Zone:
[Image Vulnerability Scanner (Trivy/Grype)]
        ↓
[Cosign Signing Service] ↔ [Fulcio (10-min OIDC certs)]
                         ↔ [Rekor (transparency log)]
        ↓
[Container Registry (OCI-compliant, stores signatures as OCI artifacts)]
        ↓
[Binary Authorization / Admission Controller]
  ← [Policy Engine — version-controlled IaC, dual approval]
  — verifies Cosign signature + SLSA provenance in Rekor
        ↓              ↓
[Kubernetes Pod]   [PagerDuty Alert — unsigned image]
        ↓
[Audit Log (Kafka, append-only)]
```

### STRIDE

**S:** Developer credential theft enabling malicious code push or OIDC token spoofing for SLSA provenance generation. Clever attackers attempt to circumvent authorization checks — even modern AI agents struggle to detect and mitigate these. Strong authentication (password + FIDO2 U2F) is the best defense. Fulcio certificate spoofing — strict auth/authz restricting access to Fulcio. Registry spoofing — attacker directs Binary Authorization to pull from malicious registry. Mitigation: pin trusted registry domain in Binary Authorization policy.

**T:** Image Vulnerability Scanning policies, Fulcio TLS certificates, fake certificates appended to Rekor, Container Registry signature records, Audit Logs, commit signatures, and OIDC credential theft corrupting builds. Mitigation: mTLS between services, strong auth (password + FIDO2 U2F), strict authorization, digital signing of all records, tested backups.

**R:** Attacker edits or deletes malicious activity from Audit Log. Append-only policy, tested backups, digital signing of records.

**I:** mTLS between all components, encryption of sensitive data at rest. Ideally private keys managed by HSM/KMS — directly applicable since Fulcio's signing keys are the most sensitive material in this system. Build logs accidentally capturing credentials — OIDC authentication eliminates long-lived secrets from pipelines.

**D:** Attacker spawns multiple deployment requests past the expected 5,000 images across 50 teams. Rate Limiter and Load Balancer guard the system. PagerDuty alerts if deployment volume significantly exceeds baseline — volume deviation is a detection signal. Container Registry unavailability blocks all deployments — multi-AZ replication mitigates.

**E:** Attacker steals Fulcio CA private key — starts signing spoofed TLS certificates, allows malicious builds to bypass image integrity check. TLS private key must be stored in HSM/KMS — key material never leaves hardware boundary. Admin credential theft — strong auth/authz, least privileges. Binary Authorization policy escalation — attacker weakens or disables admission policy. Mitigation: policy changes require dual approval and immutable audit log entries.

**Score: 9/10 architecture, 5.5/6 STRIDE**

---

## The Pattern That Kept Defeating Me

Across 14 challenges, one gap appeared consistently: **Repudiation**.

Every single time. The first four challenges I missed it entirely. The next eight I got it partially. By Challenge 11 it finally clicked.

The R in STRIDE is always the same answer regardless of the system:

*"An attacker performs malicious actions then attempts to delete the evidence."*

The mitigation is always three layers:
1. **Append-only Kafka** — no delete permissions exist at any level
2. **Digital signatures** on every log record — tampered records have invalid signatures
3. **Offsite backups** — independent copy for recovery even if primary store is destroyed

Write that on your hand before your security engineering interview.

---

## The Other Pattern: HSM for Cryptographic Material

Any component storing private keys, signing keys, or encryption keys should be HSM-backed. Always. In every challenge. The pattern:

*"Attacker compromises the server. Attacker cannot extract private keys because they never left the HSM hardware boundary."*

This pattern appears in: Auth System (TOTP secret encryption), MFA (TOTP secrets), TLS Rotation (CA private key), Service Mesh (Certificate Store), Secrets Management (Root Key), CI/CD (Cosign keys), Image Integrity (Fulcio CA key).

When in doubt: HSM.

---

## Scores Summary

| Challenge | Architecture | STRIDE | Notable |
|---|---|---|---|
| 1 — Auth (1B users) | 8/10 | 5.5/6 | |
| 2 — OAuth (50K apps) | 8/10 | 5.5/6 | |
| 3 — Zero Trust | 8/10 | 5/6 | |
| 4 — MFA Worldwide | 9/10 | 5.5/6 | |
| 5 — Sessions (20M users) | 8.5/10 | 6/6 | First perfect STRIDE |
| 6 — DDoS | 8.5/10 | 5.5/6 | |
| 7 — Service Mesh | 8.5/10 | 5.5/6 | |
| 8 — TLS Rotation | 8.5/10 | 5.5/6 | |
| 9 — Network Segmentation | 8.5/10 | 5/6 | First AWS challenge |
| 10 — API Gateway | 8.5/10 | 5.5/6 | |
| 11 — Secrets Management | 8.5/10 | 5.5/6 | |
| 16 — Threat Detection | 8.5/10 | 5.5/6 | |
| 20 — Secure CI/CD | 8.5/10 | 6/6 | Second perfect STRIDE |
| 22 — Image Integrity | 9/10 | 5.5/6 | |

---

## Resources Used Across All Challenges

- *Designing Data-Intensive Applications*, Kleppmann & Riccomini, 2nd ed. — Chapters 6, 9, 11, 12
- *API Security in Action*, Madden (Manning) — Chapters 10, 11
- *Full Stack Python Security*, Byrne (Manning) — Chapters 7, 8
- *AWS Security*, Shields (Manning) — Chapter 5
- Saed Farah's 40 Real Security Engineering Problems: [secengweekly.substack.com](https://secengweekly.substack.com/p/if-i-had-to-interview-security-again)
- Sigstore documentation: [docs.sigstore.dev](https://docs.sigstore.dev)
- SLSA framework: [slsa.dev](https://slsa.dev)
- Cloudflare Learning Center: [cloudflare.com/learning/ddos](https://cloudflare.com/learning/ddos)
- MITRE ATT&CK Framework: [attack.mitre.org](https://attack.mitre.org)
- RPKI documentation: [rpki.readthedocs.io](https://rpki.readthedocs.io)
- SPIFFE documentation: [spiffe.io](https://spiffe.io)

---

## What Is Next

I am working through all 25 of Saed's challenges. After that I am generating an extended set covering:
- Saed's remaining 15 problems not in the original PDF
- AI-specific security challenges (prompt injection defense, model weight protection, RAG pipeline security, LLM API security, training data poisoning)
- Gap challenges targeting the STRIDE domains where my scores were weakest

All diagrams, exercises, and blog posts are at [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises).

Star it if this helped. Drop what you would have designed differently in the comments — I am genuinely curious where your architecture diverges from mine.

---

*Tanveer Salim — Security Engineer in training. Intel IPAS threat modeler (553 threats, 100+ engineers, STRIDE methodology). dev.to/fosres | github.com/fosres*
