---
title: "Can You Explain the TLS Handshake? A Security Engineering Interview Challenge"
published: false
description: "Test your understanding of TLS 1.3 handshakes and forward secrecy with these real interview questions. Includes step-by-step solutions."
tags: security, networking, interviews, tls
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/placeholder.jpg
---

## The $4.2 Million MITM Attack Nobody Saw Coming

It was a regular Tuesday morning when the CFO of a mid-sized financial services firm clicked "Wire Transfer: $4,200,000" from what appeared to be their bank's legitimate portal. The SSL padlock icon was there. The domain looked right. Everything seemed normal.

**Except it wasn't their bank.**

An attacker had positioned themselves between the CFO and the actual bank, intercepting every packet. No encryption. No certificate validation. Pure HTTP traffic dressed up to look secure. By the time the fraud was discovered three hours later, the money had bounced through six countries and vanished.

The post-mortem revealed the terrifying truth: **the internal accounting system had never been configured to use HTTPS**. Every login, every transaction, every authorization—transmitted in plaintext across the corporate network for five years.

One compromised switch. One packet sniffer. Game over.

## Why TLS is Everywhere (And Why You Need to Understand It)

This is why **Transport Layer Security (TLS)** has become the bedrock of internet security. Every HTTPS connection, every API call, every mobile app talking to a backend—they all depend on TLS to prevent exactly this kind of man-in-the-middle (MITM) attack.

But here's the reality: **most developers don't actually understand how TLS works.**

They know it encrypts stuff. They know you need certificates. They've seen "SSL/TLS handshake" in error messages. But ask them to explain the actual protocol flow? *Crickets.*

If you're interviewing for Security Engineering roles (or any backend/infrastructure position), you **will** be asked about TLS. It's not optional knowledge—it's table stakes.

## Before We Dive In: Help Me Help You! 📊

**Quick favor:** I'm building these exercises based on what YOU need. **[Take this 10-second poll](https://strawpoll.com/wby5QoKAkyA)** to tell me why you're here. Your vote directly shapes what I create next!

**👉 [Vote now: Why are you reading this?](https://strawpoll.com/wby5QoKAkyA)** *(seriously, takes 10 seconds)*

---

## The Challenge: Two Real Interview Questions

I recently encountered this question during Security Engineering interview prep:

> **"Explain the SSL/TLS handshake. How do certificates get provisioned?"**

Simple question. Brutal in an interview if you don't know the details.

Let me challenge you with two specific questions that test your understanding:

---

### Question 1: TLS 1.3 Handshake Steps

**Walk me through the TLS 1.3 handshake step-by-step. Start with the client initiating the connection and explain each message exchanged until application data can be transmitted. Be specific about message names.**

*Take 5 minutes. Write down your answer before scrolling.*

---

### Question 2: Forward Secrecy

**Why did TLS 1.3 make Diffie-Hellman key exchange mandatory instead of allowing RSA key exchange? What problem does this solve?**

*Again, write your answer before looking at the solution.*

---

## My Answers (After Much Trial and Error)

### Question 1: TLS 1.3 Handshake Steps

The TLS handshake protocol ensures client and server establish shared secret keys.

Here's the complete message flow:

**1. Client sends a ClientHello message**
- The client specifies which algorithms it would like to use in TLS
- Sends a public key to initiate key exchange

**2. Server responds with ServerHello**
- Lets the client know which ciphers are selected
- The server also sends its public key for key exchange

**3. Server sends TLS Certificate to client**
- Contains the server's public key and identity information
- Includes the certificate chain

**4. Server sends CertificateVerify message**
- Contains signature over ClientHello + ServerHello + Certificate transcript
- This proves server owns the private key corresponding to its TLS Certificate

**5. Server sends Finished Message**
- Contains a Message Authentication Code (MAC) over the entire handshake transcript

**6. Client validates TLS Certificate Chain**
- The client verifies the entire chain-of-trust from the server's TLS Certificate, through any Intermediate Certificate Authority, up to a trusted Root Certificate Authority
- Checks: certificate is signed by trusted CA, not expired, not revoked

**7. Client derives session keys**
- Generates keys using HKDF (HMAC-based Key Derivation Function)
- Verifies the server's Finished MAC

**8. Client sends Finished Message back to server**
- Client's MAC over entire handshake transcript

**9. Encrypted application data transmission begins**
- All communications between client and server are encrypted with chosen AEAD cipher (e.g., AES-256-GCM or ChaCha20-Poly1305)

Here's a visual representation of the TLS 1.3 handshake process:

![TLS 1.3 Handshake Diagram](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/tls-handshake-diagram.png)

**Key insight:** Notice that BOTH the server AND client send Finished messages. Many candidates forget the client's Finished message, which would cause the handshake to fail!

---

### Question 2: Forward Secrecy

RSA Key Exchange cannot support forward secrecy. 

**Forward secrecy means even if a long-term key is compromised, previously encrypted sessions cannot be compromised.** 

RSA Key Exchange uses long-term private keys for key exchange. That means if the RSA keys for key exchange are compromised, attackers will be able to decrypt past sessions.

**The threat model:**
1. Attacker records encrypted TLS traffic today (can't decrypt it now)
2. Years later, attacker breaks into server and steals server's long-term RSA private key
3. With RSA key exchange: attacker can now decrypt ALL past recorded traffic ❌

**How Diffie-Hellman solves this:**
- Uses ephemeral (temporary) key pairs generated fresh for each session
- These ephemeral private keys are deleted immediately after the handshake
- Even if the server's long-term private key is later compromised, past sessions remain secure because the ephemeral DH keys no longer exist ✓

This is why TLS 1.3 dropped RSA Key Exchange entirely.

---

## 📊 Pause & Vote: What Brought You Here?

If you found these answers helpful, **[please take my 10-second poll](https://strawpoll.com/wby5QoKAkyA)**! I'm tracking what topics resonate most so I can create better exercises and blog posts.

**[👉 Click here to vote](https://strawpoll.com/wby5QoKAkyA)** - it's anonymous and helps me understand what content you actually want!

---

## What I Learned From This Exercise

**1. Message names matter:** Saying "the server sends a signature" isn't good enough. You need to say "**CertificateVerify message**."

**2. Both parties send Finished messages:** The handshake isn't complete until the client also sends a Finished message with a MAC over the handshake transcript.

**3. Forward secrecy is about long-term keys:** It protects against future compromise of the server's private key, not about protecting one session key from another.

**4. Certificate chain verification goes from leaf to root:** The client starts with the server's certificate and works its way UP to a trusted Root CA, not the other way around.

## Resources & Further Practice

These questions are part of my **[Security Engineering Interview Prep repository](https://github.com/fosres/SecEng-Exercises)** where I'm building a comprehensive collection of:

- ✅ LeetCode-style security exercises
- ✅ Real interview questions with detailed solutions
- ✅ Comprehensive test suites for secure coding practice
- ✅ Weekly blog posts breaking down security concepts

**⭐ If you found this helpful, please star the repo!** I'm building this as an open-source resource to help developers break into Security Engineering roles.

### Recommended Reading

The answers in this post are based on these authoritative sources:

1. **[Serious Cryptography, Second Edition](https://nostarch.com/serious-cryptography-2nd-edition)** by Jean-Philippe Aumasson - The definitive guide to modern cryptography fundamentals
2. **[Bulletproof TLS and PKI, Second Edition](https://www.feistyduck.com/books/bulletproof-tls-and-pki/)** by Ivan Ristić - Comprehensive deep dive into TLS protocol and certificate infrastructure
3. **[Cloudflare Learning: TLS](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)** - Excellent visual explanations and practical examples

---

## Your Turn: Vote & Share Your Experience

**First things first:** If you haven't already, **[please vote in my 10-second poll](https://strawpoll.com/wby5QoKAkyA)**! I'm using this data to decide what exercises to build next in the **[SecEng-Exercises repo](https://github.com/fosres/SecEng-Exercises)**.

**[📊 Click to vote: Why are you reading this blog?](https://strawpoll.com/wby5QoKAkyA)**

---

**Now, how did your answers compare?** What surprised you most about the TLS handshake?

**Drop a comment below** with:
- What you got right
- What you got wrong  
- Any "aha!" moments
- Topics you want me to cover next

And if you're preparing for Security Engineering interviews, check out **[my GitHub repo](https://github.com/fosres/SecEng-Exercises)** for more challenges like this!

---

*Building this content takes significant time and research. If you found it valuable:*
- ⭐ **[Star the GitHub repo](https://github.com/fosres/SecEng-Exercises)**
- 🔄 Share this post with your network
- 💬 Comment with your own TLS war stories

**Next post:** *"Certificate Provisioning: From CSR to Production HTTPS"* - covering Question 4 of the original interview question.

---

**About the Author:** I'm currently executing a 28-week Security Engineering curriculum to transition from Intel's Product Assurance and Security division (where I documented 553+ threats using STRIDE methodology) to General Security Engineering roles. Follow my journey and learn alongside me!

**Tags:** #security #networking #interviews #tls #cybersecurity #webdev #backend #devops
