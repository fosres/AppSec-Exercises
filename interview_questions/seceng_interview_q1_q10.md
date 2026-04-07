---
title: "Security Engineering Phone Screen: 10 Questions You Must Answer Fluently"
published: false
description: "My personal answers to 10 real Security Engineering phone screen questions — covering TCP, cookies, sessions, OAuth2, JWT, PKI, TLS, symmetric/asymmetric crypto, and HMAC."
tags: security, appsec, interview, networking
cover_image:
series: Security Engineering Interview Prep
---

> **Series note:** This post is Part 1 of my Security Engineering Interview Prep series. I am working through [Saed Farah's "If I Were Starting Over as a Security Engineer in 2026"](https://secengweekly.substack.com/p/if-i-were-starting-over-as-a-security) question bank — 94 questions mapped to a structured curriculum — and archiving my personal answers here as I lock each one in.
>
> These are the answers I would give in a real phone screen. I am targeting mid-level Security Engineering roles at companies like Anthropic, GitLab, Stripe, Coinbase, Trail of Bits, and NCC Group.

---

## Why Phone Screen Answers Belong in a Blog

The following ten questions appear in Security Engineering phone interviews. They come from **Section A: Encryption, Authentication & Access** of Saed Farah's question bank, and nine of the ten are flagged ★ **INDISPENSABLE** — meaning they appear frequently enough across mid-level Security Engineering screens that a weak answer on any of them is a disqualifying signal.

Interview prep that stays in a notebook rots. Writing answers in public forces you to be precise. Vague mental models collapse under the pressure of an interviewer's follow-up. Clear writing is the test.

Let's get into it.

---

## Q1 — What is a Three-Way Handshake?

This is the technique used in TCP/IP connections to verify
sender and recipient of messages can communicate with each other.

Below is a quick summary of the handshake:

1. Sender sends an SYN packet to recipient

2. Recipient replies back with a SYN-ACK packet to sender

3. Sender replies back with an ACK packet

It is possible an attacker can trick either party into believing
they are the authentic recpient of said party's messages: an
attack known as a TCP Session Hijacking Attack.

To prevent this the TCP 3-way handshake enforces Initial Sequence
Number Randomization. Now that said party is sending a random number
it is hard for the attacker to predict what the future ISN will
be in said party's future packets--mitigating the attack.

Without doing the TCP 3-way handshake an attacker
can next attempt a Denial of Service by sending excessive SYN packets
--depleting the other party of system resources.

> **Curriculum anchor:** Week 1–2 TCP/IP fundamentals. ★ Indispensable.

---

## Q2 — How Do Cookies Work?

Let me first start with the rationale behind cookies.

In the modern world the user must make an effort to prove their
identity to a service. This can be done by entering a (sufficiently
complex) password, or a passkey, or biometric credentials. Users
frequently close sessions to work on something else only to come back
to the service after a brief period of time. It would annoy the user
to have to exert manual effort to prove their identity to a web
service! Had that been the case critical business models such as
Software as a Service may not have been as profitable as they are
today.

To make the user's life easier web security developers introduced
the Cookie system. After the user proves their identity through
manual effort the first time (such as by using one of the techniques
discussed previously) -- the web service passes on a Cookie which
contains secret information unique to said user. Whenever the user
revisits the web service the user's browser automatically sends the
cookie to the web service for authentication. If the secret information
is verified to be correct the user's identity is verified.

Throughout history web developers faced issues with attackers stealing
Cookies or even tricking users to submitting cookies to the web
service without their knowledge. Several security defenses to protect
cookies from theft or unwitting submission have been invented such
as the HttpOnly flag (forbids Javascript from accessing the Cookie),
the Secure flag (which only allows the cookie to be submitted upon
the browser being able to establish a valid HTTPS connection to the
target website), and the SameSite flag (which restricts the ability
of a cookie to be sent in cross-site requests), Expires flag (which
sets expiration date of cookie)--a good habit to set expiration
to minimize risk of cookie theft, Domain, and Path flags (to
restrict to which webistes and endpoints the browser is allowed
to send cookies too).

Web developers must take care to verify the secret information
received from cookies matches what is expected. They must also
be sure to set the proper security flags to avoid mismanagement
of the cookie. Finally Web Developers must be careful not to
allow the attacker to steal any secrets stored within the Cookie.
For instance if a Cookie stores a CSPRNG-generated string the
web server should NOT also store the string--only a cryptographically
secure message digest. This--and using a constant-time comparision
string function to compare message digest--are appropriate precautions
to prevent an attacker from stealing the Cookie secret.

> **Curriculum anchor:** Week 6 — session management and secure cookie flags. ★ Indispensable.

---

## Q3 — How Do Sessions Work?

HTTP requests are not persistent--they do not keep track of the
state of previous HTTP requests/replies. This is a downside for
users using a web-service: a person that has logged into a web service
would ideally want the web service to remember they are the true
identity as the user and that they are authorized to access/interact
with certain resources on the web service. Web developers had
to figure out a way to allow this beyond sending simple HTTP requests.

This gave birth to two important techniques for establishing and
verifying user sessions: User session cookie management and
verifying Anti-CSRF tokens. Both of these techniques require the
user to receive and store credentials that the web service verifies
upon the user revisiting the web service within the expiration
time window. This allows the web service to automatically verify
the identity of the user to access certain resources from the web
service. Precautions have been made to prevent attackers from
corrupting user sessions (see previous explanations above). Anti-CSRF
tokens prevent an attacker from tricking users into performing actions
on a cross-site that said user has a valid cookie for.

Upon logout session credentials are marked as invalid. Upon expiration
session credentials must be rejected by the web server.

> **Curriculum anchor:** Week 6 — session management. See also: *Full Stack Python Security*, Chapter 3.

---

## Q4 — Explain How OAuth2 Works

OAuth is a framework that allows a third-party service (called a
client in OAuth2) to access a protected resource on behalf of a
resource owner (the human user).

Here are the steps on the most important version of OAuth2, the
authorization grant, works. My information is taken from
"OAuth2 in Action" -- page 23. [^1]

0. It is ideal if the client
generates a `code_verifier` for Proof-Key for Code Exchange. This
is a CSPRNG-generated secret. The client then can either send
the `code_verifier` to the Authorization Server or ideally
send the cryptographic message digest of the `code_verifier`
to the Authorization Server. In either case what the Authorization
Server receives is called the `code_challenge`. Proof-Key for Code
Exchange prevents a MITM attacker that has stolen the
authorization code from receiving an access token from the
Authorization server's token endpoint. Although ideal not
required in OAuth2. The `code_challenge` can be the `code_verifier`
itself but ideally the cryptographic message digest of the
`code_verifier`. Having the Authorization Server's token endpoint
store the hash, instead of the actual `code_verifier` protects the
`code_verifier` from theft if an attacker compromises the
Authorization Server's token endpoint.

1. The third-party service, called the client, redirects the resource
owner, or user, to the authorization endpoint. There, the user must
prove their identity using traditional authentication.

2. The resource owner is given the option to authorize the client.
The user manually approves.

3. The authorization server now redirects resource owner back
to client with authorization code.

4. Client authenticates by sending client credentials, authorization
code, and ideally also the Proof-Key for Code Exchange `code_verifier`
to the Authorization Server's token endpoint.

5. Authorization server sends access token to client. Ideally
the authorization server also sends a refresh token the client
can use to get a new access token should the current access token
expire.

6. Client accesses the protected resource after sending the access token.

> **Source:** *OAuth 2 in Action* (Justin Richer & Antonio Sanso), p. 23. [^1]
>
> **Curriculum anchor:** Week 12 — SSO + OAuth2 + JWT. ★ Indispensable.

---

## Q5 — Explain How JWTs Work

The following answer is straight from:

https://www.jwt.io/introduction#what-is-json-web-token [^2]

JWT Tokens are a compact and self-contained technique to transmit
secret information between client and server. The recipient of the
token can verify the authenticity of the message since the JWT Token
is signed.

There are two uses of JWTs:

1. Authorization: After the user manually authenticates themselves and
proves their identity the user is assigned a JWT Token. From that point
on for every endpoint the user accesses the server verifies the user's
identity by verifying the user's JWT Token. Developers must be
careful the JWT Token is not stolen--such as from an XSS exploit.

2. Secure Information Exchange: JWT Tokens are also used in the
private transfer of information. The secrecy of the JWT Token content
is protected under TLS. The authenticity of the JWT Token is protected
by HMAC or digital signature (using a private-public key pair).

There are three components to a JWT Token:

1. Header: Usually explains the type of token and the digital
signature algorithm being used.

2. Payload: This is the main content of the JWT Token--compromised
of claims.

3. Signature: This is either the HMAC or digital signature that
recipients can verify upon recieving the message. A valid verification
implies the message was not tampered and was sent by the claimed
sender.

> **Source:** [jwt.io — Introduction to JSON Web Tokens](https://jwt.io/introduction). [^2]
>
> **Curriculum anchor:** Week 6 — API auth patterns. ★ Indispensable.

---

## Q6 — What Is a PKI Flow? How Would You Diagram It?

PKI flow maps the chain-of-trust from Root Certificate Authority
to the TLS Certificate owned by a web service. The idea is all
the digital signatures of the certificates belonging to each of
these services must be verified by clients as valid before the
client (or user's browser) accepts the TLS certificate of the
web service as valid. This is a prerequisite that must be done
before the client establishes a secure HTTPS connection with
a web server.

The diagram of the flow of verification--showing the order at
which TLS Certificates are verified--are shown below:

Root Certificate validated-->Intermediate Certificates validated
-->Web Server TLS Certificate validated

There is a point to the existence of the Root Certificate.
Every browser comes with it a set of publicly known Root TLS
Certificates--so a self-signed Root TLS Certificate is sufficient
to verify that a Root TLS Certificate is valid. The Root Certificate
can be thought of as a Root of Trust for this reason. If Root
TLS Certificates are publicly acknowledged why do we have Intermediate
TLS Certificates. In case a Root Certificate is compromised it would
be costly to replace the original Root Certificate with a brand new
one. An Intermediate Certificate Authority will be much more quickly
be able to replace an invalid/stolen TLS Certificate than a Root
Certificate. The Intermediate Certificate Authority signs the TLS
Certificate of the web service the client is interested in visiting.

A self-signed TLS certificate for a web service means nothing--anyone
can make one--but only the real web service should be able to convince
an Intermediate TLS Certificate to sign the web service's TLS
Certificate. This is not to say it is impossible for Intermediate
Certificate Authorities to mis-issue TLS Certificates. To this day
it is a problem. The best mitigation of that is DNSSEC and DANE.

Although those two techniques are best practice the industry
has decided to settle with Certificate Transparency. These are
unmodifiable--append only logs of issued TLS Certificates that
site owners can check to see if a TLS Certificate has been mis-issued
for their site. Although Certificate Transparency is an industry
standard--it does NOT prevent mississuance of TLS Certificates.

To prevent mis-issuance the Certificate Authority Authorization
field in DNS records has been introduced whitelisting which
Certificate Authorities are authorized to issue TLS Certificates.

Still even this does not prevent the mis-issuance of TLS Certificates.
The best defenses to prevent mis-issuance are still DNSSEC and
DANE--despite low adoption.

To avoid the risk of theft of TLS Certificate--web services are
encouraged to replace their TLS Certificates periodically--from as
little as 3 months to no more than a year of time.

> **Curriculum anchor:** Week 5 — cryptography basics + asymmetric key infrastructure.

---

## Q7 — Describe the Difference Between Symmetric and Asymmetric Encryption

Symmetric-Key Cryptography uses the same key to encrypt/decrypt
information. This is the encrypion featured in password authentication,
encrypting of documents, generating HMACs, and more. Symmetric-Key
Cryptography--when using a sufficiently long and CSPRNG-generated
key--is thought to be resistant to attack by a quantum supercomputer.

Asymmmetric Encryption: In this encryption one key is used to encrypt
data and a separate key is used to decrypt data. This field begain
with the invention of Diffie-Hellman Key Exchange by cryptographers
Diffie Whitfield, Martin Hellman, and Ralph Merkle. Asymmetric
Encryption is featured in digital signatures and public-key encryption.

Unfortunately asymmetric key encryption is harder to use than
symmetric-key encryption--and this is arguably the biggest hurdle
to its adoption. Even as late as 2022 CE NIST admits it should take
two whole decades for organizations to adopt the new post-quantum
safe public-key algorithms NIST standardized. Classical Asymmetric
-Key Encryption is vulnerable to Shor's Algorithm--an algorithm
that a quantum supercomputer can execute to crack the private key
featured in classical asymmetric-key encryption.

Some examples of algorithms that fall under symmetric-key cryptography:

AES, HMAC-SHA-256, Argon2ID

Some examples of asymmetric-key encryption algorithms:

Diffie-Hellman Key Exchange, RSA, Kyber-1024, Dilithium

> **Curriculum anchor:** Week 5 — cryptography basics. ★ Indispensable. Pre-loaded from Intel ChaCha20 (symmetric) + XMSS (asymmetric post-quantum signatures).

---

## Q8 — Describe the TLS Handshake

The following gives the steps for the Handshake:

1. Client sends ClientHello Message:

	a. Details which algorithms the client wants to use.

	b. Client sends it public key for key exchange in this message

2. Server responds with ServerHello:

	a. Tells client which algorithm(s) the server chose.

	b. Client recives server's public key for key exchange

2.5. Both Client and Server independenty derive premaster secret
from ECDHE shared secret. The ECDHE shared secret is derived during
ECDHE key exchange. Used later in MAC verification to verify
no MITM attack took place during TLS Handshake.

3. Server sends TLS Certificate to client

	a. Has server's public key and identity information

	b. Includes certificate chain.

4. Server sends CertificateVerify message.

	a. Contains signature over ClientHello + ServerHello +
Certificate Transcript.

	b. This proves server owns the private key corresponding to
the public key in the TLS certificate.

5. Server sends "Finished" Message with MAC

	a. Contains a MAC over the entire handshake transcript.

		i. Client must first verify public key in TLS
Certificate is valid before verifying MAC. This avoids the
Diffie-Hellman MITM where the attacker sends ECDHE public keys
to victim whose private keys the attacker has knowledge of.

6. Client verifies TLS Certificate Chain

	a. Starting from TLS Certificate of the website, past
Intermediate Certificates, up to the Root TLS Certificate of the
website. All signatures must be valid. If at any point a signature is
found to be invalid the client must reject the TLS certificate and
refuse to establish a TLS connection with the website. At that point it
is possible the website is a fake.

7. Client Derives Session Keys to Verify MAC

	a. Client derives session keys using HKDF from premaster
secret to verify MAC Server sent over TLS Handshake Transcript (
ClientHello + ServerHello + TLS Certificate). This proves no MITM
attack took place.

8. Client sends "Finished" Message

	a. Client reports it finished verifying server's identity by
sending "Finished" message

	b. Client sends a MAC to server over entire handshake
transcript. Server verifies MAC is correct. This proves there
was not MITM in the handshake process.

9. Encrypted Communication Between Client and Server Begins

	a. Encrypted Communication in TLS takes place in TLS 1.3
with AEAD ciphers.

> **Curriculum anchor:** Week 2 — TLS/HTTPS networking. ★ Indispensable.

---

## Q9 — How Does HMAC Work?

A Hash-based Message Authentication Code is built on a cryptographic
message digest. To use an HMAC a user must supply a secret key
and a document as two arguments. The HMAC will generate an ID
number unique to the secret key and document pair. The recipient
of a message can then verify that a message was truly sent
by the alleged sender by recalculating the HMAC and verifying the
HMAC sent by the sender matches the one the recipient recalculated.

Security Engineering Interviews care less on the math behind
how algorithms work and more on how to make use of them.

> **Curriculum anchor:** Week 5 — cryptography basics. Pre-loaded from Intel crypto implementations.

---

## Q10 — Why Is HMAC Designed the Way It Is?

Resource: Understanding Cryptography Second Edition [^3]

HMACs are designed the way they are to avoid common attacks against
MACs: including the suffix and prefix attacks--and HMACs are designed
the way they are since they make use of cryptographic message digest
functions--which are widely available in software cryptographic
libraries to implement and are much easier to program securely
than block ciphers--the alternative building block used to make
a MAC. HMACs are widely used instead of MACs built on block ciphers
since HMACS are easier to prove to be secure even if the hash
featured in HMAC is found to be weak against collision resistance or
weak in second preimage resistance--under certain assumptions.

> **Source:** *Understanding Cryptography*, 2nd Edition (Christof Paar & Jan Pelzl). [^3]
>
> **Curriculum anchor:** Week 5 — cryptography basics. ★ Indispensable.

---

## Where These Questions Sit in the Curriculum

| Question | ★ Indispensable? | Curriculum Week | Status |
|---|---|---|---|
| Q1 — TCP Three-Way Handshake | ★ Yes | Week 1 | ✅ Pre-loaded |
| Q2 — How Cookies Work | ★ Yes | Week 6 | 🔵 Near-term |
| Q3 — How Sessions Work | No | Week 6 | 🔵 Near-term |
| Q4 — OAuth2 | ★ Yes | Week 12 | 🟣 Build toward |
| Q5 — JWT | ★ Yes | Week 6 | 🔵 Near-term |
| Q6 — PKI Flow | No | Week 5 | ✅ Pre-loaded |
| Q7 — Symmetric vs. Asymmetric | ★ Yes | Week 5 | ✅ Pre-loaded |
| Q8 — TLS Handshake | ★ Yes | Week 2 | ✅ Pre-loaded |
| Q9 — HMAC | No | Week 5 | ✅ Pre-loaded |
| Q10 — Why HMAC Is Designed That Way | No | Week 5 | ✅ Pre-loaded |

---

## What's Next

Part 2 will cover **Q11–Q17** — the remainder of Section A — including Perfect Forward Secrecy, data-at-rest encryption strategy, authentication vs. authorization, and Kerberos/Diffie-Hellman/RSA distinctions.

Part 3 will move into **Section B: Network Security, Protocols & Logging** — the largest section at 36 questions.

---

## References

[^1]: Justin Richer & Antonio Sanso. *OAuth 2 in Action*. Manning Publications, 2017. p. 23 — Authorization Code grant flow and PKCE extension.

[^2]: JSON Web Tokens — Introduction. [jwt.io/introduction](https://jwt.io/introduction).

[^3]: Christof Paar & Jan Pelzl. *Understanding Cryptography*, 2nd Edition. Springer, 2010. HMAC construction and attack analysis.

---

*This post is part of my public Security Engineering interview prep series. I am building toward a full-time Security Engineering role and maintaining an open-source project — [SecEng-Exercises on GitHub](https://github.com/fosres/SecEng-Exercises) — that curates high-quality, secure code datasets to train AI to write more secure code. Follow along on [Dev.to](https://dev.to/fosres).*
