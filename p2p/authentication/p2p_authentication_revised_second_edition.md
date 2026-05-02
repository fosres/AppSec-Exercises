# Authentication for FOSRES 

Hi there. I am developing a site on AWS to teach myself and others

Security Engineering principles. This article explains how I will

build an authentication system to teach myself how Security

Engineers handle designing them, reviewing their implementation,

and deploying the required infrastructure on the Cloud.

You can see my introduction to this project
[here](https://dev.to/fosres/introducing-fosres-a-free-and-open-source-security-research-project-4ij6)



# Part 1: Authentication System

I will first work with Claude to generate the authentication

system. It is my responsibility to audit it. I will be presenting

the code as an audit challenge so you are more than welcome

to audit it and report bugs if necessary. Find my email in my

Dev.to profile to contact me if you find any.

Below is a system diagram of the final version of the authentication

system:

[Challenge_1_Secure_System_Design_Authentication.png]

## STRIDE Threat Model

## STRIDE Threat Model — Challenge 1: Authentication Service

**S — Spoofing**

An attacker brute-force guesses the correct password and TOTP code stolen
from a previous phishing attack. Alternatively, the attacker launches a
Stored XSS attack that steals the victim user's session credentials and
exfiltrates them to the attacker's server — bypassing authentication
entirely. Mitigations: Rate Limiter blocks brute force attempts, CAPTCHA
blocks automated credential stuffing, MFA Store ensures stolen passwords
alone are insufficient, HTTPOnly cookie flag prevents XSS-based session
token theft.

**T — Tampering**

An attacker uses a SQL Injection attack to tamper with database records
directly. Additionally, an attacker modifies a JWT payload to claim
elevated privileges. Mitigations: Parameterized queries prevent SQL
injection, cryptographic signature verification on every token at the Auth
Service prevents JWT payload tampering.

**R — Repudiation**

An attacker, after compromising an account and logging in as the victim to
perform malicious activity, deletes all log records from Kafka to cover
their tracks and deny wrongdoing. Mitigation: Kafka is configured as a
write-once, append-only log with no delete permissions granted to the Auth
Service — even a fully compromised Auth Service cannot erase past events.

**I — Information Disclosure**

An attacker exfiltrates the PostgreSQL database, leaking password hashes
and TOTP secrets stored within. Mitigations: Argon2ID renders leaked
password hashes computationally useless, encryption at rest on the
database, and least-privilege database access so the Auth Service cannot
read tables it does not own.

**D — Denial of Service**

An attacker launches a botnet to overwhelm the server with excessive
requests, depleting server resources and rendering it unable to respond to
legitimate users — for example an HTTP Flood Attack or a Slowloris Attack.
Mitigations: Rate Limiter and CAPTCHA in the DMZ absorb and block malicious
traffic before it reaches the Auth Services.

**E — Elevation of Privilege**

An attacker gains admin-level privileges via a UNION SQL Injection attack
against PostgreSQL, allowing modification of other users' data. Mitigation:
Parameterized queries prevent SQL injection from executing against the
database.


## Compliance

I intend the web application to be GDPR compliant (Claude help

me with meeting GDPR compliance with AWS).

## How Authentication Will Work

### Client-Side Hashing for Registration

Authentication and Encryption inspired by [Bitwarden Whitepaper's](https://bitwarden.com/assets/lrLsAOcvBsN1vaYAaZQKt/a73a6f46d55cf705423aa7a6a12b7f8a/whitepaper-login.png?w=960&fm=avif) system diagram for user


The following is ASCII-based art:

```
╔══════════════════════════════════════════════════════════════╗
║  CLIENT                                                      ║
║                                                              ║
║  ┌───────────────────────────┐                               ║
║  │  Argon2ID (KDF)           │                               ║
║  │  Salt   : username        │──────── Master Key            ║
║  │  Payload: master password │                               ║
║  └───────────────────────────┘                               ║
║                                                              ║
║  ┌───────────────────────────┐                               ║
║  │  Argon2ID (KDF)           │◀── Master Key                 ║
║  │  Payload: master key      │                               ║
║  │  Salt   : master password │                               ║
║  └─────────────┬─────────────┘                               ║
║                │Intermediate Hash                            ║
║                │                                             ║
╚════════════════╪═════════════════════════════════════════════╝
                 │                   🔒 https://
                 ▼
╔══════════════════════════════════════════════════════════════╗
║  CLOUD                                                       ║
║                                                              ║
║  ┌──────────────────────────────────────┐                    ║
║  │  SHA-256(Intermediate Hash)          │                    ║
║  │  = Verification Hash                 │                    ║
║  └──────────────────┬───────────────────┘                    ║
║                     │                                        ║
║      KMS – Data Protection Key – XChaCha20-Poly1305          ║
║  ┌────────────────────────────────┐                          ║
║  │  Verification Hash             │                          ║
║  ├────────────────────────────────┤                          ║
║  │  Database with Transparent     │                          ║
║  │  Data Encryption (TDE)         │                          ║
║  ├────────────────────────────────┤                          ║
║  │  Verification Hash             │                          ║
║  └────────────────────────────────┘                          ║
╚══════════════════════════════════════════════════════════════╝
```

## Required Crypto Libraries

### Backend Crypto Libraries

For `argon2` the `passlib` library will be used.

For `sha256` the `hashlib` library will be used.

Key Derivation Function: Argon2ID

HKDF: HKDF-SHA-256 which offers 128 bits of quantum security

Symmetric Key Algorithm: XChaCha20-Poly1305

### Frontend Crypto Libraries

For Angular.js the frontend crypto libraries will be:

`@noble/hashes`.

-------------------------------------------

## Full Stack

The backend framework is Django:

Here is a comparision chart of Django's security features

vs the others:


## Frontend Featured in the Exercises

Angular.js since it has the best security features.

Here is a comparision chart:

| Feature | Angular | React | Vue/Nuxt | Next.js | Alpine.js |
|---|---|---|---|---|---|
| Auto-escaping default | ✅ | ✅ | ✅ | ✅ | ✅ |
| Built-in CSRF | ✅ | ❌ | ❌ | ❌ | ❌ |
| TypeScript default | ✅ | ❌ | ❌ | Optional | ❌ |
| Single auditable XSS sink | ✅ | ❌ | ❌ | ❌ | ❌ |


## Account Recovery

Unlike traditional web services FOSRES will assign recovery key

upon account creation. This recovery key must be saved and stored

by the user. Never will the user be allowed to reopen access to

their account unless the correct recovery key is presented.

The recovery key is the Intermediate Hash generated after applying

the user password as payload and username as salt. It will

be presented to the user as a hexadecimal string to store offline.

## Detecting Database Tampering

To detect database tampering an HMAC signature will be used to

sign database records. Periodically new versions of the key will

be generated. From that moment on new database records will be

signed with the newest HMAC key. However, old HMAC-signed records

and their keys can still remain in database. It is when said

record containing HMAC signature with outdated key is retrieved

is the information verified and updated with an HMAC signature

featuring the newest key. This is a balance between security and

performance. It would be cumbersone updating every database

record all at once with the newest version of the key. Imagine

if the database grows in size. Now, a daemon will run quietly

updating database records in the meantime updating all signatures

with the newest key until the entire database has been updated.

I estimate this should take up to 15 minutes total given 10 million

records.

## CAPTCHA

ALTCHA and email verification are both required. Modern email

providers monitor the behavior of their clients to flag and

potentially ban suspicious users. ALTCHA is a GDPR-compliant

self-hosting friendly CAPTCHA library.

## MFA Methods:

MFA methods TOTP and U2F will be allowed. People will be able to

register their account under either. If a person chooses U2F

they will not be allowed to use TOTP as a backup. Instead they

will be required to use a backup U2F key. This policy is enforced

to protect people from attacks exploiting fallback MFA methods.

This article focuses on handling the user's username and password.

A separate article will explain how the MFA infrasturcture will

be deployed in detail.

## Testing

All AI agents must first generate a beta version of the full-stack

page of code requested complete with a full test-case suite. The

developer must then manually check if the test cases work as well as

test with additionl test cases. As a Security Engineer one must check

for security bug test cases--and the AI agent must include that in the

test case suite where applicable. After the developer has tested

through all test cases the developer is strongly encouraed to

allow a second, independent AI agent to first verify all test

cases as well as additional tests. The developer can then

verify the test cases made by the second independent AI.

Claude will be responsible for generating code and the first

test case suite for each page of full-stack code made.

Mistral will be the secondary testing agent. Mistral, unlike Claude,

is capable of executing code in a sandbox so Mistral is valuable

as a testing agent. Claude is frequently used by developers

and Security Engineers for software engineering planning.

## Policy on Code Generation

It will always be *harder* to write secure code the first time

than to detect security bugs in code. I am aware Claude Mythos

has made headlines in the past that it is so good at finding

security bugs (even zero-days) that Anthropic deliberately canceled

debuting it to the public and let other companies use it first to

help them remove security bugs. I am sorry but I am not convinced

this is going to be sufficient to remove future security threats.

Marcus J Ranum warned this is the Penetrate and Patch problem:

people pay too much attention to fixing patches instead of focusing

on designing infrastructure and software to be secure from the ground

up--with flaw handling in mind. So the real problem is people will

ignore this reality and instead over-rely on Claude Mythos to find

future insecure patches for them. The problem with that is the same

security bugs will be generated faster than ever thanks to human

misuse of AI, no matter how many patches Mythos makes the rate

at which security bugs will be published will still be faster than

even Mythos can detect, and the same security bugs will be complained

about more than ever before even with Mythos's help.

I will paste an excerpt written by Ranum below on this from the

article I hyperlinked:

```
"Penetrate and Patch" crops up all over the place, and is the primary dumb idea behind the current fad (which has been going on for about 10 years) of vulnerability disclosure and patch updates. The premise of the "vulnerability researchers" is that they are helping the community by finding holes in software and getting them fixed before the hackers find them and exploit them. The premise of the vendors is that they are doing the right thing by pushing out patches to fix the bugs before the hackers and worm-writers can act upon them. Both parties, in this scenario, are being dumb because if the vendors were writing code that had been designed to be secure and reliable then vulnerability discovery would be a tedious and unrewarding game, indeed!

Let me put it to you in different terms: if "Penetrate and Patch" was effective, we would have run out of security bugs in Internet Explorer by now. What has it been? 2 or 3 a month for 10 years? If you look at major internet applications you'll find that there are a number that consistently have problems with security vulnerabilities. There are also a handful, like PostFix, Qmail, etc, that were engineered to be compartmented against themselves, with modularized permissions and processing, and - not surprisingly - they have histories of amazingly few bugs. The same logic applies to "penetration testing." There are networks that I know of which have been "penetration tested" any number of times and are continually getting hacked to pieces. That's because their design (or their security practices) are so fundamentally flawed that no amount of turd polish is going to keep the hackers out. It just keeps managers and auditors off of the network administrator's backs. I know other networks that it is, literally, pointless to "penetration test" because they were designed from the ground up to be permeable only in certain directions and only to certain traffic destined to carefully configured servers running carefully secured software. Running a "penetration test" for Apache bugs is completely pointless against a server that is running a custom piece of C code that is running in a locked-down portion of an embedded system. So, "Penetrate and Patch" is pointless either because you know you're going to find an endless litany of bugs, or because you know you're not going to find anything comprehensible. Pointless is dumb.

One clear symptom that you've got a case of "Penetrate and Patch " is when you find that your system is always vulnerable to the "bug of the week." It means that you've put yourself in a situation where every time the hackers invent a new weapon, it works against you. Doesn't that sound dumb? Your software and systems should be secure by design and should have been designed with flaw-handling in mind.
```

Even an AI trained in writing secure code will fail to prevent all

security problems since some security problems are design and

infrastructure flaws from the very beginning.

To avoid this penetrate and patch problem I will release my security

designs for this project, release the Claude conversation, and

release all test case studies to the public--allowing people to

use whatever means they find suitable to verify that the product

is sufficiently secure.

# Generate One Function, Test First Before Publish

For the sake of sanity and maintaining security at scale I will

generate one function implementation at a time and publish successful

test cases both at once. This will prevent me from missing security

bugs (though I admit even this will not nullify all future security

bugs)

List of Features and Functions to be Generated in Order:

Each item gives the feature/function and its REST API handle.

1. Account Registration Page (/register)

This is a simple registration page that asks the user for the following:

a. Username

b. Password

c. ALTCHA Challenge Response

The user fills out the above fields of info. The frontend of

the registration must next do the following work:

2. Calculate Master Key (function name: master_key_gen)

That is calculating the following:


║  ┌───────────────────────────┐                               ║
║  │  Argon2ID (KDF)           │                               ║
║  │  Salt   : username        │──────── Master Key            ║
║  │  Payload: master password │                               ║
║  └───────────────────────────┘                               ║

The name of the Angular.js function that does this is named

"master_key_gen" as said above. Please have test cases testing

that a proper Argon2ID hash is generated.

Using `@noble/hashes` in Angular.js let us use
[the](https://libsodium.gitbook.io/doc/password_hashing/default_phf)
[following](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
[parameters](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_pwhash_argon2id.h):

```typescript
argon2id(password, salt, {
	t: 2,
	m: 65536,   // 64 MiB in KiB — LibSodium Interactive
	p: 1,
	dkLen: 32,
});
```

The above code snippet features parameters for interactive online

use as recommended by Libsodium documentation and are suitable

for use with `@noble/hashes`.

3. Calculate Intermediate Hash 

The next step is to calculate the Intermediate Hash based on the

following:


║  ┌───────────────────────────┐                               ║
║  │  Argon2ID (KDF)           │◀── Master Key                 ║
║  │  Payload: master key      │                               ║
║  │  Salt   : master password │                               ║
║  └─────────────┬─────────────┘                               ║
║                │Intermediate Hash                            ║
║                ▼                                             ║

Same parameters to calculate the Master Key are used to calculate

Intermediate Hash.

4. Calculate Verification Hash

The frontend first checks if TLS is enforced. If not registration

automatically fails.

The Intermediate Hash is transmitted over HTTPS to the server.

The server is responsible for computing the Verification Hash

by applying SHA-256 to the received Intermediate Hash:

```
SHA-256(Intermediate Hash) = Verification Hash
```

This design intentionally offloads the expensive Argon2ID

operations to the client. By the time the Intermediate Hash

reaches the server, all memory-hard KDF work is already done.

The server performs only a single fast SHA-256 operation to

derive the Verification Hash before storing it. This means

the server never stores or sees the Intermediate Hash directly —

only its SHA-256 digest is persisted in the database. In case

an attacker steals the password database the attacker is stuck

with the verification hash and cannot resend it to the server

to bypass authentication since that would result in a distinct

verification hash.

The verification hash is stored with Django ORM in a PostGreSQL

Database.

## Secure System Design: Authentication

Let's use Terraform for all Infrastructure-as-Code:

Load Balancer:  AWS Load Balancer

Rate Limiter: AWS WAF Rate Limiter

Kafka: Append Only Log Rate Limit Policy

Following Secure System Diagram for Challenge 1
