# Authentication for FOSRES 

Hi there. I am developing a site on AWS to teach myself and others

Security Engineering principles.



# Part 1: Authentication System

I will first work with Claude to generate the authentication

system. It is my responsibility to audit it. I will be presenting

the code as an audit challenge so you are more than welcome

to audit it and report bugs if necessary. Find my email in my

Dev.to profile to contact me if you find any.

Below is a system diagram of the final version of the authentication

system:

[Challenge_1_Secure_System_Design_Authentication.png]

## Compliance

I intend the web application to be GDPR compliant (Claude help

me with meeting GDPR compliance with AWS).

## How Authentication Will Work

### Client-Side Hashing for Registration

Authentication and Encryption inspired by [Bitwarden Whitepaper's](https://bitwarden.com/assets/lrLsAOcvBsN1vaYAaZQKt/a73a6f46d55cf705423aa7a6a12b7f8a/whitepaper-login.png?w=960&fm=avif) system diagram for user


The following is ASCII-based art:

╔════════════════════════════════════════════════════════════════════════════════════════════════╗
║  CLIENT                                                                                        ║
║                                                       ┌──────────────────────────────────┐   ║
║                       User Asymmetric Key        ┌───▶│  ML-KEM-1024 + X25519 Key Pair   │   ║
║                                                  │    │  ┌─────────────┬──────────────┐  │   ║
║  ┌───────────────────────────┐                   │    │  │ Private Key │ Public Key   │  │   ║
║  │  Argon2ID (KDF)           │                   │    │  └─────────────┴──────────────┘  │   ║
║  │  Salt   : username        │──────── Master Key┤    └──────────────────────────────────┘   ║
║  │  Payload: master password │                   │                                           ║
║  └───────────────────────────┘                   │    ┌──────────────────────────────────┐   ║
║                                                  └───▶│  HKDF-SHA-512 ──▶ Stretched      │   ║
║                                                       │                   Master Key     │   ║
║                                                       └─────────────────┬────────────────┘   ║
║                                                                         │                    ║
║  ┌───────────────────────────┐                                          ▼                    ║
║  │  Argon2ID (KDF)           │◀── Master Key   ┌───────────────────────────────────────┐    ║
║  │  Payload: master key      │                 │  Generated Symmetric Key              │    ║
║  │  Salt   : master password │                 │  Encryption Key : 256 bits            │    ║
║  └─────────────┬─────────────┘                 │  MAC Key        : 256 bits            │    ║
║                │                               └─────────────┬─────────────────────────┘    ║
║                │Intermediate Hash                            │  Symmetric Key               ║
║                ▼                                             │                              ║
║  ┌──────────────────────┐  ┌─────────────────────────┐       │  ┌────────────────────────┐  ║
║  │  Master Password     │  │  192-bit Nonce (CSPRNG) │───────┼─▶│  XChaCha20-Poly1305    │  ║
║  │  Hash (SHA-256)      │  └─────────────────────────┘       │  │  Nonce  : 192-bit      │  ║
║  └──────────────────────┘       ▲                            │  │  Payload: sym key      │  ║
║                │                │ Nonce                      └─▶│  Key: stretched mkey   │  ║
║                │          CSPRNG┘                               └──────────┬─────────────┘  ║
║                │                                                           │                ║
║                │                                                           ▼                ║
║                │                                        ┌───────────────────────────────┐   ║
║                │                                        │   Protected Symmetric Key     │   ║
║                │                                        └───────────────────────────────┘   ║
╚════════════════╪════════════════════════════════════════════════════╪══════════════════════╝
                 │                   🔒 https://                      │
                 ▼                                                    ▼
╔════════════════════════════════════════════════════════════════════════════════════════════════╗
║  CLOUD                                                                                         ║
║                                                                                                ║
║      KMS – Data Protection Key – XChaCha20-Poly1305 Encryption                                ║
║  ┌────────────────────────────────┬───────────────────────────────────────┐                   ║
║  │  SHA-256(Master Password Hash) │       Protected Symmetric Key         │                   ║
║  ├────────────────────────────────┴───────────────────────────────────────┤                   ║
║  │       Database with Transparent Data Encryption (TDE)                  │                   ║
║  ├────────────────────────────────┬───────────────────────────────────────┤                   ║
║  │  SHA-256(Master Password Hash) │       Protected Symmetric Key         │                   ║
║  └────────────────────────────────┴───────────────────────────────────────┘                   ║
╚════════════════════════════════════════════════════════════════════════════════════════════════╝



Key Derivation Function: Argon2ID

HKDF: HKDF-SHA-256 which offers 128 bits of quantum security

Symmetric Key Algorithm: XChaCha20-Poly1305

-------------------------------------------

## Full Stack

All possible backend and frontend frameworks will be visitable,

auditable, and therefore hackable by visitors.

Backends: 

	1. Flask

	2. Django

	3. FastAPI

## Frontends Featured in the Exercises

| Exercise | Backend | Frontend |
|---|---|---|
| 1 | FastAPI | React |
| 2 | Flask | React |
| 3 | FastAPI | React |
| 4 | Django | Alpine.js |
| 5 | Django | Next.js (TypeScript) |
| 6 | FastAPI | Nuxt.js (Vue) |
| 7 | Django | Angular |

**Distinct frontends:** React (×3), Alpine.js, Next.js, Nuxt.js, Angular:

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

## MFA Methods:

MFA methods TOTP and U2F will be allowed. People will be able to

register their account under either. If a person chooses U2F

they will not be allowed to use TOTP as a backup. Instead they

will be required to use a backup U2F key. This policy is enforced

to protect people from attacks exploiting fallback MFA methods.

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
