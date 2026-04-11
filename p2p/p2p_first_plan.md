# Free and Open Source Security Research (FOSRES)

Hi. I am Tanveer Salim. And usually I let Claude do the talking.

For the first time I am actually writing this from scratch.

I would like to introduce you to the FOSRES project. A project

meant to train future Security Engineers in Web/Cloud/AI Security.

In this project you will be challenged to audit and fix others' code

for security bugs, deploy applications in secure cloud environments

(here I use AWS only for now), and be asked to apply your skills with

using AI to reduce project timelines (a necessary skill you need

to build now). Just to let you know I have chosen Claude Code as my

official AI agent. Other AI Agents I would recommend are Mistral

(most privacy friendly although worse at software engineering

than Claude), or GLM-5 (not privacy-friendly at all).

Below I will explain the required tech skills you want to have:

## Topics for FOSRES Challenges

A. Web Security

You want to be able to audit and fix code containing any of these

vulnerabilities:

1. Broken Authentication / Authorization

        a. Session Cookie Authentication + CSRF

        b. Password Authentication

        c. JWT Token Authentication

2. Broken SQL Injection

3. Broken XSS

4. Server Side Request Forgery

5. IDOR (Insecure Direct Object Reference)

6. Missing Rate Limiting

7. OS Path Traversal

8. OS Command Injection

9. Malicious File Uploads

10. Security Misconfigurations (see Week 14 from 48-week Plan)

11. API Key Management & Authentication

12. Security Logging and Monitoring Failures

13. XXE Entity Bugs

B. Cloud Security

The only real way to learn Cloud Security is to *do* it:

hence why I am making this project. It is meant to teach you

Cloud Security as much as it is meant to teach me.

(To Be Determined)

C. AI Security

(To Be Determined)

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
║  │  Salt   : email address   │──────── Master Key┤    └──────────────────────────────────┘   ║
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
║                │                                             │  Symmetric Key               ║
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

Generated RSA Key Pair --> Replaced with:

ML-KEM-1024-X25519 Hybrid for Public Key Encapsulation

HKDF: HKDF-SHA-256 which offers 128 bits of quantum security

Symmetric Key Algorithm: XChaCha20-Poly1305

Support for Cryptography:

| Need | Python | JavaScript |
|---|---|---|
| **ML-KEM-1024 + X25519 (your design)** | **Manual combiner: `liboqs-python` + `cryptography` + HKDF** | **Manual combiner: `mlkem` + Web Crypto + `@hpke/core`** |

Manual support for the Hybrid Public Key Encryption will be done

based on [Request for Comments 9180](https://datatracker.ietf.org/doc/rfc9180/)

Python Libraries `liboqs-python` and `cryptography` will

be used in the backend.


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
