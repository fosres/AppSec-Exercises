# Quiz Question 1: STRIDE Threat Model — Kerberos Windows Authentication

**Curriculum Reference:** Week 7 — Windows Security  
**Source:** *Complete 48-Week Security Engineering Curriculum*, p. 30  
**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)

---

## System Description

You are a Security Engineer tasked with threat modeling the **Kerberos Windows Authentication flow** using STRIDE.

### Components

| Component | Description |
|---|---|
| **Client** | Domain-joined workstation |
| **KDC** | Key Distribution Center / Domain Controller |
| **Service** | Target resource (e.g. file server) |
| **Active Directory** | Credential store (NTDS.dit) |

### Flows

| # | Flow | Description |
|---|---|---|
| 1 | Client → KDC | AS-REQ: Authentication request |
| 2 | KDC → Client | AS-REP: TGT + session key encrypted with NT Hash |
| 3 | Client → KDC | TGS-REQ: Service ticket request, presents TGT |
| 4 | KDC → Client | TGS-REP: Service Ticket encrypted with service account NT Hash |
| 5 | Client → Service | AP-REQ: Client presents Service Ticket |
| 6 | Service → Client | AP-REP: Optional mutual authentication confirmation |

### Cryptographic Context

| Layer | Algorithm | Status |
|---|---|---|
| Password storage (NT Hash) | MD4, no salt | Broken since 1995 |
| RC4 session keys | RC4 stream cipher | Deprecated mid-2026 (CVE-2026-20833) |
| Integrity verification | HMAC-SHA1-96 | Weak but not broken |

---

## Your Task

**For each letter of STRIDE, identify at least one concrete threat against this system.**

Consider each component (Client, KDC, Service, Active Directory) and each flow (1–6) when formulating your threats.

| STRIDE Category | Definition | Your Threat |
|---|---|---|
| **S** — Spoofing | Impersonating something or someone | |
| **T** — Tampering | Modifying data or code | |
| **R** — Repudiation | Claiming not to have performed an action | |
| **I** — Information Disclosure | Exposing data to unauthorized parties | |
| **D** — Denial of Service | Denying or degrading service | |
| **E** — Elevation of Privilege | Gaining capabilities without authorization | |

---

## Notes

- There is no time limit
- Think about each component and each flow independently
- Multiple threats per STRIDE category are encouraged
- Consider both the cryptographic weaknesses discussed (MD4, RC4) and the architectural trust assumptions of Kerberos
- When you are ready, submit your answer for grading

Spoofing:

	1. An attacker can generate a spoofed password that

collides with the NT hash to decrypt the TGT. This can allow the

attacker to next receive a Service Ticket which next would allow

the attacker access to the protected resource. Bear in mind NT

hashes use MD4 which is no longer a collision-resistant algorithm!

	2. An attacker can also generate a spoofed password that

collides with the client's NT hash to decrypt the client-server

session key. Once the attacker has the plain client-server session

key the attacker can next forge a Service Ticket signed with the

recovered client-server session key. Keep in mind the client-server

session key is used to HMAC-SHA1-96 sign the Service Ticket to prove

the Service Ticket has not been tampered with.


	2. Tampering:

		1. An attacker can compromise the Key Distribution

Center and tamper NT hash records on the Key Distribution Center.

	3. Repudiation:

		1. HMACs are used to sign the Service Ticket.

	Unfortunately HMACs do not offer non-repudiation! Under the

	Spoofing section I explained an attacker can forge an HMAC

	signature on a spoofed Service Ticket.

		2. An attacker that has stolen a Service Ticket,

	even if it is encrypted, and the client-server session key

	the attacker can construct a valid authenticator and thus

	gain access to the protected resource. The service will not

	be able to tell the difference between the attacker and

	an innocuous user. This is called Pass-the-Ticket.

		

	4. Information Disclosure:

		1. The Key Distribution Center sends an encrypted

	Ticket Granting Ticket. Kerberos supports weak ciphers
	
	including RC4 and DES. If these weak ciphers used an attacker

	can crack the key since DES only offers 56 bits of security

	and can therefore be cracked through brute-force. This was

	done by the EFF in the 1990s. RC4 is vulnerable to

	cryptanalysis. An attacker can thus crack the secret key

	from these weak ciphers and decrypt the Ticket Granting

	Ticket.

		2. If preauthentication is disabled an attacker

	can request a TGT for that specific user without credentials.

	When the TGT is requested a session key encrypted with the

	client's NT hash is also received. An attacker can next crack

	the session key offline. This is called ASREProasting.

		3. If the Service Account's password is weak a

	MITM attacker can decrypt the Service Ticket offline to

	recover the service account's password. This is called
	
	Kerberoasting.

	
		4. When requesting for a TGT the user may have to

	validate preauthentication by sending a timestamp encrypted

	with its own credentials. This is supposed to ensure the

	user is requesting a TGT. However MITM attackers can capture

	pre-authentication messages--including the encrypted timestamps.

	The attacker can next crack the encrypted timestamp to recover

	the user's password. This is known as ASREQroasting. 

		5. Timeroasting: Abuses Microsoft's NTP extension to

	extract password-equivalent hashes for computer and trust

	accounts from domain controllers without authentication. In

	Windows Kerberos unauthenticated clients can request salted

	password hashes for any computer account. Timeroasting only

	reveals the Relative Identifiers of computers. An attacker

	can use this information to map RIDs to hostnames. This allows

	attackers to leverage SMB Null session enumeration. Or the

	attacker can next correlate cracked password hashes to computer

	names using reconnaissance.

	5. Denial of Service:

		1. An attacker can compromise the Key Distribution

Center and tamper NT hash records. This allows the attacker to send

encrypted Ticket Granting Tickets with NT hashes already known to

the attacker. Since the attacker does not know of the change in

hash the client will be unable to decrypt the Ticket Granting Ticket.

	6. Elevation of Privilege:
	
		1. The main concern for elevation of privilege is

	an attacker bypassing authentication for a service.
---

*Generated during Week 7 Security Engineering study session — February 2026*
