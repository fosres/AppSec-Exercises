Ans to Question 1:

In a recursive DNS query the DNS server queries other DNS servers

until it finds the answer.

In an iterative DNS query each DNS server responds to the client

with the IP address of another DNS server to ask for DNS resolution

(https://www.cloudflare.com/learning/dns/what-is-recursive-dns/)

Recursive DNS queries are the norm since they resolve faster than

iterative DNS queries. This is because Recursive DNS resolvers

caches the final answer to every query to save time next time the

DNS query is asked

Ans to Question 2:

https://www.cloudflare.com/learning/dns/dns-records/

A Record: Stores IP address of domain

AAAA Record: Stores IPv6 address of domain

MX Record: Directs mail to email server

CNAME Record: Forwards one domain or subdomain to another domain.

Although it does not give an IP address.

TXT Record: Allows admin to store text notes

NS Record: Stores the name server for a DNS entry.

SOA Record: Stores admin information about a domain.

3. delv @8.8.8.8 example.com NS +rtrace

This command asks `delv` to query for the `NS` Resource Record for

`example.com` and verify the entire DNSSEC chain-of-trust

using Google's public DNS recursive resolver (which has the IP address

of 8.8.8.8).

Here are the results of this query:

```
;; fetch: example.com/NS
;; fetch: example.com/DNSKEY
;; fetch: example.com/DS
;; fetch: com/DNSKEY
;; fetch: com/DS
;; fetch: ./DNSKEY
; fully validated
example.com.            21600   IN      NS      hera.ns.cloudflare.com.
example.com.            21600   IN      NS      elliott.ns.cloudflare.com.
example.com.            21600   IN      RRSIG   NS 13 2 86400 20251220035840 20251218015840 34505 example.com. Mb9DyAq4+c+1FkobbFRcp1iyA/MNMVBin+tMD2bMepY5j0G/4/c+puHx vWpppBjzd/NUEjvSFEoN1gVYOxVWTQ==
```

4.

In DNSSEC Resource Records are digitally signed by the administrator

for a domain using the Zone Signing Private Key. The Zone Signing

Public Key is published as a Resource Record and is signed by the Key

Signing Private Key. The Key Signing Public Key is also published as a

Resource Record and is signed by Key Signing Private Key. The Zone

Signing Private Key can be stored either offline (more secure) or

stored in a machine--such as Hardware Security Module. This would make

it easier for administrators to DNSSEC-sign new Resource Records. A

cryptographic message digest of the KSK DNS record, and this hashed

is signed by the DNS parent zone (e.g. a Domain Registrar). 

The DS record of the parent zone is signed, in turn, by its parent

DNS server (e.g. a TLD-DNS server). This process continues up until

the DNS root server.

DNSSEC keys for DNS root servers are self-signed and the signing

process is broadcasted to the whole public on Youtube for people

to verify.

5. DNS Cache Poisoning attacks take place when attackers compromise

a DNS recursive resolver and tamper DNS records. For example an

attacker can modify the IP address for google.com (which is not

protected by DNSSEC by the way!). If that happens even a victim

browser user manually types in the correct URL with HTTPS

(https://google.com) the victim browser user will be forwarded

to the IP address the attacker specified in the resolver!

DNSSEC was invented to mitigate this attack. DNSSEC mitigates this

attack by allowing the public to verify digitally signed DNS records.

This way clients can use DNSSEC-validating recursive resolvers to

ensure DNS records are authentic and not tampered.

RRSIG records carry the digital signatures of associated DNS records.

For example `cloudflare.com`'s A DNS Resource Records are signed by

CloudFlare's DNSSEC Zone Signing Private Key as seen below:

```
delv cloudflare.com
; fully validated
cloudflare.com.         300     IN      A       104.16.132.229
cloudflare.com.         300     IN      A       104.16.133.229
cloudflare.com.         300     IN      RRSIG   A 13 2 300 20251220041031 20251218021031 34505 cloudflare.com. aYU/0MkH0mCgeJDX1PW2g6PMml/axyWrrcH/ilBhNWpp/y7L5Tp34J2B RzD7Tl3irvtrWT8yBzkAXihzk+0FdQ==
```

Ans to Question 6:

In DNS tunneling attacker send traffic that is not standard DNS

traffic (e.g. HTTPS traffic or VPN traffic).

Attacker can abuse tunneling to bypass network security measures

and hijack command/control of infected devices.

DNS tunneling is easy to exploit because network admins often

allow DNS traffic to be sent unchecked.

Administrators can do payload analysis to analyze the contents of

DNS requests/responses for suspicious activity.

Ans to Question 7:

NOTE: You approved that I walk through TLS v1.3 instead.

In the TLSv1.3 handshake the client and server must establish

a shared secret using Diffie-Hellman Key Exchange.

1. ClientHello: This is always the first message sent in a new handshake.

In the ClientHello message the client gives its preferences for

which ciphersuites it wishes to use to secure its TLS connection

with the server, Compression Methods (if any selected), a randomly

generated number in case weak random generators are in use, etc.

In addition to generating the ClientHello message the client generates

its own private-public key pair (c,C = cQ) and sends the public key

C to the server in addition to sending the ClientHello message.

2. The server receives the client's public key C and the ClientHello

message. The server generates its own private-public keypair

(s,S = s). The server also generates a Diffie Hellman

secret = DH(s,C). The server next generates keys = KDF(secret).

The server generates a MAC over ClientHello, ServerHello, TLS

certificate, and signatures that are sent to the client using keys.

As a response the server sends a ServerHello message back to the client.

In this message the server explains what selected connection parameters

it has chosen to use to TLS with the client. This includes what

selected CipherSuites have been chosen. The server also sends its

public key S back to the client. The server also sends a TLS

Certificate compliant with the selected CipherSuite to the client

as well. The client needs the Certificate to verify the server

is authentic. The server signs the ClientHello and ServerHello

messages using the private key associated with its certificate.

The server now sends the signatures, ServerHello, and its TLS

certificate to the client.

Upon receipt of these messages the client first verifies the

Certificate and then the signatures. If these tests pass the client

next calculates its secret = DH(c,S) as well as keys = KDF(secret).

The client verifies the MAC the server sent to the client using

keys.

Now that all this information is verified TLSv1.3 handshake

successful and the client and server are ready to exchange

authenticated, encrypted messages with each other.

References:

Serious Cryptography, Second Edition

Bulletproof TLS and PKI, Second Edition

Ans to Question 8:

Intermediate certificates are easier to replace and revoke

than root certificates--mitigating the risk of compromise.

Reference:

https://www.ssldragon.com/blog/root-intermediate-certificate/

Ans to Question 9:

Certificate Transparency helps the general public detect the

miss-issuance of TLS certificates. Certificate Authorities sumbit

their public certificates to public log servers. Each log server

returns proof of submission called a Signed Certificate Timestamp

--which will need to be inspeced by end users. Certificate

Transparency aims to reduce the time it takes for the public to

realize a TLS Certificate has been misissued.

With the invention of Certificate Transparency domain owners,

browsers, academics, and others can analyze and monitor these

logs.

Certificate Transparency does NOT prevent the mis-issuance of

TLS certificates. That's what DNSSEC was invented for. A

DNSSEC validating CA such as Let's Encrypt will able to tell if

someone is attempting to impersonate a domain that is protected

under DNSSEC much more easily than one that does not.

Reference: certificate.transparency.dev

Ans to Question 10:

Here are some important reasons to always prefer TLS v1.3 over v1.2:

1. TLSv1.3 is more secure than TLS v1.2: it deprecates weak

CipherSuites

2. TLSv1.3 handshake is significantly faster.

3. In TLSv1.3 perfect forward secrecy is mandatory

4. TLSv1.3 round trip time is zero.

5. TLSv1.3 offers better performance

References:

https://www.loginsoft.com/post/tls-1-3-vs-tls-1-2-understanding-key-security-and-performance-differences 

https://www.geeksforgeeks.org/computer-networks/differences-between-tls-1-2-and-tls-1-3/

Ans to Question 11:

1. It seems the server is using a version of TLS that is earlier

than TLSv1.3. The risk is the attacker is more likely to succeed

in a Man-in-the-Middle Attack by breaking the cipher or stealing

secret keys.

2. I would disable ciphersuites that do not offer the use of

ephemeral secrets or that do not feature AEAD ciphers. These two

critical features are mandatory in TLSv1.3. If possible I would

even contact the system administrators of the site and recommend

them to upgrade to TLSv1.3 since perfect forward secrecy and use

of AEADs is mandatory in TLSv1.3.

Here are specific examples of such CipherSuites:

# TLS 1.3 (suites in server-preferred order)
TLS_AES_256_GCM_SHA384 (0x1302)
TLS_CHACHA20_POLY1305_SHA256 (0x1303)
TLS_AES_128_GCM_SHA256 (0x1301)

# TLS 1.2 (suites in server-preferred order)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

Reference: https://stackoverflow.com/questions/79482550/apache-including-ciphers-that-arent-specifically-allowed-tls-1-3

3. I would test the TLS handshake process which should reveal

which ciphersuites are chosen by the server. Check for the use

of CipherSuites that feature ephemeral secrets and AEAD ciphers.

This should be visible in the ServerHello message response from

the server during the TLS handshake in TLSv1.3.

You should see the CipherSuite the server has chosen with the

`openssl` command like this:

```
---
SSL handshake has read 3982 bytes and written 397 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 256 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: F7FB07CD75123B463865FE2EC042C51E8BC36696138233A350FD19575D767D46
    Session-ID-ctx: 
    Resumption PSK: 8D0990260229D0403C26AD44B413F013BE84F50DD55730EC4200E14311473F80C9214E1320156AD9377467F566399B97
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 64800 (seconds)
    TLS session ticket:
    0000 - ca fe 0a 96 bb d0 50 03-45 e7 9d 3f 63 45 b9 05   ......P.E..?cE..
    0010 - 1a ef 1a e4 6d fc e4 d1-14 24 1a a5 5e 53 b2 42   ....m....$..^S.B
    0020 - e0 6b f1 79 38 af 7b aa-ab e5 fc e1 3c c7 fe 56   .k.y8.{.....<..V
    0030 - 26 44 4a 82 6c bf 24 8e-25 93 b6 f3 84 1d f2 ae   &DJ.l.$.%.......
    0040 - 3e 7e 6f 01 15 29 62 13-13 31 87 e3 97 b6 df 7e   >~o..)b..1.....~
    0050 - 23 0b 64 49 5c f1 1c c0-f9 08 81 fd ad 6e fd 6b   #.dI\........n.k
    0060 - 51 6a b1 3c 8b 67 61 c3-7b ba a9 6e 17 13 fa b8   Qj.<.ga.{..n....
    0070 - 7b ad 24 53 a1 4d 77 ff-f6 ab aa 58 90 4a 96 e2   {.$S.Mw....X.J..
    0080 - 83 8e 37 ea 7b de fd bd-d3 36 38 3b 19 72 0a d1   ..7.{....68;.r..
    0090 - 33 21 e3 85 54 5f a0 3a-bc a0 23 d0 7c 1a a9 b1   3!..T_.:..#.|...
    00a0 - 97 8c b5 52 44 ad 79 3b-de 66 d6 0c 5e 3c b9 c0   ...RD.y;.f..^<..
    00b0 - a5 f0 8a 45 c5 dc a5 8e-be 80 a4 cd 79 60 c0 7b   ...E........y`.{

    Start Time: 1766171216
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no
    Max Early Data: 0
---
```

4. This is a difficult scenario! If the client only supports

deprecated TLS versions the server should refuse the connection

request to protect the client. 

