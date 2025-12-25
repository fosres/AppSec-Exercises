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
