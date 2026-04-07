Exercise 1:

```
Field						What It Says			Suspicious

From						"PayPal Security"			No
						<service@paypal.com>

Return-Path					<bounce@paypa1-secure.com>		Yes

Reply-To					verify-account@paypa1-secure.com	Yes

DKIM-Signature					d=paypa1-secure.com			Yes

Authentication-Results spf=			spf=fail (google.com: domain of service@paypal.com does not designate
        185.220.101.47 as permitted sender)						Yes

Authentication-Results dmarc=			dmarc=fail (p=REJECT) header.from=paypal.com

											Yes

First `Received:` (originating IP)		from smtp-relay.paypa1-secure.com	Yes

X-Mailer					PHPMailer 6.1.5 (https://github.com/PHPMailer/PHPMailer)										No
```

Solutions to Questions for Exercise 1

1. No, because the true domain the email was sent from is

`paypa1-secure.com` not `paypal.com`. We consistently see this domain

mismatch problem throughout the email details. Such as in the SPF.

2. The difference cannot be understated: `paypa1-secure.com` is

much longer and has different characters than `paypal.com`: a domain

mismatch. This is a phishing attack since the sender is pretending to be

`paypal.com` and is trying to trick the user into clicking on the link

to "Verify Email". The intended action is obvious: the victim is

supposed to type and submit their PayPal credentials to the attacker

after clicking on the "Verify Now" button.

3. The DKIM Signature mismatch is another piece of evidence the email

was sent by the owner of `paypa1-secure.com` and not `paypal.com` since

only the site owner of `paypa1-secure.com` would be able to send

such a signature.

4. DMARC failure takes place when an email message fails either

the SPF or DKIM tests and also checks if the authenticated domain in

the "From" field matches. In this case the email message fails

the SPF test, valid DKIM test, and the test to check if the email in

the "From" field matches the authenticated domain.

5. I did the following on the IP address of interest:

```
[I] fosres@fosres ~/P/g/A/n/email (main)> delv -x 185.220.101.47
; unsigned answer
47.101.220.185.in-addr.arpa. 86400 IN   PTR     tor-exit-47.for-privacy.net.
```

The IP address is a TOR exit-node IP address. Wow, totally not from

`paypal.com`, huh? Whoever sent this email sent it using The Onion

Router (TOR).

6. It suggests the attacker submitted the email using a PHP script.

Hmmm....Because what kind of email agent is sent using a PHP script

that calls upon the PHPMailer library.

Exercise 2

1. 3 hops

Starting from the SMTP Email Server of `paypa1-secure.com` to the

SMTP Server of Google (Gmail) to the MX Email server of our company.

2. Hop 2 is suspicious as it is on the blacklist.

3. There is NO SPF record found! No that does not match what I read

in the original bare plaintext email. When we read the bare plaintext

email message we read `service@paypal.com`

did not recognize the attacker's Tor exit node IP address as a

permitted sender.

4. Yes, in the Hops section as discussed in Part 2 the IP address

is in the blacklist. The attacker (or some other attacker) has abused

the same IP address to send malicious email messages before.

So when I compare the Google Admin Toolbox and MXToolBox I honestly

like the MXToolBox better because it indicates the IP address

the attacker sent with was with a TOR node--which is blacklisted.

Meanwhile Google Admin Toolbox shows there is nothing wrong amongst

the hops.

Another important difference is the Google Admin Toolbox says

IP address of SPF is unknown--which explains the cause of failure.

Exercise 3

Part A

URL: https://rubrique-details-activiter.info/index.php

ID:

Submission #9363781 is currently offline

Part B:

`urlscan.io` gives no results for the URL captured in Part A

Skipping Part B


Part C

1. 19 / 94 vendors red-flagged the suspicious URL:

rubrique-details-activiter.info. A lot of these mark

the URL suspicious to phishing--which confirms my hypothesis

that the attacker is trying to trick the user into submitting

credentials.

2. There are no Sibling Domains nor multiple pages

hosted by the same IP address.

3. No Analyst Comments 

4. There are 8 / 94 vendors that flag.

There are several other domains that share the same IP address.

Solution to Exercise 4

Part A

1. The Sender Policy Framework does appear. No, it does not include

`+all`--which would be dangerous because SPF would verify as valid

any email sent from any IP address or domain--this does not respect

principle of least privileges. Instead the SPF only permits emails

sent from the following IP addresses / subnets:

ip4:208.82.237.96/29 ip4:208.82.237.104/31 ip4:208.82.238.96/29

ip4:208.82.238.104/31

2. Yes, it has a DMARC.

`p=quarantine`

Unfortunately the DMARC record is an unsigned answer!

```
[I] fosres@fosres ~/P/g/A/n/email (main)> delv TXT _dmarc.craigslist.org
; unsigned answer
_dmarc.craigslist.org.  300     IN      TXT     "v=DMARC1; p=quarantine; pct=100; rua=mailto:ruarua@craigslist.org; ruf=mailto:rufruf@craigslist.org,mailto:craigslist-dmarc@datafeeds.phishlabs.com;"
```

3. Unfortunately the record for `craigslist.org` is unsigned.

Craigslist is vulnerable to DNS Cache Poisoning Attacks.


4 and 5. Judging by the fact that `craigslist.org` has DNS verification

records and that the real `craigslist.org` is already registered

even if an attacker sends an email from `jobs@craigslist.org` the

email will be thrown into spam since the DMARC records would fail.

Exercise 4

Part B

1. `paypal.com`'s DMARC policy is:

```
_dmarc.paypal.com.      3600    IN      TXT     "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com; ruf=mailto:d@ruf.agari.com"
```

So it is `p=reject`

Paypal does publish a `rua=` address in their DMARC record.

`rua` records specify the URI of the mailbox to receive DMARC aggregate

reports. It's required to request for DMARC aggregate reports.

3. Paypal does show `fully validated` for its domain which means

it is protected by DNSSEC. However the phishing domain does not.

Since PayPal is fully validted by my DNSSEC resolver we have reliable

assurance the IP address associated with `paypal.com` is the authentic

IP address registered for `paypal.com`.

4. Here are the results of the DMARC record record retrievals:

```
[I] fosres@fosres ~/P/g/A/n/email (main)> delv TXT _dmarc.amazon.com
                                          delv TXT _dmarc.linkedin.com
                                          delv TXT _dmarc.wikipedia.org
; unsigned answer
_dmarc.amazon.com.      900     IN      TXT     "v=DMARC1;" "p=quarantine;" "pct=100;" "rua=mailto:report@dmarc.amazon.com;" "ruf=mailto:report@dmarc.amazon.com"
; unsigned answer
_dmarc.linkedin.com.    3600    IN      TXT     "v=DMARC1; p=reject; rua=mailto:d@rua.agari.com,mailto:yfy3q-9359@rua.dmarc.emailanalyst.com; ruf=mailto:d@ruf.agari.com"
; unsigned answer
_dmarc.wikipedia.org.   600     IN      TXT     "v=DMARC1; p=reject; rua=mailto:dmarc-rua@wikimedia.org;"
```

So LinkedIn and Wikipedia both have `p=reject`. Only Amazon has

`p=qurantine`. `quarantine` means if an email will stil be sent

to the user's inbox but flagged as suspicious.

5. NXDOMAIN means the DNS Resource Record was not found. In fact

the question gives the answer away :D

If no DMARC records are found for a domain--that is NOT a good sign!

Be suspicious of emails sent from such a domain!

Exercise 5

1. So the abuse confidence is 95%--which isn't surprising considering

the IP address is a TOR exit node IP address.

2. There are 6491 reports of abuse since 2021! The most recent

report was only 6 hours ago when I queried!

3. Web App Attack ; Brute Force ; Spam ; the list goes on

4. This is a TOR exit node IP address! Not what you expect

the authentic domain owner to send from!

5. A malicious Tor user is impersonating `paypal.com` and trying

to trick the email recipient into giving away their credentials

to the attacker.

Answers to Shodan:

1. Shodan uses TCP Port 80

2. HTTP service is being used

3. Here is the banner: Tor built-in httpd

It is clear that a Tor service is running
