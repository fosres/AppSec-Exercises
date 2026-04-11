The following are a series of questions that are asked in the phone

interview for Security Engineering positions. I hereby archive 10

questions and their answers.

Question 1:

What is a three-way handshake?

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


Question 2:

How do Cookies Work?

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

Question 3:

How do session works?

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

Question 4:

Explain how OAuth Works:

OAuth is a framework that allows a third-party service (called a

client in OAuth2) to access a protected resource on behalf of a

resource owner (the human user).

Here are the steps on the most important version of OAuth2, the

authorization grant, works. My information is taken from

"OAuth2 in Action" -- page 23.

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

----------------------------------------------------------------------

Question 5. Explain how JWT works

The following answer is straight from:

https://www.jwt.io/introduction#what-is-json-web-token

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

Question 6:

What is a PKI flow? How would you diagram it?

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


Question 7:

Describe the difference between symmetric and asymmetric encryption:

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

Question 8:

What is the SSL Handshake?

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

Question 9:

Explain how HMAC works:

A Hash-based Message Authentication Code is built on a cryptographic

message digest. To use an HMAC a user must supply a secret key

and a document as two arguments. The HMAC will generate an ID

number unique to the secret key and document pair. The recipient

of a message can then verify that a message was truly sent

by the alleged sender by recalculating the HMAC and verifying the

HMAC sent by the sender matches the one the recipient recalculated.

Security Engineering Interviews care less on the math behind

how algorithms work and more on how to make use of them.

Solution to Question 10:

Explain why HMAC is designed that way:

Resource: Understanding Cryptography Second Edition

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

Question 11

What is the difference between authentication and authorization?

Authentication is about the user proving their identity to a

service. This is often done through password (still the only way

to encrypt the user's data securely using Zero-Knowledge Encryption).

A second identity test is Multi-Factor Authentication--which can

take the forms of Time-Based One Time Passwords (TOTP codes) (

Google 2FA), Hash-based One Time Passcodes (with the use of a security

key such as Yubikey), biometrics (not recommended in cases where the

user must protect their privacy from the service!), or ideally

Universal Second Factor Authentication (standardized by FIDO2 Alliance

) (which works by pluggin a security key into the computer and tapping

the key physically).

After the user manually authenticates using a combination of the

above methods -- websites that wish to keep track of the user's

session assign and send the user session credentials--such as

a Session Cookie. This allows the user to prove they have been

authenticated as they access resources to a service within a

time window. After said time window passes the session credentials

become invalid and the user must manually sign in again. This is

done to protect the user's account from theft in case the session

credentials are stolen.

Authentication should be complete before authorization tests take

place.

Authorization is about deciding who gets access to which protected

resource. Famous workflows such as OAuth2 have been engineered to

make it easier for developers to restrict which protected resources

a third-party service can access on a user's behalf. Authorization

has been done using techniques such as Role-Based Access Control

where the service decides if a registered user is allowed to access

a protected resource based on what role they have. For example

a registered user may be required to have the role of admin to

have access to a protected resource that allows the user to monitor

logs on the system. Another standard tecnique is Attribute-Based

Access Control--where the service decides if a register user

is allowed to access a protected resource based on the user's traits.

For example Youtube checks if a person is registered as above the 18

before allowing the user to access age-restricted videos. Historically

Authorization has been a difficult problem and is currently the OWASP

#1 issue in WebApps since it is hard to define and keep track of who

is allowed to access which resource.

Often in development a common bug is that developers think it is

sufficient to authenticate the user as a test of authorizaton.

This is not true! After verifying the user's identity the service

must check if the registered user has the required roles/traits

required to access the protected resource. And such mistakes

are hard to notice visually--and that allows attackers to silently

bypass. Another mistake is allowing the user

to specify what role they have in their input. Only the service

gets to record what role each user has! Otherwise an attacker

can escalate their privileges. Another mistake is contradictory

authorization policies. To avoid this OWASP recommends to apply

the same authorization template exactly once.

Question 12:

What's the difference between Diffie-Hellman and RSA?

Diffie-Hellman solved the problem of ensuring two people

across an untrusted network can exchange secrets with each other.

In reality the Diffie-Hellman Merkle Exchange is vulnerable

to the Diffie-Hellman Man-In-The-Middle Attack--where the attacker

establishes sessions with both sender and recipient individually,

decrypts, and reencrypts each party's message with the recipient's

public key to trick both sender and recipient to think they have

a shared session secret with each other exclusively. Nonetheless

Diffie-Hellman is the first major step in client-server encrypted

communication when both sender and recipient want to keep their

conversation confidential from others on the Internet.

The standard defenses against this attack are the modern TLS

Certificate Authority System--ideally also deployging websites

under DNSSEC and DANE.

RSA solved the issue of public-key encryption. One can use RSA

to first encrypt whole documents with a symmetric-key cipher

and then encrypt the symmetric key with the RSA public key to allow

the recipient to decrypt confidentially since only the recipient

knows the private key. RSA is also used as a digital signature

algorithm--meaning recipients of messages can verify that someone

sent an authentic message and said sender cannot later deny having

sent that message--just like a handwritten signature could. RSA

technically can also be used to establish a shared session secret

just like Diffie-Hellman--however starting from TLS 1.3 this was

dropped for ECDHE.

Question 14:

If compressing and encrypting a file, which do you do first, and why?

First compress then encrypt for if you do not--especially when using

an AEAD where authenticity of encrypted data is a concern--the

attacker can get away with tampering data.

Also encrypting first then compressing is less efficient to save

memory so for a great balance of security and performance one

should compress first then encrypt.


Question 15:

How do I authenticate you and know you sent the message?

There are several ways this is done in the industry:

In TLS this Message Authentication Codes (featuring a symmetric key)

allow me to authenticate messages but do NOT ensure non-repudiation.

This means the sender of a message can potentially get away with

sending a message simply by arguing the recipient modified

the message after receiving it.

To avoid that problem digital signatures were invented using

public-key cryptography such as RSA or EdDSA or the recent PQC

digital signature algorithms such as ML-DSA. Digital Signatures

will not allow the sender to deny having sent a message after

a recipient receives it since only the sender knows the private

key.

Question 16

Should you encrypt all data at rest?

Depends on the context. Simply encrypting all data at rest is

not a magic bullet to solve all your confidentiality problems.

For example if one is posting a comment on a social media platform

such as Youtube encrypting said data at rest is useless since

everyone is supposed to see the comment.

Likewise just because a service says they encrypt data at rest

does not mean your data is secure. One must take a look at the

threat model. Consider Proton Lumo (yes I am going to pick on

them)--they claim there is Zero-Knowledge Access Encryption.

However when you look at the system diagram for Proton Lumo's

U2L Encryption (https://proton.me/blog/lumo-security-model)

author Marc Dupont clearly admits Proton Lumo's LLM server can

clearly says "The LLM server possesses the private counterpart of the

PGP key the request was encrypted with, and thus can decrypt the

AES key. Using this key, the LLM gets to see the decrypted user message

and process it directly. The user’s cleartext message never leaves the

server, and the request is not logged or retained by the LLM server

after completing that request.". To be honest the U2L encryption is

therefore meaningless because whether or not the U2L encryption

exists in addition to TLS Proton Lumo's server knows the private key

--meaning they can give away captured user data once decrypted.

To Lumo's credit Lumo does not log requests but said privacy policy

can still work even without U2L encryption as do respectable

VPNs such as PrivateInternetAccess (the FBI failed twice to recover

user sensitive data from it). In fact Lumo's promise to *not* log

requests is what truly matters--not the U2L encryption. My main point

it is not sufficient to say data is encrypted at rest--one must

consider the threat model and evaluate how the key is managed and how

the sensitive encrypted data is stored (is an AEAD being used to detect

tampering?) Certainly there is value in Proton Lumo's promise to

store user data on their servers at rest encrypted--but they did not

need to apply asymmetric encryption since it actually does not offer

better privacy. Lumo could have simply stored the data at rest

encrypted using a symmetric key for encryption where said key is

managed by a FIPS-140-2 Hardware Security Module. As with U2L Lumo

still knows the key for decryption and again what really matters

is that Lumo does not log requests since whether or not Lumo

uses the symmetric-key encryption method I said vs their U2L

they can always quietly give away decrypted user data if pressured

by some organization like a government.

Question 17

What is Perfect Forward Secrecy?

Imagine if you and a recipient establish a shared session master

secret using Diffie Hellman Key Exchange. Then for each session

where we talk to each other you two establish a temporary shared

session secret tied to each individual conversation--so that is

called an ephemeral shared secret in cryptography. Now imagine

the worst--an attacker steals the shared session master secret?

Yet imagine even after the attacker steals the shared session

master secret the attacker is still unable to figure out any of

the ephemeral secrets tied to individual conversations since each

ephemeral secret was generated using a CSPRNG. That's the value

of Perfect Forward Secrecy: even if the attacker steals the long

-term session secret the attacker will not be able to crack

any of the short-term session secrets. This is the feature the

Signal messaging system is famous for. This is what TLS v1.3 now

does with ECDHE.

Question 18

 What are common ports involving security? What are their risks?

Here are the important ports:

Port 22 -- Secure Shell (SSH). SSH is under constant threat

of brute-force cracking for SSH password authentication. It

is recommended one use SSH public-key authentication for that

reason.

Port 23 -- Telnet (non-encrypted communication between client

and server ; SSH was invented to offer end-to-end encrypted

communication between client and server): Not encrypted -- do

NOT use in modern times

Port 25 - Simple Mail Transfer Protocol: Not encrypted by

default--strongly recommend deploying DNSSEC and DANE to ensure

end-to-end encrypted transit of email messages in transit.

Port 53 - Domain Name System: Not encrypted by default: strongly

recommend using a VPN service that encrypts DNS traffic as well.

Also DNS uses UDP which is connectionless and less reliable than

TCP.

Port 80 -- Hypertext Transfer Protocol: Traffic not encrypted

by default. Strongly recommend using HTTPS at all times instead.

All traffic request for Port 80 should be redirected to Port 443

for HTTPS Traffic

Port 443 - HTTPS: End-to-end encrypted HTTP Traffic. This is the

*de facto* industry standard for website communication between

server and client. HTTPS has been subject to HTTP downgrade

attacks such as the SSL Stripping Attack disclosed by Moxie

Marlinspike--whose mitigation is Strict Transport Layer Security.

Port 143 - IMAP: A protocol to retrieve email messages. At risk

of theft of plaintext credentials--whose mitigation is IMAPS

discussed below.

Port 993 -- IMAPS: A protocol to retrieve email messages under

protection of TLS (preferred--should be using in all cases!).

Port 3389 - Remote Desktop Protocol: Allows remote access to machines

by encrypting I/O--allowing one to access local files and apps

on a specific desktop. RDP unfortunately does suffer from security

vulnerabilities such as BlueKeep Vulnerability

(https://www.cloudflare.com/learning/access-management/what-is-the-remote-desktop-protocol/)

which affects old Windows OS implementations of RDP.

A second major downside is that slow connections can frustrate

users. In the past attackers have exploited it to install

cryptocurrency mining software.

Question 19

Which port was used for DNS

Port 53

Question 21

Describe HTTPS and how it is used

HTTPS ensures all HTTP traffic is protected under 

encryption in transit. This is usually done on port 443. Today TLS 1.3

is the recommended standard to deploy

HTTPS under--which fixes several security vulnerabilities previous

versions had. In the modern world most organizations first acquire

a signed TLS Certificate from a Certificate Authority (such as

Let's Encrypt). To deploy TLS an organization must include support

for TLS on their web server. A popular option is to simply deploy

the web application with `nginx` as a reverse web proxy to take

care of TLS Deployment. Before encryption under HTTPS can begin

the TLS handshake must first be completed between client and server.

Then encryption in transit under TLS 1.3 to establish an HTTPS

connection can begin.

HTTPS historically has been subject to several problems such as

TLS Certificate Misissuance and HTTP Downgrade Attacks such as the

SSL Stripping Attack.

TLS Certificate Misissuance takes place when a Certificate Authority

is tricked into signing a TLS Certificate to an imposter. To

prevent this several defenses have been invented such as Certificate

Authority Authorization, DNSSEC, and DANE.

To avoid HTTP Downgrade Attacks HTTP Strict Transport Layer Security

is recommended.

What is the difference between HTTPS and SSL?

SSL is the outdated standard for encrypting data in transit

under HTTPS--the protocol for encrypted HTTP traffic.

SSL was replaced since it was vulnerable to attacks such as the

BEAST and POODLE attacks.

The updated standard replacing SSL is TLS--we are now at TLS 1.3

and that is what websites should be using to encrypt data in transit

to clients with.

Question 22

How does threat modeling work?

According to Shostack's work "Threat Modeling Designing for

Security" the entire point of threat modeling is to detect weaknesses

in a security defense and fortify said weaknesses. No security system

is impenetrable so often serious decisions between security and cost

have to be made. Threat Modeling as a discipline was invented to

decide those trade-offs. Shostacks' work gives a template on how

to threat model under the STRIDE Threat Modeling Framework--which

asks us to identify vulnerabilities allowing an attacker to do the

following:

Spoofing: How can the attacker impersonate an authentic user's identity

Tampering: How can the attacker make unauthorized edits to information?

Repudiation: How can the attacker deny having performed an action

Information Disclosure: How can the attacker find and leak sensitive

information (e.g. password data breach then sold on the dark market)

Denial of Service: How can the attacker blockade others' access to

resources on a technology or service (e.g. a web service)

Elevation of Privileges: How can the attacker gain the permissions

to access protected resources the attacker is not qualified to have

access to?

These are the questions under STRIDE that help Threat Modelers

identify the vulnerabilities that can harm users. It is not enough

to just highlight vulnerabilities. Ideally a Threat Modeler must

sit--in person--with the development team and review the System

Diagram Architecture and specifications, then implementations, to find

vulnerabilities and make decisions on what defenses are worth the

hassle of deploying. Some companies try to handle this by making

generic databases of exploits that can affect various systems since

said organization can be very large--such as a corporation with 

an international staff.

Questions 23 and 24

What is a subnet and how is it useful in security?

A subnet is a subrange of IP addresses allocated to machines.

The first several bits of a 32-bit IP address for a network

is the IP Address for what is known as a CIDR Subnet notation.

The number of the first bits part of the subnet IP address

constitute the subnet mask.

The subnet mask is a 32-bit number that when binary ANDed to

an IP address of any machine in the network yields the network address.

A subnet separates machines from others in a computer network

--restricting other machines' access to those networks.

This is an essential security feature that protects access to

machines from adversary machines.

Smaller subnets have less risk of exposure.

Question 25 

Explain what traceroute is and how it works?

traceroute prints the route packets trace to a network host.

traceroute tries to do this by launching probe packets with a

small Time-To-Live then listening to an ICMP "time exceeded"

reply from the gateway. If the probe answers from different

gateways the answer of each probe will be listed. This is how

traceroute lists the routers through which packets are hopping

to in an attempt to reach the destination.

Q26 Draw a network, then find where an issue happened.

Question 29

What is the OSI model?

The OSI Model has  7 layers where bottom layers support upper layers.

It is an abstraction and is not perfect.

Below are the 7 layers:

Physical Layer: Physical hardware applying electric integrated circuits

to carry information (Someone destroys cables or smashes hardware

--not a formal cyberattack just saying this is the layer where that

happens :) )

Data Link Layer: This is the layer where Ethernet carries Internet

Data. (MAC Address Spoofing and ARP Spoofing takes place here )

Network Layer: This is the logical layer where IPv4 operates. In this

layer machines are allocated IPv4 addresses. (IP Address Spoofing

takes place here) 

Transport Layer: This is the layer that is part of TCP/IP.

This is the layer where attacks such as SYN floods, port scanning,

and TCP session hijacking take place.

Session Layer: It is argued TLS truly begins here

Presentation Layer - Serialization, Encoding, and Encryption

Negotiation here

Application Layer: The layer where protocols like HTTPS and WebSockets

(SQLi ; XSS attacks take place here!) exist.


Q30 How does a router differ from a switch?

A router transfers network packets amongst machines in the Network

Layer.

A switch transfers network packets amongst machines in the Data

Link Layer. Switches cannot segment broadcast domains without

VLANs. Routers enforce network boundaries. 

Q32:

How does a packet travel between two hosts on the same network?

A packet is transported either through the Network Layer or

Data Link Layer on a switch. Routers are not needed here since they

transport packets across networks. 

ARP translates network address to MAC addresses when a packet must

be translated from the Network Layer to Data Link Layer and

vice-versa.
