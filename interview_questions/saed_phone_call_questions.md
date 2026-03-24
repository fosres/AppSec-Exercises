The following are a series of questions that are asked in the phone

interview for Security Engineering positions. I hereby archive 10

questions and their answers.

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

2. How do Cookies Work?

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
