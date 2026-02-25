SSL/TLS Handshake Quiz - Free Response (Revised)

Question 1: TLS 1.3 Handshake Steps

Walk me through the TLS 1.3 handshake step-by-step. Start with the client initiating the connection and explain each message exchanged until application data can be transmitted. Be specific about message names.

The TLS Handshake protocol ensures client and server establish shared

secret keys.

Below is a rough outline of the message:

1. Client sends a ClientHello message. The

client specifies which algorithms the client

would like to use in TLS and sends a public key

to initiate key exchange.

2. The server responds with ServerHello

	a. Lets the client know which ciphers

	are selected.

	b. The server also sends its public key

	for key exchange.

3. Server sends TLS Certificate to client.

4. Server sends CertificateVerify message.

Server sends CertificateVerify message containing signature over

ClientHello + ServerHello + Certificate transcript. This proves

server owns private key corresponding to its TLS Certificate.

5. Finally server sends Finished Message containing a Message

Authentication Code over the entire handshake transcript.

6. Client validates TLS Certificate Chain.

	I. The client verifies the entire chain-of-trust

	from the server's TLS Certificate, past Intermediate Certificate

	Authority, and finally the Root Certificate Authority.

7. Client generates keys verifying MAC using specified HKDF

8. Client sends Finished Message back to server.

9. All communications between client and server henceforth

are encrypted with chosen AEAD (e.g. AES-256-GCM or

ChaCha20-Poly1305).

Question 2:

Why did TLS 1.3 make Diffie-Hellman key exchange mandatory instead of allowing RSA key exchange? What problem does this solve?

RSA Key Exchange cannot support forward secrecy. Forward secrecy

means even if a long-term key is compromised previously

encrypted sessions cannot be decrypted. RSA Key Exchange uses

long-term private keys for Key Exchange.

If the RSA keys for key exchange are compromised attackers

will be able to decrypt past sessions--so RSA Key Exchange was

dropped in TLSv1.3.
