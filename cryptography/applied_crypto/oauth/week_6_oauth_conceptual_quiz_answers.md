Question 1: Grant Type Selection (Week 6 Core)

"We're building a mobile app (iOS and Android) that needs to access our backend API. The app will call endpoints like /api/user/profile and /api/posts. How would you handle authentication?"

Below is a sample of the data the `api/user/profile` endpoint

would return:

```
{
  "posts": [
    {
      "post_id": 789,
      "user_id": 12345,
      "author": "alice_smith",
      "content": "Just finished my morning run! 🏃‍♀️",
      "created_at": "2026-02-16T07:45:00Z",
      "likes_count": 23,
      "comments_count": 5,
      "is_public": true,
      "media": [
        {
          "type": "image",
          "url": "https://cdn.example.com/posts/789_1.jpg"
        }
      ]
    },
    {
      "post_id": 788,
      "user_id": 12345,
      "author": "alice_smith",
      "content": "Private thought - only friends can see",
      "created_at": "2026-02-15T20:30:00Z",
      "likes_count": 8,
      "comments_count": 2,
      "is_public": false,
      "visibility": "friends_only"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total_posts": 156,
    "has_more": true
  }
}
```

Which authentication method? (API Keys vs OAuth 2.0 vs mTLS)

1. OAuth2 is best in this case.

API Keys require the client handle an API key that has to constantly

be sent to endpoints. This is risky since the API key can be

stolen in a Man-in-the-Middle Attack. Even though TLS can mitigate

this API Keys have more issues. API Key Revocation is less

sophisticated as OAuth2--where OAuth2 offers the use of a refresh

token to replace an expired one.

mTLS is a great way to authenticate a client but does not give

the resource owner the decision to authorize access to specific

protected resources.

2. If OAuth, which grant type? (Authorization Code, Client Credentials, Implicit, etc.)

Authorization Code Grant Type is best practice

3. Why that choice?

Figure 6.6 -- Choose Appropriate Grant Type

Page 221 -- Grant Types

For both let's use the authorization code grant type. This is

the recommended grant type for OAuth2 for several reasons:

	1. Keep in mind the user is using a mobile phone and therefore can

authenticate themself using a web browser. User's login credentials are

not seen by the client. They are instead passed to the authorization

server (protected under TLS). The developers of the authorization

server are free to decide how authentication should take place.

This technique allows the client application to benefit from future

improvements to user authentication.

	2. Implicit grant is worse than the authorization grant type for several

reasons:

		1. No way for client to keep a secret. Losing the potential

	benefit from having a native client (mobile app) as a

	separate channel.

		2. No way to use refresh tokens.

	3. Client Credentials grant is less worse than Implicit Grant because

the client is responsible for storing a secret the client knows.

The issue with that option is that the resource owner has no

opportunity to authenticate themselves. This is a probelm since

only the client can decide when to access the sensitive info--not

the resource owner!

	4. Resource Owner Credentials Grant Type is a bad idea since the

resource owner gives away user credentials to client--and the client

sends the user's credentials to the authorization server. It is

risky to allow the client to handle the credential secrets. It is

also risky to have the client send the user credentials to the

authorization server.

	5. The Assertion Credentials Grant Type does not work since the client

is acting on behalf of the resource owner--making Assertion Credentials

Grant Type unsuitable.

4. What about PKCE? (Is it needed? Why?)

Yes, PKCE is needed when using the Authorization Code Grant Type.

PKCE will stop the attacker from intercepting stolen authorization

codes.

Question 2:

You mentioned in Question 1 that PKCE is needed for mobile apps using

Authorization Code flow. Now let's dive deeper into HOW PKCE actually

works.

1. What PKCE stands for

Answer:

Proof Key for Code Exchange

2. The attack scenario PKCE prevents (be specific - what type of attack?)

Authorization Code Interception Attack: An attacker can steal an

authorization code and send it to the authorization server.

3. How code_verifier works (what is it? where is it generated? where is it stored?)

A code_verifier is a randomly generated string of data. It is generated

and stored on the client.

4. How code_challenge works (what is it? how is it computed? where is it sent?)

The code_challenge is a cryptographic message digest (e.g SHA256)

of the code_verifier. This prevents the authorization server, or

anyone that compromises the authorization server, or anyone

that steals the code_challenge, from deducing what the code_verifier

is. 

The preimage resistance property of cryptographic message digests

prevents attackers from reversing

the code_challenge back to the code_verifier.

The client sends the code_challenge to the authorization server.

5. The verification step (how does the auth server verify PKCE?)

Later after the client has received the authorization code the client

makes a token request and attaches in its request the code_verifier.

The authorization server calculates the cryptographic message digest

of the code_verifier and checks if this digest matches the

code_challenge. If so request is approved and token is granted.

6. Why this prevents the attack (why can't an attacker use a stolen authorization code?)

An attacker cannot use the stolen authorization code without knowledge

of the code_verifier--which is supposed to be a long string generated

by a CSPRNG that is hard to guess.

Question 3:

1. What the state parameter is (what type of value? who generates it?)

The state parameter is a random string generated by a CSPRNG.

It defends OAuth2 against CSRF attacks. Such an attack can waste

client and server resources and cause the client to fetch a token

that was never requested (page 51 OAuth2 in Action).

2. When the state parameter is used (which steps in the OAuth flow?)

It is passed as the first call to the authorization server (pages 51

; 125 OAuth2 in Action). The authorization server replies with the state

parameter as one of the parameters of the redirect URI. So when the

redirect URI is called the client must check the validity of the

state parameter before continuing the OAuth2 flow.

3. What attack does the state parameter prevent? (be specific - name the attack type)

CSRF (Cross Site Request Forgery).

4. How does the attack work WITHOUT the state parameter? (describe the attack scenario)

If the state parameter is absent the attacker can inject their own

authorization code into the client--bypassing OAuth2 checks.

5. How does the state parameter prevent this attack? (what does the client check?)

See answer (2.)

6. Why constant-time comparison matters (bonus: security detail)

Without constant-time comparision (in Python you can use

`hmac.compare_digest()` for example) the attacker can deduce the

`state` parameter while the client is comparing before performing

redirection of URI.

----------------------------------------------------

Question 4:


2. What is a refresh token? (What is it? When is it issued? How long does it live?)

A refresh token can be used by OAuth2 to receive a new access token

and refresh token.

3. How does the token refresh flow work? (Step-by-step process)

	1. Client requests access to protected resource using

	access token but receives an error.

	2. Client next sends refresh token to authorization server

	and receives new access token and new refresh token. Previously
	
	sent refresh token is now null-and-void.
	
	3. Client now requests access to protected resource using

	new access token and is approved for access as response.

4. What does the authorization server return? (What tokens are returned?)

The new access token to access protected resource and new refresh

token are both returned. The previously sent refresh token is now

null-and-void.

5. Why should refresh tokens rotate? (What security benefit does rotation provide?)

Rotation of refresh tokens avoids the issue of an attacker stealing

the refresh token to receive an access token. If that happens an

attacker can abuse the access token to gain access to protected

resources. So it is wise to rotate refresh tokens to avoid this.

Rotation of refresh tokens renders the old refresh token null-and-void

and be replaced with a different, new refresh token. To ensure this

works refresh tokens should be valid significantly longer than

access tokens. Otherwise the refresh token expires too soon and the

entire OAuth2 flow must start all over again from scratch.

6. What happens to the old refresh token after rotation? (Why is this important?)

It is null-and-void. Even if an attacker steals the old refresh

token the attacker will be unable to receive a new access token

from the authorization server.

-----------------------------------

Question 5:

1. What does "Bearer token" mean? (What does token_type: "Bearer" signify?)



2. What are the different ways to send access tokens? (List the options)

3. Which method is recommended? (And why?)

4. Why are the other methods problematic? (Security issues with each)

5. What's the proper format for the recommended method? (Exact header format)
