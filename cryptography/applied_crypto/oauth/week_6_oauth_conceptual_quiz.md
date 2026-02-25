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
