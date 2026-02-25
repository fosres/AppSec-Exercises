# Question 1: Mobile App Authentication (Week 6 Level)

## Scenario

We're building a mobile app (iOS and Android) that needs to access our backend API. The app will call these endpoints:

### API Endpoints

**`GET /api/user/profile`** - Returns user's profile information

```json
{
	"user_id": 12345,
	"username": "alice_smith",
	"email": "alice@example.com",
	"phone": "+1-555-0123",
	"full_name": "Alice Smith",
	"date_of_birth": "1990-05-15",
	"profile_picture_url": "https://cdn.example.com/profiles/12345.jpg",
	"preferences": {
		"newsletter": true,
		"notifications_enabled": true
	}
}
```

**Sensitivity**: HIGH - Contains PII (email, phone, DOB)

---

**`GET /api/posts`** - Returns user's posts (public and private)

```json
{
	"posts": [
		{
			"post_id": 789,
			"user_id": 12345,
			"content": "Just finished my morning run! 🏃‍♀️",
			"is_public": true,
			"likes_count": 23
		},
		{
			"post_id": 788,
			"user_id": 12345,
			"content": "Private thought - only friends can see",
			"is_public": false,
			"visibility": "friends_only",
			"likes_count": 8
		}
	]
}
```

**Sensitivity**: VARIABLE - Public vs private posts

---

**`POST /api/posts`** - Create new posts (requires write permission)

**`PUT /api/user/profile`** - Update user profile (requires write permission)

**`DELETE /api/posts/{id}`** - Delete user's posts (requires delete permission)

---

## Questions (Answer all 4)

### 1. Which authentication method should you use for this mobile app?

Choose from: **API Keys** vs **OAuth 2.0** vs **mTLS**

### 2. Which OAuth grant type should you use?

Choose from: **Authorization Code**, **Client Credentials**, **Implicit**, **Resource Owner Password**

### 3. Why is this the appropriate choice for mobile apps?

Explain your reasoning. Consider:
- What makes mobile apps different from backend services?
- What security properties does your chosen method provide?
- Why is PKCE mentioned for mobile apps?

### 4. Why would API Keys NOT be appropriate for this use case?

Compare API Keys to your chosen method. Consider:
- How would API Keys be distributed to mobile apps?
- What happens when an API key is compromised?
- Can you differentiate between users with API Keys?

---

## Instructions

Write your answer in **5-8 sentences** covering all 4 questions. 

Focus on:
- Grant type selection
- Security reasoning
- Why mobile apps need PKCE
- Why alternatives don't work

---

## Reference Materials

You should reference:
- **OAuth 2 in Action, Chapter 2, Section 2.2** (pages 22-30) - Authorization Code flow
- **OAuth 2 in Action, Chapter 6, Section 6.1** (pages 93-108) - Choosing grant types
- **OAuth 2 in Action, Chapter 6, Section 6.2.3** (pages 112-117) - Native applications
- **OAuth 2 in Action, Chapter 6, Section 6.2.4** (pages 117-118) - Public vs confidential clients

---

## What This Question Tests (Week 6 Scope)

- ✅ Do you understand when to use OAuth vs API Keys?
- ✅ Do you know Authorization Code + PKCE is for mobile apps?
- ✅ Do you understand why mobile = public client?
- ✅ Can you explain why API Keys don't work for user-specific access?

---

## Example Answer Format

Your answer should look something like this:

> I would use [METHOD] because [REASON]. For the grant type, I'd choose [GRANT TYPE] because [REASON]. Mobile apps are [PUBLIC/CONFIDENTIAL] clients, which means [EXPLANATION]. PKCE is required because [REASON]. API Keys would not work because [REASON 1], [REASON 2], and [REASON 3].

---

## Submit Your Answer

Write your answer below (5-8 sentences):

[YOUR ANSWER HERE]

Question 2:

# Question 2: PKCE Explanation (Week 6 Core)

## Scenario

You mentioned in Question 1 that PKCE is needed for mobile apps using Authorization Code flow. Now let's dive deeper into HOW PKCE actually works.

---

## The Question

**"Walk me through how PKCE works and what attack it prevents. Explain the mechanics of `code_verifier` and `code_challenge`."**

---

## What Your Answer Should Cover

Your answer should explain:

1. **What PKCE stands for**

2. **The attack scenario PKCE prevents** (be specific - what type of attack?)

3. **How code_verifier works** (what is it? where is it generated? where is it stored?)

4. **How code_challenge works** (what is it? how is it computed? where is it sent?)

5. **The verification step** (how does the auth server verify PKCE?)

6. **Why this prevents the attack** (why can't an attacker use a stolen authorization code?)

---

## Instructions

Write your answer in **6-10 sentences**. Be specific about:
- When each value is generated
- Where each value goes (client vs auth server)
- The cryptographic relationship between code_verifier and code_challenge
- Why PKCE specifically helps mobile/public clients

---

## Reference Materials

You should reference:
- **OAuth 2 in Action, Chapter 6, Section 6.2.4** (pages 117-118) - Public vs confidential clients
- **OAuth 2 in Action, Chapter 7, Section 7.7** (pages 136-137) - Native applications best practices, PKCE mention
- **OAuth 2 in Action, Chapter 10** - (You may want to reference this if you read ahead, though it's not required for Week 6)
- **RFC 7636** - Proof Key for Code Exchange (PKCE) specification (optional reference)

---

## Hints

Think about the flow:

```
Step 1: Client generates something BEFORE authorization request
Step 2: Client sends something TO auth server in authorization request  
Step 3: Auth server stores something
Step 4: Client receives authorization code
Step 5: [ATTACK COULD HAPPEN HERE]
Step 6: Client sends something ELSE to auth server in token request
Step 7: Auth server verifies something matches
```

What are the "somethings"? How do they relate to each other?

---

## What I'm Testing (Week 6 Scope)

- ✅ Do you understand what code_verifier and code_challenge are?
- ✅ Do you understand the cryptographic hash relationship (SHA-256)?
- ✅ Do you understand WHEN each value is used in the flow?
- ✅ Do you understand WHY this prevents code interception attacks?
- ✅ Can you explain this clearly to an interviewer?

---

## Submit Your Answer

Write your answer below (6-10 sentences):

[YOUR ANSWER HERE]

Question 3:

# Question 3: State Parameter (Week 6 Core)

## Scenario

In OAuth 2.0 Authorization Code flow, there's a parameter called `state` that's recommended (and sometimes required) for security. Let's explore what it does and why it matters.

---

## The Question

**"What's the state parameter in OAuth and why is it important? Explain the attack it prevents and how it works."**

---

## What Your Answer Should Cover

Your answer should explain:

1. **What the state parameter is** (what type of value? who generates it?)

2. **When the state parameter is used** (which steps in the OAuth flow?)

3. **What attack does the state parameter prevent?** (be specific - name the attack type)

4. **How does the attack work WITHOUT the state parameter?** (describe the attack scenario)

5. **How does the state parameter prevent this attack?** (what does the client check?)

6. **Why constant-time comparison matters** (bonus: security detail)

---

## Instructions

Write your answer in **6-10 sentences**. Be specific about:
- When state is generated
- Where state is sent
- What state is compared against
- Why the comparison prevents the attack

---

## Reference Materials

You should reference:
- **OAuth 2 in Action, Chapter 3, Section 3.2** (pages 46-51) - "Adding cross-site protection with the state parameter"
- **OAuth 2 in Action, Chapter 7** (pages 121-138) - Common client vulnerabilities
- **OAuth 2 in Action, Listing 2** (pages 312-313) - Callback and token request code

Key quote from page 51:
> "The state parameter is used to carry information about the client's state through the OAuth dance... it also serves an important security function in preventing certain kinds of attacks."

---

## Hints

Think about the OAuth flow:

```
Step 1: Client generates state value
        state = ???

Step 2: Client redirects to auth server
        /authorize?...&state=xyz789

Step 3: User authenticates and authorizes

Step 4: Auth server redirects back to client
        /callback?code=abc123&state=xyz789

Step 5: Client must do something with state before proceeding
        What check happens here?

Step 6: If check passes, exchange code for token
```

Also consider: What if an ATTACKER creates their own authorization request and tricks the victim into completing it?

---

## Example Attack Scenario (Think About This)

```
1. Attacker starts OAuth flow with their OWN account
2. Attacker receives callback with authorization code
3. Attacker STOPS before exchanging code for token
4. Attacker tricks Victim into clicking the callback URL
5. Victim's browser loads the callback in the legitimate app
6. WITHOUT state parameter: What happens?
7. WITH state parameter: What happens?
```

---

## What I'm Testing (Week 6 Scope)

- ✅ Do you understand what CSRF attacks are?
- ✅ Do you understand how state parameter prevents CSRF on OAuth callback?
- ✅ Do you understand the validation process (comparing stored vs received state)?
- ✅ Do you understand why random, unpredictable state values matter?
- ✅ Can you explain this attack scenario clearly?

---

## Bonus Points

If you mention:
- Why state should be cryptographically random
- Why constant-time comparison (`secrets.compare_digest`) should be used
- Why state should be single-use

---

## Submit Your Answer

Write your answer below (6-10 sentences):

[YOUR ANSWER HERE]

# Question 4: Token Refresh Flow (Week 6 Core)

## Scenario

Access tokens in OAuth have a limited lifetime and expire after a period of time (typically 15 minutes to 1 hour). When this happens, the app needs a way to get a new access token without forcing the user to log in again. This is where refresh tokens come in.

---

## The Question

**"How should an app handle expired access tokens? Walk me through the token refresh process."**

---

## What Your Answer Should Cover

Your answer should explain:

1. **What happens when an access token expires?** (What error does the API return?)

2. **What is a refresh token?** (What is it? When is it issued? How long does it live?)

3. **How does the token refresh flow work?** (Step-by-step process)

4. **What does the authorization server return?** (What tokens are returned?)

5. **Why should refresh tokens rotate?** (What security benefit does rotation provide?)

6. **What happens to the old refresh token after rotation?** (Why is this important?)

---

## Instructions

Write your answer in **6-10 sentences**. Be specific about:
- The trigger event (when refresh happens)
- What the client sends to the auth server
- What the auth server returns
- Why rotation matters for security

---

## Reference Materials

You should reference:
- **OAuth 2 in Action, Chapter 3, Section 3.4** (pages 54-58) - "Refresh the access token"
- **OAuth 2 in Action, Listing 4** (pages 313-314) - Refreshing an access token (code example)
- **OAuth 2 in Action, Chapter 5, Section 5.4** (pages 86-88) - "Adding refresh token support"
- **OAuth 2 in Action, Listing 10** (page 322) - Refreshing access tokens (authorization server side)

Key concepts:
- Access tokens are short-lived
- Refresh tokens are long-lived
- Token rotation (issuing new refresh token on each use)

---

## Hints

Think about the flow:

```
Step 1: App tries to call API with access token
        GET /api/user/profile
        Authorization: Bearer expired_token_xyz

Step 2: API responds with error
        What HTTP status code? What error message?

Step 3: App realizes token is expired
        What does the app do next?

Step 4: App sends refresh request
        POST /token
        What parameters are included?

Step 5: Auth server validates refresh token
        What checks does it perform?

Step 6: Auth server issues new tokens
        What tokens are returned?
        What happens to the old refresh token?

Step 7: App retries original API call
        With the new access token
```

---

## What I'm Testing (Week 6 Scope)

- ✅ Do you understand when token refresh happens?
- ✅ Do you understand the refresh token grant type?
- ✅ Do you understand what gets sent in the refresh request?
- ✅ Do you understand token rotation and why it matters?
- ✅ Can you explain the complete refresh flow?

---

## Example Flow (For Reference)

Consider this scenario:
- User logged in 2 hours ago
- Access token expired after 1 hour
- App tries to fetch user data
- API returns 401 Unauthorized
- App uses refresh token to get new access token
- App retries with new token

What are the exact steps?

---

## Submit Your Answer

Write your answer below (6-10 sentences):

[YOUR ANSWER HERE]

