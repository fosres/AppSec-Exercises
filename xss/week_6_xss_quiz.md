Exercise 1:

Vulnerable Code Snippet:


Vulnerabilities:

1. No Rate Limiting: An attacker can overwhelm the server with

excessive requests.

2. No headers for `X-XSS-Protection` nor protection against

MIME Sniffing (`X-Content-Type-Options: nosniff`).

3. No proper headers for `Content-Security-Policy`

4. No HTML Escape Encoding applied to `query` leaving webapp vulnerable

to Reflected XSS. 

5. Debug Mode is set to True. This is dangerous and can leak

sensitive info. Should be set to 'False'.

Exercise 2:

Vulnerabilities:

1. No rate-limiting. Attackers can overwhelm the webapp with excessive

requests.

2. There are inline scripts in the source code. There should be

`script-src` nonces to reduce risk of XSS. To learn how to do so

see the link:

https://www.johal.in/fastapi-content-security-csp-policies-nonce-hashes-strict-dynamic-2026/

https://www.compilenrun.com/docs/framework/fastapi/fastapi-security/fastapi-security-headers/

https://centralcsp.com/docs/csp-hashes-nonce

https://medium.com/@srirammanansri/why-xss-is-not-usually-possible-in-json-responses-cross-site-scripting-in-json-responses-67fa4a23b74d

3. SQL Injection Vulnerabilities in `create_comment()` and

`get_comment()`.

4. Lack of Security Headers in responses.

5. Stored/DOM XSS Vulnerabilities at line 240

Exercise 3:

Vulnerabilities:

1. No rate-limiting. An attacker can overwhelm the server with

excessive requests.

2. In `create_session()` the raw session ID is stored in the database.

This leaves the session ID at risk of exposure if the database is

stolen.

Likewise the hash of the session ID should be used to retrieve

the correct data from the database in `get_session_info()`.

Same idea for `logout_session()`.

3. XSS Vulnerabilties in `registerUser()` upon setting the value

of `result.innerHTML` (line 844). 

4. Similiar issues as (3.) in `loginUser()` upon setting the value

of `result.innerHTML` (line 867). 

5. Similiar issues as (3.) in `getProfile()` upon setting the value

of `result.innerHTML` (line 881). 

6. Similiar issues as (3.) in `createSession()` upon setting the value

of `result.innerHTML` (line 912).

7. Similiar issues as (3.) in `getSessionInfo()` upon setting the value

of `result.innerHTML` (line 928).

8. Similiar issues as (3.) in `testRateLimit()` upon setting the value

of `result.innerHTML` (line 956).

9. Similiar issues as (3.) in `getRateLimitStatus()` upon setting the value

of `result.innerHTML` (line 969) and when setting the `html` variable

(line 975).

10. Similiar issues as (3.) in `getViolations()` upon setting the value

of `html` in line 998.

11. Similiar issues as (3.) in `generateAPIKey()` upon setting the value

of `result.innerHTML` (line 1040).

12. Similiar issues as (3.) in `listAPIKeys()` upon setting the value

of `html` in line 1064.

Exercise 4:

Vulnerabilities:

0. No rate-limiting. An attacker can overwhelm the server

with excessive requests.

1. XSS vulnerability in `loadUsers()`.

2. XSS vulnerability in `loadPreferences()`.

3. XSS vulnerability in `executeJavascript()`.

4. XSS vulnerability in line 538.

5. XSS vulnerability in line 554.
