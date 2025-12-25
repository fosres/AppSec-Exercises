#Week 2 Lab: OpenSSL HTTPS Security Analysis & Testing

## Lab Overview
**Difficulty:** Beginner-Intermediate  
**Estimated Time:** 2-3 hours  
**Prerequisites:** Basic command-line experience

This lab teaches practical OpenSSL skills for analyzing HTTPS connections to production websites. You'll learn to inspect TLS configurations, identify security vulnerabilities, and understand certificate validation—critical skills for Application Security Engineers performing security assessments.

---

## Learning Objectives

By completing this lab, you will:

1. Use `openssl s_client` to analyze HTTPS connections
2. Inspect and validate certificate chains
3. Identify weak cipher suites and deprecated protocols
4. Detect common TLS misconfigurations
5. Perform security assessments of real-world HTTPS implementations
6. Generate professional security reports

---

## Part 1: Basic HTTPS Connection Analysis (45 minutes)

### Background

Application Security Engineers regularly assess TLS/SSL configurations of web applications. Understanding how to inspect HTTPS connections helps identify vulnerabilities like weak encryption, expired certificates, or protocol downgrade attacks.[^1]

### Task 1.1: Your First HTTPS Connection Analysis

**Step 1:** Connect to Google and view the full TLS handshake

```bash
openssl s_client -connect google.com:443 -showcerts
```

Press Ctrl+C to exit after the connection establishes.

**What you're seeing:**
- **CONNECTED**: TCP connection established
- **Certificate chain**: All certificates from server to root CA
- **Server certificate**: Google's TLS certificate
- **TLS Protocol**: Version negotiated (e.g., TLSv1.3)
- **Cipher**: Encryption algorithm selected
- **Session-ID**: For session resumption

**Challenge Question 1:** In the output, find these three pieces of information:
1. What TLS protocol version was negotiated?

Answer:

TLSv1.3

Here is the snippet of the response that is relevant:

```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
```

2. What cipher suite is being used?

TLS_AES_256_GCM_SHA_384

3. How many certificates are in the chain?

Three certificates in the chain.

---

### Task 1.2: Extract and Inspect a Certificate

**Step 1:** Save Google's certificate to a file

```bash
openssl s_client -connect google.com:443 -showcerts < /dev/null 2>/dev/null | \
	openssl x509 -outform PEM > google_cert.pem
```

**Step 2:** View the certificate in human-readable format

```bash
openssl x509 -in google_cert.pem -text -noout
```

**Step 3:** Extract specific information

View just the issuer:
```bash
openssl x509 -in google_cert.pem -noout -issuer
```

View validity dates:
```bash
openssl x509 -in google_cert.pem -noout -dates
```

View the subject (who the certificate belongs to):
```bash
openssl x509 -in google_cert.pem -noout -subject
```

View Subject Alternative Names (SANs):
```bash
openssl x509 -in google_cert.pem -noout -text | grep -A1 "Subject Alternative Name"
```

**Challenge Question 2:** 
1. What is the certificate's "Not After" date (expiration)?

notAfter=Feb 25 15:50:08 2026 GMT

2. Who issued the certificate (Issuer)?

Google Trust Services

Below is the relevant line of evidence:

```
issuer=C = US, O = Google Trust Services, CN = WE2
```
3. What domains are listed in the Subject Alternative Names?

Long list of alternatives:

DNS:*.google.com, DNS:*.appengine.google.com, DNS:*.bdn.dev, DNS:*.origin-test.bdn.dev, DNS:*.cloud.google.com, DNS:*.crowdsource.google.com, DNS:*.datacompute.google.com, DNS:*.google.ca, DNS:*.google.cl, DNS:*.google.co.in, DNS:*.google.co.jp, DNS:*.google.co.uk, DNS:*.google.com.ar, DNS:*.google.com.au, DNS:*.google.com.br, DNS:*.google.com.co, DNS:*.google.com.mx, DNS:*.google.com.tr, DNS:*.google.com.vn, DNS:*.google.de, DNS:*.google.es, DNS:*.google.fr, DNS:*.google.hu, DNS:*.google.it, DNS:*.google.nl, DNS:*.google.pl, DNS:*.google.pt, DNS:*.googleapis.cn, DNS:*.googlevideo.com, DNS:*.gstatic.cn, DNS:*.gstatic-cn.com, DNS:googlecnapps.cn, DNS:*.googlecnapps.cn, DNS:googleapps-cn.com, DNS:*.googleapps-cn.com, DNS:gkecnapps.cn, DNS:*.gkecnapps.cn, DNS:googledownloads.cn, DNS:*.googledownloads.cn, DNS:recaptcha.net.cn, DNS:*.recaptcha.net.cn, DNS:recaptcha-cn.net, DNS:*.recaptcha-cn.net, DNS:widevine.cn, DNS:*.widevine.cn, DNS:ampproject.org.cn, DNS:*.ampproject.org.cn, DNS:ampproject.net.cn, DNS:*.ampproject.net.cn, DNS:google-analytics-cn.com, DNS:*.google-analytics-cn.com, DNS:googleadservices-cn.com, DNS:*.googleadservices-cn.com, DNS:googlevads-cn.com, DNS:*.googlevads-cn.com, DNS:googleapis-cn.com, DNS:*.googleapis-cn.com, DNS:googleoptimize-cn.com, DNS:*.googleoptimize-cn.com, DNS:doubleclick-cn.net, DNS:*.doubleclick-cn.net, DNS:*.fls.doubleclick-cn.net, DNS:*.g.doubleclick-cn.net, DNS:doubleclick.cn, DNS:*.doubleclick.cn, DNS:*.fls.doubleclick.cn, DNS:*.g.doubleclick.cn, DNS:dartsearch-cn.net, DNS:*.dartsearch-cn.net, DNS:googletraveladservices-cn.com, DNS:*.googletraveladservices-cn.com, DNS:googletagservices-cn.com, DNS:*.googletagservices-cn.com, DNS:googletagmanager-cn.com, DNS:*.googletagmanager-cn.com, DNS:googlesyndication-cn.com, DNS:*.googlesyndication-cn.com, DNS:*.safeframe.googlesyndication-cn.com, DNS:app-measurement-cn.com, DNS:*.app-measurement-cn.com, DNS:gvt1-cn.com, DNS:*.gvt1-cn.com, DNS:gvt2-cn.com, DNS:*.gvt2-cn.com, DNS:2mdn-cn.net, DNS:*.2mdn-cn.net, DNS:googleflights-cn.net, DNS:*.googleflights-cn.net, DNS:admob-cn.com, DNS:*.admob-cn.com, DNS:*.gemini.cloud.google.com, DNS:googlesandbox-cn.com, DNS:*.googlesandbox-cn.com, DNS:*.safenup.googlesandbox-cn.com, DNS:*.gstatic.com, DNS:*.metric.gstatic.com, DNS:*.gvt1.com, DNS:*.gcpcdn.gvt1.com, DNS:*.gvt2.com, DNS:*.gcp.gvt2.com, DNS:*.url.google.com, DNS:*.youtube-nocookie.com, DNS:*.ytimg.com, DNS:ai.android, DNS:android.com, DNS:*.android.com, DNS:*.flash.android.com, DNS:g.cn, DNS:*.g.cn, DNS:g.co, DNS:*.g.co, DNS:goo.gl, DNS:www.goo.gl, DNS:google-analytics.com, DNS:*.google-analytics.com, DNS:google.com, DNS:googlecommerce.com, DNS:*.googlecommerce.com, DNS:ggpht.cn, DNS:*.ggpht.cn, DNS:urchin.com, DNS:*.urchin.com, DNS:youtu.be, DNS:youtube.com, DNS:*.youtube.com, DNS:music.youtube.com, DNS:*.music.youtube.com, DNS:youtubeeducation.com, DNS:*.youtubeeducation.com, DNS:youtubekids.com, DNS:*.youtubekids.com, DNS:yt.be, DNS:*.yt.be, DNS:android.clients.google.com, DNS:*.android.google.cn, DNS:*.chrome.google.cn, DNS:*.developers.google.cn, DNS:*.aistudio.google.com

**Security Note:** Modern browsers ignore the Common Name (CN) field and only validate domains against Subject Alternative Names. Missing SANs is a critical misconfiguration.[^2]

---

### Task 1.3: Certificate Chain Validation

**Step 1:** View the complete certificate chain

```bash
openssl s_client -connect google.com:443 -showcerts < /dev/null 2>/dev/null
```

Count how many "BEGIN CERTIFICATE" blocks you see.

**Step 2:** Verify chain validation

```bash
openssl s_client -connect google.com:443 < /dev/null 2>/dev/null | grep "Verify return code"
```

Expected output: `Verify return code: 0 (ok)`

**Challenge Question 3:** What does "Verify return code: 0" mean? What would indicate a problem?

That means certificate chain validation was successful. Any return

code other than zero would indicate an error took place in validation.
---

## Part 2: Protocol and Cipher Suite Security Testing (60 minutes)

### Background

Weak protocols (SSLv3, TLS 1.0/1.1) and cipher suites (RC4, DES, export ciphers) expose applications to attacks like POODLE, BEAST, and downgrade attacks. Major browsers deprecated TLS 1.0/1.1 in 2020.[^3][^4]

### Task 2.1: Test Protocol Support

**Test TLS 1.3 (most secure):**
```bash
openssl s_client -connect google.com:443 -tls1_3 < /dev/null 2>&1 | grep "Protocol"
```

**Test TLS 1.2 (still secure):**
```bash
openssl s_client -connect google.com:443 -tls1_2 < /dev/null 2>&1 | grep "Protocol"
```

**Test TLS 1.1 (deprecated - should fail):**
```bash
openssl s_client -connect google.com:443 -tls1_1 < /dev/null 2>&1 | grep "Protocol"
```

**Test TLS 1.0 (deprecated - should fail):**
```bash
openssl s_client -connect google.com:443 -tls1 < /dev/null 2>&1 | grep "Protocol"
```

**Test SSLv3 (severely broken - should fail):**
```bash
openssl s_client -connect google.com:443 -ssl3 < /dev/null 2>&1
```

**Challenge Question 4:** 
1. Which protocols does Google support?

Google supports TLS versions 1.1 - 1.3, inclusive.

2. What error do you get when trying SSLv3?

The following is the exact error message printed by `openssl`:

```
s_client: Unknown option: -ssl3
s_client: Use -help for summary.
```
3. Why was SSLv3 deprecated?

SSLv3 was deprecated due to serious security vulnerabilities like

the POODLE attack--rendering it unsafe for use.

---

### Task 2.2: Cipher Suite Analysis

**Step 1:** View the negotiated cipher suite

```bash
openssl s_client -connect google.com:443 < /dev/null 2>&1 | grep "Cipher"
```

**Step 2:** Test for weak RC4 cipher support (should fail)

```bash
openssl s_client -connect google.com:443 -cipher 'RC4' < /dev/null 2>&1 | grep "Cipher"
```

**Step 3:** Test for DES cipher support (should fail)

```bash
openssl s_client -connect google.com:443 -cipher 'DES' < /dev/null 2>&1 | grep "Cipher"
```

**Step 4:** Test for export-grade ciphers (should fail)

```bash
openssl s_client -connect google.com:443 -cipher 'EXPORT' < /dev/null 2>&1 | grep "Cipher"
```

**Challenge Question 5:** What cipher suite did Google negotiate? Does it provide forward secrecy? (Hint: look for ECDHE or DHE)

```
TLS_AES_256_GCM_SHA384
```
This is a ciphersuite of TLSv1.3 which provides forward secrecy.

**Secure Cipher Suite Examples (from "API Security in Action"):**[^6]
- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

---

### Task 2.3: Test Specific Cipher Suite

**Force a specific cipher:**
```bash
openssl s_client -connect google.com:443 -cipher 'ECDHE-RSA-AES128-GCM-SHA256' < /dev/null 2>&1
```

**Challenge Question 6:** Did Google accept this cipher? How do you know?

No, instead the ciphersuite `TLS_AES_256_GCM_SHA384` was chosen instead.
Here is the part of the response that makes this clear:

```
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
DONE
```

## Part 3: Common Security Issues (60 minutes)

### Task 3.1: Certificate Expiration Check

**Create a script to check certificate expiration:**

Below is my Python3 script. It is designed to be resistant to

OS Command Line Injection Attacks. One should press Ctrl+D

after the first command below in the script executes to

finish the openssl connection whose results stored in the

`cert_chain` variable:

```
#/usr/bin/python3

import sys
import subprocess


cert_chain = subprocess.run(["openssl","s_client","-connect",sys.argv[1]+":443","-servername",sys.argv[1]],capture_output=True,text=True)


file_name = "/tmp/cert_chain.txt"

with open(file_name,"w") as file:
	file.write(cert_chain.stdout)

subprocess.run(["openssl","x509","-noout","-dates","-in",file_name])
```

**Make it executable and test:**

**Challenge Question 7:** Why is certificate expiration monitoring critical for production systems?

Certificate Expiration is critical for production systems because

if certificates expire client connections will be left unprotected

by TLS past expiration. Some browsers block access to sites whose

certificates have expired to protect clients.

This would damage the reputation of the site if that happens.

---

### Task 3.2: Hostname Verification

**Test certificate hostname mismatch (simulated):**

```bash
# Connect to google.com but verify as if it's yahoo.com
openssl s_client -connect google.com:443 -verify_hostname yahoo.com < /dev/null 2>&1
```

**Challenge Question 8:** What error do you see? How does this protect against man-in-the-middle attacks?

The following is the error I see:

```
Verify return code: 62 (hostname mismatch)
```
**Security Note:** Endpoint identity validation (hostname verification) prevents attackers from presenting a valid certificate for `evil.com` to intercept traffic meant for `bank.com`. In Java, this is configured with `setEndpointIdentificationAlgorithm("HTTPS")`.[^6]

---

### Task 3.3: Self-Signed Certificate Detection

Many development environments use self-signed certificates. Learn to identify them:

```bash
# This site uses a self-signed cert (use carefully - educational only)
openssl s_client -connect self-signed.badssl.com:443 < /dev/null 2>&1 | grep "Verify return code"
```

You should see: `Verify return code: 18 (self signed certificate)` or `Verify return code: 19 (self-signed certificate in certificate chain)`

**Challenge Question 9:** Why are self-signed certificates dangerous in production?

They offer no meaningful assurance of authenticity. Any attacker

can make up a website and self-sign a fake certificate under the name

of `google.com` but only the real `google.com` can have their TLS

certificate signed by the official Intermediate Certificate Authority

"Google Trust Services".
---

## Part 4: Comprehensive Security Assessment (60 minutes)

(SKIPPING because it does not prepare us for General Security

Engineering interviews)

---

## Part 5: Automation Script (Bonus)

(SKIPPED ENTIRELY SINCE IRRELEVANT)

---

**Lab Version:** 1.0 (Revised)  
**Last Updated:** December 2025  
**Estimated Completion Time:** 2-3 hours  
**Difficulty Level:** Beginner-Intermediate  
**Focus:** Analysis & Testing (not PKI creation)
