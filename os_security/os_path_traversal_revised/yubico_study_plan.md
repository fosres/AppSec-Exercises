# Yubico Product Security Engineer Interview Prep
## 2-Week Study Plan (Dec 23, 2025 - Jan 5, 2026)

**Interview Date:** January 5, 2026  
**Role:** Product Security Engineer (Hardware/Firmware Security)  
**Location:** Remote, Western US  

---

## Executive Summary

This is a **Product Security Engineer** role focused on **hardware/firmware security** for YubiKey devices, NOT a web application security role. The position involves:

- Collaborating with firmware and software teams
- Ensuring YubiKey develops secure products (hardware authentication devices)
- Cryptographic protocol implementation security
- Secure development lifecycle for hardware/firmware

**Your Key Strengths for This Role:**
- ✅ Intel Threat Modeling (553+ threats, STRIDE methodology)
- ✅ C/C++ Systems Programming (YubiKey firmware is C/C++)
- ✅ Cryptography Expertise (XMSS, ChaCha20, Argon2)
- ✅ Intel Crypto Academy Level I training
- ✅ Hardware security understanding from Intel background

**Fit Assessment:** 8/10 - Much better aligned than AppSec web roles!

---

## Interview Panel

1. **Stephan** - Sr Product Security Engineer (Germany)
2. **Vishal** - Security Engineer (West Coast)
3. **Ben** - Director of Infrastructure Security (Colorado)
4. **Chad** - Sr Software Engineer (Seattle)

**Interview Structure:** 60 minutes with Stephan, 45 minutes each with Vishal, Ben, and Chad

---

## Week 1: Product Security Fundamentals

### Day 1 (Dec 23): YubiKey Architecture & FIDO2 - 5 hours

**Morning (3 hours): Understand YubiKey as a Product**

- What is inside a YubiKey?
	- Secure element (tamper-resistant cryptographic chip)
	- NFC chip for contactless communication
	- USB controller
	- Firmware running in C/C++
	
- **Read:**
	- YubiKey 5 Series Technical Manual: https://www.yubico.com/products/yubikey-5-overview/
	- YubiKey Hardware Architecture: https://developers.yubico.com/
	
- Cryptographic operations performed on-device:
	- ECDSA signatures
	- RSA operations
	- HMAC computations
	- Random number generation

**Afternoon (2 hours): FIDO2 Protocol Implementation Perspective**

- **Focus:** Not "how to use WebAuthn" but "how to IMPLEMENT CTAP2 in C"
- CTAP2 authenticator commands in firmware
- USB HID protocol implementation
- **Think:** You'd be reviewing C code that implements these protocols

**Study Resources:**
- FIDO2 CTAP Specification: https://fidoalliance.org/specifications/download/
- CTAP2 Protocol Overview: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- WebAuthn (W3C spec): https://www.w3.org/TR/webauthn-2/

**Deliverable:** Understand YubiKey is firmware device implementing crypto protocols in C/C++

---

### Day 2 (Dec 24): Hardware Security & Secure Elements - 5 hours

**Morning (3 hours): Secure Element Architecture**

- What is a secure element?
	- Tamper-resistant hardware
	- Isolated execution environment
	- Secure key storage
	- Physical attack resistance
	
- Key concepts:
	- Cryptographic key storage (keys never leave secure element)
	- Side-channel attack resistance (DPA, SPA, timing attacks)
	- Fault injection resistance
	- FIPS 140-2/140-3 certification requirements

**Study Resources:**
- FIPS 140-2 Overview: https://csrc.nist.gov/publications/detail/fips/140/2/final
- Secure Element Fundamentals: https://www.smartcard-hsm.com/2018/01/16/secure-elements.html
- Hardware Security Modules (HSM) concepts

**Afternoon (2 hours): Common Hardware Vulnerabilities**

- Fault injection attacks (voltage glitching, clock glitching)
- Power analysis (DPA - Differential Power Analysis, SPA - Simple Power Analysis)
- Electromagnetic (EM) analysis
- Physical tampering and decapsulation
- Side-channel attacks on cryptographic implementations

**Study Resources:**
- "Introduction to Hardware Security" research papers
- Side-Channel Attacks: https://en.wikipedia.org/wiki/Side-channel_attack
- Common Weakness Enumeration (CWE) for hardware: https://cwe.mitre.org/

**Deliverable:** Understand hardware attack surface and secure element protection

---

### Day 3 (Dec 25): C/C++ Secure Coding - 5 hours
*Christmas - lighter day if needed*

**All Day: Review C/C++ Secure Coding Knowledge**

- Memory safety vulnerabilities:
	- Buffer overflows (stack, heap)
	- Use-after-free
	- Double-free
	- Null pointer dereference
	- Format string vulnerabilities
	
- Integer vulnerabilities:
	- Integer overflows in cryptographic code
	- Signedness issues
	- Truncation errors
	
- Cryptographic implementation pitfalls:
	- Timing attacks (constant-time operations)
	- Secure random number generation
	- Proper key zeroization
	- Side-channel resistant coding

**Study Resources:**
- CERT C Secure Coding Standard: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
- CWE Top 25 Most Dangerous Software Weaknesses: https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html
- "The Art of Software Security Assessment" (Chapter on C/C++)
- OWASP C-Based Toolchain Hardening: https://owasp.org/www-pdf-archive/C-Based_Toolchain_Hardening.pdf

**Practice:** Review sample C code for security vulnerabilities

**Deliverable:** Refresh secure C/C++ coding practices

---

### Day 4 (Dec 26): Threat Modeling for Hardware - 6 hours

**Morning (3 hours): Apply STRIDE to Hardware**

- Threat modeling YubiKey itself (not web applications)
- Physical attack surface:
	- Spoofing: Device impersonation, cloning attempts
	- Tampering: Firmware modification, hardware modification
	- Repudiation: Audit logging of device operations
	- Information Disclosure: Side-channel leakage, physical probing
	- Denial of Service: Device bricking, battery drain
	- Elevation of Privilege: Bypassing authentication, privilege escalation
	
- Supply chain security:
	- Manufacturing security
	- Component sourcing
	- Firmware signing and updates
	
- **Your Intel experience translates DIRECTLY here!**

**Study Resources:**
- Microsoft STRIDE Threat Modeling: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- NIST SP 800-30: Risk Assessment Guide: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- Hardware Threat Modeling frameworks

**Afternoon (3 hours): Security Testing Methodologies**

- Static analysis for C/C++:
	- Coverity
	- Clang Static Analyzer
	- CodeQL
	- cppcheck
	- PVS-Studio
	
- Dynamic analysis:
	- Fuzzing firmware (AFL, libFuzzer)
	- Valgrind (memory errors)
	- Address Sanitizer (ASan)
	- Memory Sanitizer (MSan)
	
- Penetration testing hardware:
	- Fault injection testing
	- Side-channel analysis
	- Protocol fuzzing
	
- Cryptographic validation:
	- NIST CAVP testing
	- Known Answer Tests (KATs)

**Study Resources:**
- Fuzzing Book: https://www.fuzzingbook.org/
- Google's OSS-Fuzz: https://google.github.io/oss-fuzz/
- NIST Cryptographic Algorithm Validation Program: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

**Deliverable:** Can apply STRIDE to hardware products and explain testing approaches

---

### Day 5 (Dec 27): Cryptographic Protocols in Firmware - 6 hours

**All Day: Deep Dive into Protocol Implementation**

**WebAuthn/FIDO2 Implementation Details:**

- How ECDSA signatures are computed in firmware:
	- P-256 curve operations
	- Hash-to-curve operations
	- Signature generation and verification
	
- Challenge-response in constrained environments:
	- Random challenge generation (TRNG requirements)
	- Secure storage of challenges
	- Time-bounded responses
	
- Attestation certificate chains:
	- Device attestation keys
	- Certificate validation
	- Trust anchor management
	
- Counter implementation:
	- Preventing replay attacks
	- Monotonic counter requirements
	- Persistent storage considerations

**OATH Protocols:**

- TOTP implementation (RFC 6238):
	- Time synchronization
	- SHA-1/SHA-256 HMAC
	- 30-second time windows
	
- HOTP implementation (RFC 4226):
	- Counter-based OTP
	- Shared secret storage
	- Resynchronization

**U2F and PIV:**

- Legacy U2F protocol support
- CTAP1 backward compatibility
- PIV smart card emulation
- Key management for multiple protocols

**Study Resources:**
- FIDO2 CTAP Specification: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238
- RFC 4226 (HOTP): https://datatracker.ietf.org/doc/html/rfc4226
- PIV Standard (NIST SP 800-73): https://csrc.nist.gov/publications/detail/sp/800-73/4/final
- WebAuthn Spec (implementation perspective): https://www.w3.org/TR/webauthn-2/

**Deliverable:** Understand cryptographic protocol implementation at firmware level

---

### Day 6 (Dec 28): Secure Development Lifecycle - 5 hours

**Morning (3 hours): SDL for Hardware Products**

**Requirements Phase:**
- Security requirements gathering
- Compliance requirements (FIPS, Common Criteria)
- Regulatory requirements
- Performance vs. security tradeoffs

**Design Phase:**
- Threat modeling (your strength!)
- Security architecture review
- Cryptographic protocol selection
- Hardware/firmware partitioning

**Implementation Phase:**
- Secure coding guidelines
- Code reviews (static analysis integration)
- Unit testing with security focus
- Cryptographic implementation review

**Verification Phase:**
- Security testing (penetration testing)
- Fuzzing campaigns
- Side-channel analysis
- Certification testing (FIPS, Common Criteria)

**Release Phase:**
- Secure firmware signing
- Update mechanism security
- Vulnerability disclosure policy
- Security advisory process

**Study Resources:**
- Microsoft SDL: https://www.microsoft.com/en-us/securityengineering/sdl/
- NIST Secure Software Development Framework: https://csrc.nist.gov/Projects/ssdf
- OWASP SAMM (Software Assurance Maturity Model): https://owaspsamm.org/

**Afternoon (2 hours): Vulnerability Management**

- CVE process:
	- CVE numbering authority (CNA)
	- CVE submission and publication
	- CVSS scoring
	
- Coordinated disclosure:
	- Responsible disclosure policies
	- Embargo periods
	- Researcher coordination
	
- Patch development and deployment:
	- Firmware update mechanisms
	- Secure boot verification
	- Rollback protection
	
- Security advisories:
	- YSA (Yubico Security Advisory) process
	- Customer communication
	- Public disclosure

**Study Resources:**
- CVE Program: https://www.cve.org/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1
- Yubico Security Advisories (examples): https://www.yubico.com/support/security-advisories/
- ISO/IEC 29147 (Vulnerability Disclosure): https://www.iso.org/standard/72311.html

**Deliverable:** Understand SDL for hardware and vulnerability management process

---

### Day 7 (Dec 29): STAR Stories & Company Research - 5 hours

**Morning (2 hours): Yubico Deep Dive**

**Product Line:**
- YubiKey 5 Series (USB-A, USB-C, NFC, Nano)
- YubiKey Bio Series (fingerprint authentication)
- Security Key Series (FIDO-only, lower cost)
- YubiHSM 2 (hardware security module)

**Study Resources:**
- YubiKey 5 Series: https://www.yubico.com/products/yubikey-5-overview/
- YubiKey Bio: https://www.yubico.com/products/yubikey-bio-series/
- Security Key Series: https://www.yubico.com/products/security-key/
- YubiHSM 2: https://www.yubico.com/products/hardware-security-module/

**Recent Security Advisories:**
- Review how Yubico handles vulnerabilities
- YSA advisories: https://www.yubico.com/support/security-advisories/
- Note their disclosure process and timeline

**Company Information:**
- Founded 2007 by Stina and Jakob Ehrensvard
- Public on Nasdaq Stockholm: YUBICO
- Co-invented U2F with Google
- Co-invented FIDO2/CTAP with Microsoft
- One of nine editors of W3C WebAuthn specification

**Resources:**
- Yubico About: https://www.yubico.com/about-us/
- Yubico Blog: https://www.yubico.com/blog/
- FIDO Alliance Leadership: https://fidoalliance.org/overview/leadership/

**Open Source Contributions:**
- libfido2: https://github.com/Yubico/libfido2
- python-yubico: https://github.com/Yubico/python-yubico
- yubikey-manager: https://github.com/Yubico/yubikey-manager

**Afternoon (3 hours): Prepare STAR Stories**

**Story 1: Threat Modeling Excellence (Ownership + Technical Depth)**

**Situation:**
- Intel's Product Assurance and Security division had inconsistent threat modeling across teams
- Threat Modeling Database lacked standardization
- Engineers were creating threats without consistent categorization

**Task:**
- Improve database quality and create standardization framework
- Make threat modeling more efficient and reusable
- Train engineering teams on proper methodology

**Action:**
- Analyzed 553 threats to identify patterns and common categories
- Applied STRIDE methodology systematically
- Created reusable threat model templates
- Documented 65.83% of Intel's Threat Modeling Database
- Trained 100+ engineers on standardized approach
- Set up automated validation for consistency

**Result:**
- Database accuracy improved from 60% to 95%
- Templates adopted across IPAS organization
- Reduced time to create threat models by 40%
- Became go-to resource for threat modeling best practices

**Connection to Yubico:**
"I would apply this same systematic approach to threat modeling YubiKey products, considering both logical and physical attack surfaces, and creating reusable frameworks for your product security team."

---

**Story 2: Cryptographic Implementation (Technical Expertise)**

**Situation:**
- Intel required secure cryptographic signature implementation
- Needed post-quantum cryptographic signatures for future-proofing
- Had to meet specific performance and security requirements

**Task:**
- Implement XMSS (Extended Merkle Signature Scheme) signatures
- Ensure implementation was secure and performant
- Integrate with Intel's security architecture

**Action:**
- Studied XMSS specification thoroughly (RFC 8391)
- Implemented in C with focus on constant-time operations
- Worked with ChaCha20 encryption and Argon2 key derivation
- Completed Intel Crypto Academy Level I training
- Collaborated with cryptography experts for validation
- Performed extensive testing and security review

**Result:**
- Successfully deployed secure XMSS implementation
- Met all performance requirements
- Passed security validation
- Gained deep understanding of cryptographic protocol implementation

**Connection to Yubico:**
"This experience directly translates to reviewing and implementing cryptographic protocols in YubiKey firmware, where I understand the importance of constant-time operations, secure random number generation, and resistance to side-channel attacks."

---

**Story 3: Secure C/C++ Development (Systems Programming)**

**Situation:**
- Working on security-critical systems code at Intel
- Needed to ensure memory safety and prevent vulnerabilities
- Operating in resource-constrained environments

**Task:**
- Write secure C/C++ code for embedded systems
- Prevent common vulnerability classes (buffer overflows, integer overflows)
- Maintain performance while ensuring security

**Action:**
- Applied secure coding standards (CERT C, MISRA C)
- Used static analysis tools to catch vulnerabilities early
- Implemented defensive programming techniques
- Performed thorough code reviews with security focus
- Tested with fuzzing and dynamic analysis tools
- Maintained awareness of compiler security features

**Result:**
- Delivered secure, high-quality systems code
- Zero critical security vulnerabilities in production
- Became team resource for secure C/C++ practices
- Developed strong foundation in systems security

**Connection to Yubico:**
"My C/C++ systems programming background is directly applicable to reviewing and developing YubiKey firmware, where memory safety and cryptographic correctness are critical in a constrained embedded environment."

---

**Story 4: Learning Agility (Intel Crypto Academy)**

**Situation:**
- Needed to deepen cryptographic knowledge for security engineering role
- Intel offered Crypto Academy training program
- Opportunity to learn from cryptography experts

**Task:**
- Complete Intel Crypto Academy Level I certification
- Master modern cryptographic algorithms and protocols
- Apply knowledge to real-world security projects

**Action:**
- Completed comprehensive cryptography training
- Studied symmetric/asymmetric cryptography, hash functions, KDFs
- Learned ChaCha20, AES-GCM, Argon2, ECDSA
- Practiced cryptographic protocol analysis
- Applied learnings to actual Intel security projects

**Result:**
- Achieved Level I certification
- Gained expertise in cryptographic implementations
- Became go-to resource for crypto questions in team
- Applied knowledge to multiple security initiatives

**Connection to Yubico:**
"This demonstrates my ability to quickly learn complex technical topics and apply them practically. I'm excited to deepen my knowledge of FIDO2/WebAuthn protocols and YubiKey's cryptographic implementation."

---

**Deliverable:** 4 polished STAR stories that connect Intel experience to Yubico role

---

## Week 2: Interview Preparation & Deepening

### Day 8 (Dec 30): Firmware Security Deep Dive - 5 hours

**Firmware Vulnerability Classes:**

**Memory Safety Issues:**
- Buffer overflows in constrained environments
	- Stack buffer overflows
	- Heap overflows (if heap is used)
	- Format string vulnerabilities
	
- Use-after-free vulnerabilities
- Double-free errors
- Null pointer dereferences
- Uninitialized memory usage

**Integer Vulnerabilities:**
- Integer overflows in crypto implementations
	- Length calculations
	- Buffer size computations
	- Counter overflows
	
- Signedness issues
- Truncation errors
- Wraparound vulnerabilities

**Cryptographic Vulnerabilities:**
- Timing attacks (non-constant-time operations)
- Weak random number generation
- Improper key zeroization
- IV/nonce reuse
- Padding oracle vulnerabilities

**Firmware-Specific Issues:**
- Secure boot bypass
- Firmware downgrade attacks
- Improper firmware update validation
- Debug interface exposure
- JTAG/SWD vulnerabilities

**Study Resources:**
- OWASP Embedded Application Security: https://owasp.org/www-project-embedded-application-security/
- CWE VIEW: Hardware Design (CWE-1194): https://cwe.mitre.org/data/definitions/1194.html
- "The Hardware Hacking Handbook" by Colin O'Flynn and Jasper van Woudenberg
- "Practical IoT Hacking" by Fotios Chantzis et al.

**Practice:**
- Review hypothetical C firmware code for security issues
- Look for common patterns that lead to vulnerabilities
- Think about how you'd explain findings in an interview

**Deliverable:** Can identify and explain firmware security vulnerabilities

---

### Day 9 (Dec 31): Static/Dynamic Analysis Tools - 4 hours
*New Year's Eve - lighter day*

**Static Analysis for C/C++:**

**Tools:**
- **Coverity**: Commercial static analyzer
	- Deep data flow analysis
	- Taint analysis
	- Resource leak detection
	
- **Clang Static Analyzer**: Open source
	- Part of LLVM project
	- Good at finding logic errors
	
- **CodeQL**: GitHub's semantic code analysis
	- Query-based analysis
	- Custom vulnerability patterns
	
- **cppcheck**: Lightweight static analysis
	- Easy to integrate in CI/CD
	- Good for quick checks
	
- **PVS-Studio**: Commercial analyzer
	- Good C/C++ coverage
	- Low false positive rate

**Study Resources:**
- Clang Static Analyzer: https://clang-analyzer.llvm.org/
- CodeQL for C/C++: https://codeql.github.com/docs/codeql-language-guides/codeql-for-cpp/
- cppcheck: https://cppcheck.sourceforge.io/

**Dynamic Analysis:**

**Fuzzing:**
- **AFL (American Fuzzy Lop)**: Coverage-guided fuzzing
- **libFuzzer**: In-process fuzzing for libraries
- **Honggfuzz**: Security-oriented fuzzer
- **OSS-Fuzz**: Google's continuous fuzzing service

**Memory Error Detection:**
- **Valgrind**: Memory debugging tool
	- Memcheck for memory errors
	- Helgrind for threading issues
	
- **Address Sanitizer (ASan)**: Fast memory error detector
- **Memory Sanitizer (MSan)**: Uninitialized memory detector
- **Undefined Behavior Sanitizer (UBSan)**: Undefined behavior detection

**Study Resources:**
- AFL: https://github.com/google/AFL
- libFuzzer: https://llvm.org/docs/LibFuzzer.html
- ASan/MSan/UBSan: https://github.com/google/sanitizers
- Valgrind: https://valgrind.org/docs/manual/quick-start.html

**Deliverable:** Understand major static/dynamic analysis tools for C/C++

---

### Day 10 (Jan 1): Mock Security Review - 4 hours
*New Year's Day - lighter day*

**Practice Code Review:**

**Exercise:**
1. Find a simple C cryptographic implementation on GitHub (e.g., AES, HMAC)
2. Perform a security review looking for:
	- Memory safety issues (buffer overflows, use-after-free)
	- Timing attacks (non-constant-time operations)
	- Integer overflows (length calculations)
	- Improper error handling
	- Weak randomness
	- Missing input validation
	- Resource leaks

**Good repositories to review:**
- Small crypto libraries on GitHub
- Embedded system code samples
- IoT firmware examples

**Study Resources:**
- Sample vulnerable code: https://github.com/OWASP/IoT-Security-Verification-Standard-test-cases
- CWE Examples: https://cwe.mitre.org/data/definitions/120.html (for each CWE)

**Practice Explaining Findings:**
- Write up vulnerabilities as if reporting to developers
- Explain: What is the vulnerability? How can it be exploited? What is the impact? How to fix it?
- Practice articulating this verbally (you'll do this in interviews)

**Deliverable:** Can perform and articulate security code review findings

---

### Day 11 (Jan 2): Authentication Protocols - 5 hours

**Focus: IMPLEMENTATION Perspective, Not User Perspective**

**WebAuthn at the Firmware Level:**

**Registration Flow (Authenticator Perspective):**
1. Receive `authenticatorMakeCredential` command from platform
2. Verify user presence (button press or biometric)
3. Generate new ECDSA key pair (P-256)
4. Store private key in secure element
5. Create credential ID (encrypted handle to private key)
6. Generate attestation signature over:
	- Public key
	- Credential ID
	- Relying Party ID hash
	- User handle
7. Return attestation object to platform

**Authentication Flow (Authenticator Perspective):**
1. Receive `authenticatorGetAssertion` command
2. Decrypt credential ID to retrieve key handle
3. Verify user presence/verification
4. Retrieve private key from secure element
5. Sign over:
	- Relying Party ID hash
	- Flags (user present, user verified)
	- Counter
	- Client data hash
6. Increment signature counter
7. Return assertion to platform

**CTAP2 Commands and Responses:**
- `authenticatorMakeCredential` (0x01)
- `authenticatorGetAssertion` (0x02)
- `authenticatorGetInfo` (0x04)
- `authenticatorClientPIN` (0x06)
- `authenticatorReset` (0x07)
- `authenticatorGetNextAssertion` (0x08)

**Study Resources:**
- CTAP2 Spec (Implementation Details): https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- WebAuthn Authenticator Model: https://www.w3.org/TR/webauthn-2/#sctn-authenticator-model
- Yubico's libfido2 source code: https://github.com/Yubico/libfido2

**Deliverable:** Understand WebAuthn/CTAP2 from authenticator implementation perspective

---

### Day 12 (Jan 3): Questions Preparation - 4 hours

**Prepare Thoughtful Questions for Each Interviewer**

**For Stephan (Sr Product Security Engineer, Germany) - 60 minutes:**

*Product Security Process:*
1. "What's your threat modeling process for new YubiKey features? Do you use STRIDE or another methodology?"
2. "How do you balance security requirements with firmware size and performance constraints?"
3. "What static analysis tools does the Product Security team use for C/C++ firmware code reviews?"
4. "How do you handle security considerations when supporting legacy protocols like U2F while adding new FIDO2 features?"

*Technical Deep Dive:*
5. "What's the most interesting firmware vulnerability you've discovered or prevented at Yubico?"
6. "How does the team stay current with new attack techniques against secure elements and hardware authenticators?"

---

**For Vishal (Security Engineer, West Coast) - 45 minutes:**

*Security Engineering:*
1. "What's the most challenging security vulnerability you've found in firmware or hardware at Yubico?"
2. "How does Yubico approach side-channel analysis and testing for YubiKey devices?"
3. "What's your experience with coordinated vulnerability disclosure? How does Yubico handle researcher reports?"

*Team and Culture:*
4. "What does a typical week look like for a Product Security Engineer here?"
5. "How does the security team collaborate with firmware and hardware teams?"

---

**For Ben (Director Infrastructure Security, Colorado) - 45 minutes:**

*Infrastructure & Supply Chain:*
1. "How do you secure the firmware build and release pipeline for YubiKey products?"
2. "What are the key supply chain security considerations for hardware manufacturing?"
3. "How does Yubico ensure the integrity of firmware updates from signing to deployment?"

*Security Organization:*
4. "How is the Product Security team structured relative to Infrastructure Security?"
5. "What security metrics or KPIs does the organization track?"

---

**For Chad (Sr Software Engineer, Seattle) - 45 minutes:**

*Implementation Challenges:*
1. "What are the biggest technical challenges in implementing FIDO2 protocols in constrained firmware environments?"
2. "How do you test cryptographic implementations to ensure both correctness and security?"
3. "What's the process for integrating new cryptographic algorithms or protocols into YubiKey firmware?"

*Development Process:*
4. "What does the code review process look like for security-critical firmware changes?"
5. "How does the team handle the trade-off between adding new features and maintaining backward compatibility?"

---

**Deliverable:** 3-4 thoughtful questions per interviewer that demonstrate deep technical interest

---

### Day 13 (Jan 4): Final Review + Rest - 3 hours
*Day before interview - keep it light!*

**Morning (2 hours): Final Review**

**Review STAR Stories:**
- Story 1: Threat Modeling (553 threats, templates, 100+ engineers)
- Story 2: Cryptography (XMSS, ChaCha20, Argon2)
- Story 3: Secure C/C++ (systems programming, memory safety)
- Story 4: Learning Agility (Intel Crypto Academy Level I)

**Quick Practice:**
- "What is your threat modeling experience?" (2 min answer)
- "Tell me about your cryptographic implementation work" (2 min answer)
- "How would you review C firmware code for security?" (2 min answer)

**Review Key Concepts:**
- FIDO2/CTAP2 from implementation perspective
- Common firmware vulnerabilities
- Static/dynamic analysis tools
- STRIDE threat modeling
- Secure element architecture

**Create 1-Page Cheat Sheet:**
- Key FIDO2 commands
- Common firmware vulns
- Your STAR stories (bullet points)
- Questions for interviewers
- Yubico product line

**Afternoon (1 hour): Logistics**

**Interview Preparation:**
- Test video/audio setup thoroughly
- Test screen sharing (in case they ask you to whiteboard)
- Prepare workspace:
	- Whiteboard or paper nearby for drawing diagrams
	- Pens/markers ready
	- Notes/cheat sheet in view
	- Glass of water
	
- Prepare questions document (printed or on second screen)
- Choose professional outfit
- Set multiple alarms for interview day
- Plan to wake up 2 hours before first interview

**Mental Preparation:**
- Review accomplishments (553 threats is impressive!)
- Remember: They're excited to talk to you (you made it to technical round!)
- Get good sleep (8+ hours)
- Don't cram new material tonight

**Deliverable:** Calm, confident, well-rested, logistically prepared

---

### Day 14 (Jan 5): INTERVIEW DAY

**Morning Routine:**

**2 Hours Before:**
- Light breakfast (protein, avoid heavy carbs)
- Coffee/tea if you normally drink it (avoid changing routine)
- Quick review of 1-page cheat sheet (15 minutes max)
- Don't cram - trust your preparation

**1 Hour Before:**
- Final tech check (video, audio, internet)
- Use restroom
- Pour water
- Silence phone notifications
- Close unnecessary applications
- Have cheat sheet, notebook, questions ready

**30 Minutes Before:**
- Put on interview outfit (professional top at minimum)
- Do breathing exercises if nervous
- Arrive at video call link 5 minutes early

---

**During Interviews:**

**General Strategy:**
- **Listen carefully**, take notes
- **Ask clarifying questions** before diving into answers
- For technical questions, **think out loud** - show your process
- For code review questions, **be systematic** (check inputs, memory safety, crypto, error handling)
- **Use your STAR stories** naturally when relevant questions come up
- **Draw diagrams** if discussing architecture or threat models
- **Mention Intel experience** when it connects directly

**Technical Question Approach:**
1. Restate the question to confirm understanding
2. Clarify any ambiguities
3. Explain your thought process
4. Give structured answer
5. Provide example if relevant
6. Ask if they want more detail

**Behavioral Question Approach (STAR):**
1. Situation (brief context)
2. Task (what needed to be done)
3. Action (what YOU did specifically)
4. Result (quantifiable impact)
5. Connection to Yubico role

**Questions to Ask:**
- Ask 1-2 questions per interviewer
- Listen for natural opportunities
- Show genuine curiosity
- Take notes on their answers

**Red Flags to Avoid:**
- Don't badmouth Intel or previous colleagues
- Don't pretend to know things you don't
- Don't interrupt interviewers
- Don't check your phone
- Don't go on too long - watch for cues

**After Each Interview:**
- Jot down quick notes (what went well, what to improve)
- Take a 5-minute break if possible
- Stay hydrated
- Reset for next interviewer

---

**Post-Interview:**

**Same Day:**
- Send thank-you email to recruiter Bryan
- Thank him for coordinating interviews
- Express continued enthusiasm
- Ask about next steps and timeline

**Within 24 Hours:**
- If Bryan provides interviewer emails, send brief individual thank-you notes
- Mention specific topic discussed with each person
- Reiterate interest in role

**Follow-Up:**
- Ask Bryan about feedback if you don't hear back in 5-7 days
- Stay positive regardless of outcome
- If rejected, ask for feedback to improve

---

## Key Study Resources Summary

### FIDO2/WebAuthn (Implementation Perspective)
- FIDO Alliance Specifications: https://fidoalliance.org/specifications/download/
- CTAP2 Specification: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html
- W3C WebAuthn Spec: https://www.w3.org/TR/webauthn-2/
- Yubico libfido2 (source code): https://github.com/Yubico/libfido2

### Hardware Security
- FIPS 140-2: https://csrc.nist.gov/publications/detail/fips/140/2/final
- Side-Channel Attacks: https://en.wikipedia.org/wiki/Side-channel_attack
- Secure Elements overview

### C/C++ Secure Coding
- CERT C Secure Coding Standard: https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard
- CWE Top 25: https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html
- OWASP C-Based Toolchain Hardening: https://owasp.org/www-pdf-archive/C-Based_Toolchain_Hardening.pdf

### Threat Modeling
- Microsoft STRIDE: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- NIST SP 800-30 (Risk Assessment): https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final

### Cryptographic Protocols
- RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238
- RFC 4226 (HOTP): https://datatracker.ietf.org/doc/html/rfc4226
- NIST CAVP: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

### Static/Dynamic Analysis
- Clang Static Analyzer: https://clang-analyzer.llvm.org/
- CodeQL: https://codeql.github.com/docs/codeql-language-guides/codeql-for-cpp/
- AFL Fuzzing: https://github.com/google/AFL
- Sanitizers (ASan, MSan): https://github.com/google/sanitizers

### Yubico-Specific
- Yubico Products: https://www.yubico.com/products/
- Yubico Blog: https://www.yubico.com/blog/
- Security Advisories: https://www.yubico.com/support/security-advisories/
- Yubico GitHub: https://github.com/Yubico

### Secure Development
- Microsoft SDL: https://www.microsoft.com/en-us/securityengineering/sdl/
- OWASP SAMM: https://owaspsamm.org/
- NIST SSDF: https://csrc.nist.gov/Projects/ssdf

### Embedded Security
- OWASP Embedded Application Security: https://owasp.org/www-project-embedded-application-security/
- CWE Hardware Design: https://cwe.mitre.org/data/definitions/1194.html

---

## Priority Study Rankings

### MUST DO (Non-negotiable)
1. ✅ Days 1-2: YubiKey architecture + Hardware security
2. ✅ Day 3: C/C++ secure coding review
3. ✅ Day 4: Threat modeling for hardware
4. ✅ Day 5: Cryptographic protocols in firmware
5. ✅ Day 7: STAR stories preparation
6. ✅ Day 12: Questions for interviewers

### SHOULD DO (Very Important)
1. Day 6: Secure Development Lifecycle
2. Day 8: Firmware vulnerability classes
3. Day 9: Static/dynamic analysis tools
4. Day 11: CTAP2 implementation details

### NICE TO HAVE (If Time Permits)
1. Day 10: Mock code review practice
2. Additional Yubico product deep dives
3. Advanced FIDO2 features

---

## Success Criteria

**You'll know you're ready when you can:**

1. **Explain FIDO2/WebAuthn from implementation perspective** (not just user perspective)
2. **Apply STRIDE threat modeling to YubiKey** as a physical hardware device
3. **Identify common firmware security vulnerabilities** in C code
4. **Discuss cryptographic protocol implementation** (ECDSA, HMAC, attestation)
5. **Tell your STAR stories confidently** with clear connections to Yubico
6. **Ask intelligent questions** that show deep technical interest
7. **Articulate your Intel experience** in ways relevant to hardware security

---

## Why You're a Strong Candidate

**Your Intel background is BETTER aligned for this role than most AppSec candidates:**

1. **Threat Modeling at Scale:** 553+ threats documented, templates for 100+ engineers
	- This is EXACTLY what Product Security Engineers do
	
2. **C/C++ Systems Programming:** YubiKey firmware is C/C++, not Python/JavaScript
	- Most AppSec engineers only know web languages
	
3. **Cryptographic Expertise:** XMSS, ChaCha20, Argon2 implementations
	- YubiKey is fundamentally a cryptographic device
	
4. **Hardware Security Understanding:** Intel Crypto Academy, secure elements knowledge
	- Hardware security is core to YubiKey products
	
5. **Formal Security Training:** Intel Crypto Academy Level I
	- Shows commitment to security engineering excellence

**You're not trying to become an AppSec engineer - you're already a Product Security Engineer who worked on Intel products and now wants to work on Yubico products!**

---

## Final Mindset

**Remember:**
- They invited you to technical interviews - they SEE your potential
- Your Intel background is HIGHLY relevant (threat modeling, crypto, C/C++)
- You don't need to know everything about YubiKey - show learning ability
- Be authentic - your genuine interest in authentication/crypto will shine through
- This role fits your background better than web AppSec roles

**You've got this!** 

Your combination of:
- Threat modeling expertise
- Cryptography knowledge  
- C/C++ systems programming
- Hardware security understanding

...makes you a strong candidate for this Product Security Engineer role.

---

**Interview Day Mantra:**
"I'm a security engineer with deep threat modeling and cryptography experience who's excited to apply my skills to YubiKey hardware security."

Good luck! 🔑
