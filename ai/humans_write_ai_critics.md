---
title: Let Humans Write. Let AI Critique. A Manifesto for Security Engineers.
published: true
description: The evidence is in. AI-generated code ships more security vulnerabilities than human-written code. The solution is not to abandon AI — it is to use it for what it actually does well.
tags: security, ai, appsec, devsecops
cover_image:
---

*Security Engineering Series · March 2026*

---

> **The evidence is in.** AI-generated code ships more security vulnerabilities than human-written code. The solution is not to abandon AI — it is to use it for what it actually does well: **finding flaws before the code exists.**

---

Therefore let humans design and write code. Let AI critique every stage of development.

## 01 — The Problem Is Not That AI Exists. It Is That We Gave It the Pen.

Every week another team mandates AI coding assistants. Every quarter another report confirms the same thing: the code those assistants write is measurably less secure than code written by a careful human developer. This is not a matter of opinion. The data is replicated across multiple independent studies, multiple languages, and multiple AI models.

> *"Critical and major defects are up to 1.7x higher in AI-authored changes. Logic and correctness issues rise 75%, including business logic errors, misconfigurations, and unsafe control flow. Security vulnerabilities rise 1.5–2x, especially improper password handling and insecure object references."*
>
> — **CodeRabbit, State of AI vs Human Code Generation Report, December 2025** (470 open-source GitHub PRs)

The pattern holds at the architectural level, not just the line level. When Apiiro analyzed Fortune 50 enterprise repositories, the findings were significantly more severe than surface-level vulnerability counts suggest.

> *"Our analysis shows trivial syntax errors in AI-written code dropped by 76%, and logic bugs fell by more than 60%. But the tradeoff is dangerous: those shallow gains are offset by a surge in deep architectural flaws. Privilege escalation paths jumped 322%, and architectural design flaws spiked 153%. These are the kinds of issues scanners miss and reviewers struggle to spot – broken auth flows that look correct but aren't."*
>
> — **Apiiro, 4× Velocity, 10× Vulnerabilities: AI Coding Assistants Are Shipping More Risks, September 2025**

AI is excellent at eliminating shallow bugs — the typos, the off-by-ones, the missing null checks. It fails precisely where it is most dangerous to fail: trust boundaries, authorization logic, cryptographic implementation, and the systemic design flaws that span multiple files and services.

---

### By the numbers

| Stat | Source |
|---|---|
| **1.7×** more security vulnerabilities in AI-authored PRs vs. human PRs | CodeRabbit, Dec 2025 |
| **322%** increase in privilege escalation paths with AI coding assistants | Apiiro, Sep 2025 |
| **37.6%** increase in critical vulnerabilities after just 5 AI refinement iterations | arXiv:2506.11022, IEEE-ISTAS 2025 |
| **45%** of AI-generated code samples failed security tests across 100+ LLMs | Veracode GenAI Code Security Report, 2025 |

---

## 02 — Asking AI to Revise Its Own Code Makes It Worse, Not Better.

An intuitive response to insecure AI-generated code is to prompt the AI to fix it. Ask it to review, to harden, to patch. This is the wrong instinct. The research is unambiguous: iterative AI refinement degrades security rather than improving it.

> *"This paper analyzes security degradation in AI-generated code through a controlled experiment with 400 code samples across 40 rounds of 'improvements' using four distinct prompting strategies. Our findings show a 37.6% increase in critical vulnerabilities after just five iterations, with distinct vulnerability patterns emerging across different prompting approaches. This evidence challenges the assumption that iterative LLM refinement improves code security and highlights the essential role of human expertise in the loop."*
>
> — **Shukla, Joshi & Syed, Security Degradation in Iterative AI Code Generation: A Systematic Analysis of the Paradox, arXiv:2506.11022, accepted IEEE-ISTAS 2025**

The mechanism is not accidental. Each refinement pass takes the previous output as ground truth, compounding flaws rather than eliminating them. An authorization bug introduced in iteration one is baked deeper into the architecture by iteration five. The AI has no threat model for your system. It has patterns. And it applies them recursively.

> *"LLMs don't understand your architecture, context, or risk - they mimic patterns, not purpose. A fix that looks right might violate your access control model. A cleanup might strip away a critical logging statement. And unless someone's there to catch it, you'll only find out when it's too late."*
>
> — **Symbiotic Security, Exploring Security Degradation in Iterative AI Code Generation, July 2025**

---

## 03 — The One Variable That Reduces Vulnerabilities: Trust the AI Less.

This finding from Stanford is the most important result in this entire literature for practicing security engineers. It does not say AI is useless. It says the engineers who got better security outcomes were the ones who engaged critically — who questioned, rephrased, and rejected AI suggestions rather than accepting them.

> *"participants who had access to an AI assistant wrote significantly less secure code than those without access to an assistant. Participants with access to an AI assistant were also more likely to believe they wrote secure code, suggesting that such tools may lead users to be overconfident about security flaws in their code."*
>
> — **Perry, Srivastava, Kumar & Boneh (Stanford/UC San Diego), Do Users Write More Insecure Code with AI Assistants? ACM CCS 2023, arXiv:2211.03622**

This is not a call to stop using AI. It is a precise description of *how* to use it. The security benefit does not come from AI generating code. It comes from human judgment evaluating AI criticism. Those are structurally different workflows with measurably different outcomes.

> **"The security benefit comes from human judgment evaluating AI criticism — not from AI generating code."**

---

## 04 — What AI Actually Does Well: Finding Flaws Before the Code Exists.

There is real positive evidence for AI in security — but it is concentrated in AI as a *reviewer and critic*, not as a writer. The Gemini user study published in March 2026 found meaningful reductions in specific vulnerability categories when developers used AI assistance for review.

> *"When considering the individual vulnerabilities, Gemini assistance led to approximately 21.7% fewer vulnerabilities in password storage and 10.5% fewer in SQL vulnerabilities. However, participants still faced challenges, such as Gemini suggesting outdated libraries or omitting hashing recommendations. XSS vulnerabilities were improved by only 3.5% with the use of Gemini. CSRF and improper input validation seemed almost not to be influenced by Gemini usage."*
>
> — **Jost et al., The Impact of AI-Assisted Development on Software Security: A Study of Gemini and Developer Experience, arXiv:2603.15298, March 2026**

The pattern is clear: AI critique of specific, well-defined security properties helps. AI as an autonomous author does not. The right architecture for your workflow follows directly from that finding.

This maps to what software engineering has understood for decades about defect economics. Catching a design flaw at the requirements stage costs nearly nothing. Catching it in production costs orders of magnitude more. AI critics operating at the design, architecture, and specification stage apply pressure exactly where it is cheapest to respond to it.

> *"Finding and fixing vulnerabilities in production is orders of magnitude more expensive than preventing them during development. A skilled development team will write fewer insecure lines of code, resulting in fewer security findings, less rework, and a faster, more efficient delivery cycle."*
>
> — **SANS Institute, Why Security Tools Alone Won't Secure Your Code — and What Developers Really Need, September 2025**

---

## 05 — The Workflow: AI as Critic at Every Stage of the SDLC.

The principle is simple. **Humans write. AI criticizes. At every stage.** Not after the code is written and shipped — at every decision point in the development lifecycle, from requirements through architecture through implementation to review. Here is what that looks like in practice.

| Stage | Role |
|---|---|
| **Requirements** | **AI Critic asks:** What are the trust boundaries here? Who can call this? What data flows through it? What invariants must hold? Human defines the security requirements based on that challenge. |
| **Architecture** | **AI Critic asks:** Where are the privilege escalation paths? What happens if this service is compromised? What data does each component have access to? Human redesigns based on STRIDE analysis of the critique. |
| **API Design** | **AI Critic asks:** Is authorization checked at the right layer? What happens with a null input, a unicode bomb, an oversized payload? Human writes the spec that answers those questions. |
| **Implementation** | **Human writes the code.** AI does not author it. AI may be asked to explain a library's security properties, or to confirm that a proposed pattern is safe — but the implementation decision is human. |
| **Code Review** | **AI scans for pattern-based issues:** Semgrep, Bandit, CodeQL. Human triages findings against the threat model established in earlier stages. AI cannot determine exploitability — that judgment is human. |

This workflow is consistent with OWASP's own guidance on AI-assisted development, published in the OWASP Top 10 2025 Next Steps section:

> *"You should be able to read and fully understand all code you submit, even if it is written by an AI or copied from an online forum. You are responsible for all code that you commit. You should review all AI-assisted code thoroughly for vulnerabilities, ideally with your own eyes and also with security tooling made for this purpose (such as static analysis)."*
>
> — **OWASP Top 10 2025 — Next Steps (X01:2025), owasp.org/Top10/2025/X01_2025-Next_Steps/**

---

## 06 — The Expert Advantage: Threat Modeling Is What the AI Cannot Replicate.

The reason experienced security engineers get better outcomes from this workflow than junior developers is precisely because AI criticism is only as useful as the human evaluating it. The AI surfaces a list of concerns. The expert maps each concern against a real threat model — your specific system, your actual attack surface, your deployment context.

> *"AI can accelerate the mechanics of threat modeling, but developers still need to understand the fundamentals: how to think about trust boundaries, how to identify assets worth protecting, and how to anticipate how attackers might abuse a feature."*
>
> — **CSO Online, The New Paradigm for Raising Up Secure Software Engineers, February 2026**

This is not a reason for junior engineers to abandon the workflow. It is a reason for organizations to invest in security fundamentals alongside AI tooling. The OpenSSF has documented precisely what those fundamentals look like in the context of AI code assistants.

> *"Assume AI-written code can have bugs or vulnerabilities, because it often does. AI coding assistants can introduce security issues like using outdated cryptography or outdated dependencies, ignoring error handling, or leaking secrets."*
>
> — **OpenSSF Best Practices Working Group, Security-Focused Guide for AI Code Assistant Instructions, best.openssf.org**

---

## The Principles. With Their Sources.

→ **Humans write the code.** AI-generated code ships 1.7× more security vulnerabilities than human-written code in production repositories.
*— CodeRabbit State of AI vs Human Code Generation, Dec 2025*

→ **Do not ask AI to fix its own output.** After five AI refinement iterations, critical vulnerabilities increase by 37.6%.
*— Joshi et al., arXiv:2506.11022, IEEE-ISTAS 2025*

→ **AI is a critic, not a coauthor.** Engaging critically with AI output — not accepting it passively — is what produces fewer vulnerabilities.
*— Perry, Srivastava, Kumar & Boneh, ACM CCS 2023, arXiv:2211.03622*

→ **Critique at design time is cheaper than scanning at ship time.** Finding and fixing vulnerabilities in production costs orders of magnitude more than preventing them at design.
*— SANS Institute, September 2025*

→ **Threat modeling is the human skill AI cannot replace.** AI surfaces concerns. Experts map them against real threat models.
*— CSO Online, February 2026*

→ **You are responsible for all code you commit**, regardless of whether AI suggested it.
*— OWASP Top 10 2025, X01:2025 Next Steps*

---

## Want to Practice This?

I'm building a repository of **LeetCode-style secure coding exercises** — the kind of challenges that train the threat modeling instinct this workflow depends on. Each exercise includes a 60+ test suite and a companion post.

If you think high-quality, human-written secure code is the right training data for AI models, and you want to practice writing it yourself:

**⭐ [Star the repo on GitHub → github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

Every star helps the project reach more security engineers who want to sharpen this exact skill.

---

## One Quick Question

I write these posts to be useful, and I want to know what's actually useful to you.

**[→ Take the 30-second poll: Why do you read my blog posts?](https://strawpoll.com/wby5QoKAkyA)**

No signup, no email — just one click. The results directly shape what I write next.

---

*Security Engineering Series · dev.to/fosres · March 2026 · All citations link to primary sources*
