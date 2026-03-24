# The LLM Dependency Test: A New Way to Interview Software Engineers in the Age of AI

**Tags:** `ai`, `career`, `security`, `productivity`

---

The Pentagon recently discovered that it could not comply with its own Secretary of Defense's direct order to remove an AI tool from its weapons targeting system. Not because the order was classified. Not because of a bureaucratic delay. Because the targeting workflows were so deeply embedded in that single commercial AI that the military — with a $900 billion annual budget and the entire US defense industrial base behind it — literally could not finish the job without it.

The same week, Pentagon staff resorted to Microsoft Excel to handle tasks previously managed by the AI.

This is not a story about the Pentagon. This is a story about every software team that has quietly built itself into the same trap — just at a smaller scale and with lower stakes.

---

## The Problem Nobody Is Naming

There is a growing and largely unacknowledged skill crisis forming underneath the surface of AI-assisted software development.

A generation of engineers is learning to build with AI as a first-class team member. They are shipping features faster, writing tests more confidently, navigating unfamiliar codebases with ease. By every observable metric, they are more productive than engineers who came before them.

But strip away the AI — network outage, service disruption, vendor dispute, policy change — and a disturbing number of them cannot finish what they started.

The problem is not that they use AI. The problem is that the AI has become load-bearing infrastructure in their cognitive workflow. The understanding of what is being built, the reasoning behind architectural decisions, the ability to close the last 10% of a project under pressure — all of it has migrated into the chat window.

When the chat window goes dark, so does the team.

---

## The Horror Story Is Real

On March 17, 2026, Claude went down for roughly five hours. Over 6,800 users reported problems. Developers working in Claude Code described it as a "snow day." They were mid-project. They stopped. *(Source: [6,800 users report Claude AI down in major today outage](https://rollingout.com/2026/03/17/claude-ai-outage-anthropic-downdetector/), Rolling Out, March 17, 2026)*

That is the benign version of the story. A team misses a deadline. A deployment slips. A demo gets rescheduled.

The catastrophic version is Palantir's Maven Smart System — a billion-dollar defense platform for intelligence analysis and weapons targeting — built so thoroughly on Claude Code prompts and workflows that recertifying it with a replacement model will take twelve to eighteen months according to defense contractors. Meanwhile the military is using it anyway, in an active conflict, in defiance of its own Secretary's order, because there is no alternative ready.

> *"Removing Claude will be a major undertaking. For example, Palantir's Maven Smart Systems — a software platform that supplies militaries with intelligence analysis and weapons targeting — uses multiple prompts and workflows that were built using Anthropic's Claude Code... Palantir will have to replace Claude with another AI model and rebuild parts of its software."*
>
> — Reuters / Military Times, [Hegseth wants Pentagon to dump Claude, but military users say it's not so easy](https://www.militarytimes.com/news/pentagon-congress/2026/03/19/hegseth-wants-pentagon-to-dump-claude-but-military-users-say-its-not-so-easy/), March 19, 2026

> *"Tasks previously handled by Claude, such as querying large datasets for information, are in some cases now being done manually with tools such as Microsoft Excel."*
>
> — Reuters / U.S. News, [Hegseth Wants Pentagon to Dump Anthropic's Claude, but Military Users Say It's Not So Easy](https://www.usnews.com/news/top-news/articles/2026-03-19/hegseth-wants-pentagon-to-dump-anthropics-claude-but-military-users-say-its-not-so-easy), March 19, 2026

> *"An internal Pentagon memo said use of Anthropic's tools may continue beyond the six-month period if deemed 'mission-critical' with no viable alternative."*
>
> — CNBC, [Palantir is still using Anthropic's Claude as Pentagon blacklist plays out](https://www.cnbc.com/2026/03/12/karp-palantir-anthropic-claude-pentagon-blacklist.html), March 12, 2026

The underlying engineering failure is identical in both cases. A single external dependency became load-bearing. No fallback was built. The humans forgot how to execute without the tool.

---

## Introducing the LLM Dependency Test

What if we could identify this problem before we hire — or before we deploy — rather than discovering it at the worst possible moment?

Here is a proposed interview format that directly measures the skill that actually matters:

**Phase 1 — AI-Assisted Development**

The candidate begins working on a novel software project with full access to their preferred LLM assistant. The project is unique to each candidate and each session. The AI helps them build. The candidate directs, reviews, and integrates the output. This phase continues for a set window of time — say, sixty to ninety minutes.

**Phase 2 — The Cutoff**

At a moment chosen at random within Phase 1, the AI is cut. No warning. No graceful transition. The service simply becomes unavailable, exactly as it would in a real outage.

**Phase 3 — The Finish**

The candidate must complete the remaining work without any LLM assistance. They have access to documentation, Stack Overflow, their own notes — everything a working engineer would have. Just not the AI.

**The Evaluation**

The test measures two things simultaneously:

First, what did the candidate do *before* the cutoff? Did they write clear comments? Did they commit incrementally? Did they ask the AI clarifying questions that forced explicit specification? Or did they passively accept generated output without building their own understanding of it? Their behavior during the AI-assisted phase reveals their architecture instincts.

Second, what do they do *after* the cutoff? Do they panic or shift gears? Can they read the AI-generated code they were steering and continue it coherently? Can they close the gap between where they are and a working deliverable?

A candidate who passes is not just good at using AI. They are good at engineering. The AI made them faster. Their fundamentals make them resilient.

---

## What the Test Is Really Measuring

This test does not measure raw coding speed. It does not measure prompt engineering skill. It does not measure whether a candidate has memorized syntax or API signatures.

It measures **mental model quality**.

If a candidate genuinely understood the project as it was being built — if they were directing the AI rather than following it — then the cutoff is an inconvenience. They know what remains. They know why each piece exists. They can continue.

If the candidate was watching the AI generate and clicking accept, the cutoff is a wall. They have working code they do not understand, a half-finished project with undocumented reasoning, and no map forward.

The test surfaces the difference in about fifteen minutes.

---

## The Architectural Principle Behind the Test

The insight the test is built on is simple: **the dependency on AI is not the problem. The architecture of that dependency is.**

A surgeon using a robotic system is not helpless when the system malfunctions — because their manual surgical skills are maintained. The robot made them more precise, not more dependent. Their training preserved the fallback.

An engineer who builds with AI as acceleration on top of solid fundamentals is not helpless when the AI goes down. The AI made them faster, not dependent. Their fundamentals preserved the fallback.

The test identifies which kind of engineer you are hiring. Not by asking. By showing.

---

## Why This Matters More in Security Engineering

For security engineers specifically, the stakes of AI dependency are compounded.

AI coding agents introduced into security workflows — for code review, vulnerability scanning, threat modeling — generate working outputs that can appear correct while containing subtle flaws. The DryRun Security study from March 2026 found that Claude Code, OpenAI Codex, and Google Gemini all introduced broken access control, OAuth implementation failures, and business logic vulnerabilities into every application they were tasked to build from scratch.

A security engineer who cannot independently audit AI-generated code is not a security engineer. They are a human rubber stamp on an AI output pipeline.

The LLM Dependency Test applied to a security engineering candidate would reveal immediately whether they can actually read and reason about code — or whether they can only steer an AI that reads and reasons for them.

In security, that distinction is the difference between a defended system and a breach waiting to happen.

---

## The Second-Order Effect

Here is the part of this proposal I find most interesting.

The moment a test like this exists and becomes known in the industry, it changes how candidates prepare. Engineers who know they will face a mid-project AI cutoff in their interviews cannot afford to let their fundamentals atrophy. They have to actually build their skills without the AI, not just alongside it.

The test does not just filter for the right candidates. It shapes the behavior of the candidate pool before anyone sits down to take it.

Most interview formats test for skills that candidates develop in order to pass the interview. This test forces candidates to develop the skill that protects them — and the teams that hire them — for the rest of their careers.

---

## A Note on What This Is Not

This is not an argument against using AI tools. Engineers who use AI assistants well are genuinely more productive. The data is clear on that.

This is an argument for using AI tools in the right architectural relationship — as acceleration on top of maintained human capability, not as a replacement for it.

The Pentagon did not fail because it used AI. It failed because it forgot to remain capable without it. The distinction is everything.

---

## The Challenge to the Industry

If you are running engineering interviews in 2026, consider adding a version of this test to your process. The implementation details are yours to design — the cutoff timing, the project scope, the evaluation rubric. But the core structure is sound.

If you are preparing for engineering interviews, consider what it would mean to face this test unprepared. Then build accordingly.

And if you are an engineering manager who has watched your team slow-roll to a halt every time a major AI service goes down — you already know what this test is measuring. The question is whether you hire for it before the next outage, or discover the gap during one.

---

*This post is based on a conversation about AI-assisted software engineering, the March 2026 Anthropic-Pentagon dispute, and what the engineering profession is not yet asking about AI dependency. The LLM Dependency Test concept was proposed by Tanveer Salim.*

---

## The Throughput Problem — And Why Option 3 Solves It

After I proposed the LLM Dependency Test, a sharp critic raised a problem the test does not fully address.

Even if a candidate passes — even if they perfectly understand the codebase and can articulate exactly what remains — they still face a **physics problem**. Modern projects are scoped assuming AI-assisted velocity. An engineer producing 50-100 lines of considered code per hour cannot close the gap left by an AI that was generating 10x that. Understanding the remaining 10% does not mean finishing it on time.

This is a real limitation. And it points to something the industry has not formally addressed: **project planning in the AI era has a hidden assumption baked into every timeline — that the AI will be available for the full duration.**

There are three architectural responses to this problem.

**Option 1 — Scope conservatively from the start.** Plan every project at human velocity. Treat AI as pure acceleration that moves you ahead of schedule, never as the baseline the schedule depends on. If the AI goes down, you're early. If it stays up, you're very early. This is architecturally correct but almost nobody does it — because it makes estimates look padded, and management eventually recalibrates expectations upward until the buffer disappears. You've solved nothing structurally, just temporarily.

**Option 2 — Build multi-model redundancy into the workflow.** If one AI goes down, a fallback model — Gemini, GPT-5, a local Llama variant — picks up immediately. The throughput gap shrinks dramatically when the fallback is another AI rather than a human alone. This is achievable today and is the most practical answer for teams that cannot afford conservative scoping. However, Option 2 carries a vulnerability that is easy to miss: it is subject to **Brook's Law**. Fred Brooks observed in *The Mythical Man-Month* (1975) that adding manpower to a late software project makes it later — because new participants require onboarding time, ramp-up, and context transfer that consumes more capacity than they contribute in the short term. An unplanned fallback AI faces the exact same problem. It has no context. It has not seen the conversation history, the architectural decisions, the intermediate reasoning, or the implicit constraints the primary AI accumulated across the session. Re-establishing that context takes time — time the team does not have mid-crisis. The fallback AI is not a drop-in replacement. It is a new team member arriving at the worst possible moment, and Brook's Law applies regardless of whether that new member is human or machine.

**Option 3 — Modular milestones at AI-independent checkpoints.** Structure every project so that each meaningful increment is independently completable and shippable at human velocity. The AI makes each increment faster, but no increment *requires* the AI to exist. If the AI disappears, you ship what is done. The remaining work moves to the next release.

Option 3 is the right answer — and the reasoning is worth unpacking.

---

### Why Option 3 Distributes Risk Instead of Concentrating It

Options 1 and 2 both carry hidden failure modes. Option 1 trades throughput risk for scope credibility risk. Option 2 trades single-vendor dependency for multi-vendor coordination complexity. Option 3 does something different: it changes the **shape** of the risk entirely.

When a project is built as one long AI-assisted arc toward a single deadline, all risk concentrates at the end. An outage at 90% completion is maximally catastrophic — you are closest to done and furthest from any shippable state. The team has nothing to show and everything to explain.

When a project is built as a sequence of independently shippable modules, risk is distributed across the timeline. An outage at any point means you have something real to demonstrate. The question shifts from "will we finish?" to "how much will we finish?" — which is a fundamentally less terrifying question to answer to a stakeholder.

That psychological shift matters more than people acknowledge. A team that can say "five of seven modules are complete and working" at deadline is in a completely different conversation than a team with a 90%-complete monolith that does not run yet. The first team has leverage. The second team has an apology.

---

### Why Option 3 Is Just Good Engineering — With Higher Stakes

This is not a new idea. Modular, incremental delivery is what good engineers have always done: ship working increments, commit frequently, never let the uncommitted work exceed what you could reconstruct from memory if the power went out.

What AI changes is that the **cost of ignoring this discipline is now much higher**.

When humans wrote everything, a monolithic three-hour session was recoverable. The engineer who wrote it held the full mental model. When an AI writes 800 lines across a three-hour session that the human was loosely supervising, no human holds that model in full. An outage does not just cut throughput. It reveals that the understanding was shallower than anyone admitted.

Option 3 forces understanding to be built incrementally as a side effect of shipping incrementally. Each module that gets committed and reviewed is a module that at least one human genuinely understands. The AI outage hits a team in that state differently — not "we are stranded" but "we are paused on the next module, everything before it is solid."

---

### How This Refines the LLM Dependency Test

This analysis sharpens what the LLM Dependency Test is actually measuring — and suggests a natural extension.

The test should evaluate not just whether the candidate can continue after the cutoff, but **how much of their work is in a shippable state at the moment the AI goes down**.

A candidate who has been committing working modules incrementally throughout the AI-assisted phase walks into the cutoff with a safety net. Something real exists. The remaining work is bounded and visible.

A candidate who has been building toward a big-bang completion has nothing shippable and faces the throughput problem and the understanding problem simultaneously.

The behavior before the cutoff is as revealing as the behavior after it. A candidate who naturally structures work into independently deployable increments — without being asked, without knowing the cutoff is coming — has architecture instincts that survive an outage. A candidate who builds monolithically toward a single finish line does not.

That is the engineer worth hiring. Not because they are immune to the outage. But because when it happens, they have already protected the project.

---

*Updated March 22, 2026 — with discussion of the throughput problem and the case for modular milestone architecture.*

---

**Discussion prompts:**

- Have you experienced an AI outage mid-project? What happened?
- Would you pass the LLM Dependency Test today?
- Should this become a standard part of engineering interviews?
- Does your team plan projects assuming AI availability? What would Option 3 look like in your workflow?
