---
title: "Can You Build a Logger That Doesn't Spam? (LeetCode 359)"
published: false
description: "A deceptively simple problem that trips up engineers at Google, Amazon, and Meta. 20 test cases. One hash map. Infinite ways to get the boundary wrong."
tags: python, leetcode, interviewing, security
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/logger-rate-limiter-cover.png
---

# Can You Build a Logger That Doesn't Spam?

**Time:** 15-25 minutes  
**Difficulty:** Easy (but the boundary condition will haunt you)  
**Companies:** Google, Amazon, Meta, Uber, Bloomberg  

---

## The Setup

You're on-call at 3 AM. Your pager is exploding.

Not because production is down—but because your logging system is flooding Slack with the **same error message** 47,000 times per second.

```
[ERROR] Database connection failed
[ERROR] Database connection failed
[ERROR] Database connection failed
[ERROR] Database connection failed
... (47,000 more times)
```

Your AWS CloudWatch bill just hit $50,000. Your Slack channel is unusable. Your SRE team is mass-quitting.

**All because someone forgot to rate-limit the logger.**

---

## Why This Problem Exists

Every major tech company has learned this lesson the hard way:

### Twitter (2013)
A single trending topic generated 500,000 identical log entries per minute. Their Splunk cluster crashed, and they lost visibility into production for 2 hours during a major outage.

### Uber (2017)
A misconfigured service logged every GPS ping failure. During a network hiccup, they generated **4TB of logs in 20 minutes**. Cost: ~$200,000 in storage and analysis fees.

### Your Future Employer
They will ask you this question. Not because it's hard—but because getting the boundary condition wrong reveals whether you actually *think* about edge cases or just code and pray.

---

## The Challenge

Design a logger system that receives a stream of messages along with their timestamps. Each unique message should only be printed **at most every 10 seconds**.

```python
class Logger:

    def __init__(self):
        """
        Initialize your data structure here.
        """
        pass

    def shouldPrintMessage(self, timestamp: int, message: str) -> bool:
        """
        Returns true if the message should be printed in the given 
        timestamp, otherwise returns false.
        """
        pass
```

### The Rules

1. A message printed at timestamp `t` prevents identical messages until timestamp `t + 10`
2. All messages arrive in **chronological order** (timestamps never decrease)
3. Multiple messages can arrive at the same timestamp
4. Return `True` if the message should print, `False` if suppressed

### Example

```python
logger = Logger()
logger.shouldPrintMessage(1, "foo")   # True  - first time, print it
logger.shouldPrintMessage(2, "bar")   # True  - different message
logger.shouldPrintMessage(3, "foo")   # False - 3 < 11, suppress
logger.shouldPrintMessage(8, "bar")   # False - 8 < 12, suppress  
logger.shouldPrintMessage(10, "foo")  # False - 10 < 11, suppress
logger.shouldPrintMessage(11, "foo")  # True  - 11 >= 11, print it!
```

### Constraints

- `0 <= timestamp <= 10^9`
- `1 <= message.length <= 30`
- At most `10^4` calls to `shouldPrintMessage`

---

## Why This Is Harder Than It Looks

### Edge Case #1: The Boundary

Quick—should this print?

```python
logger.shouldPrintMessage(1, "foo")   # True (obviously)
logger.shouldPrintMessage(11, "foo")  # ???
```

The answer is `True`. But here's where people mess up:

- ❌ `timestamp - last_time > 10` → Wrong! This makes `11 - 1 = 10` return `False`
- ✅ `timestamp - last_time >= 10` → Correct! Or store `next_allowed = last_time + 10`

**One character. One bug. One failed interview.**

### Edge Case #2: The Window Reset

```python
logger.shouldPrintMessage(0, "foo")   # True, next allowed = 10
logger.shouldPrintMessage(10, "foo")  # True, next allowed = 20
logger.shouldPrintMessage(15, "foo")  # ???
```

Answer: `False`. The window resets when you *print*, not when you *try*.

After printing at `t=10`, the next allowed time is `t=20`. So `t=15` is suppressed.

### Edge Case #3: Same Timestamp, Different Messages

```python
logger.shouldPrintMessage(5, "foo")  # True
logger.shouldPrintMessage(5, "bar")  # ???
logger.shouldPrintMessage(5, "foo")  # ???
```

Answers: `True`, `False`.

Different messages are independent. But duplicate messages at the same timestamp? The second one is suppressed—even though zero seconds have passed.

---

## The Testing Gauntlet

Your implementation faces **110 test cases**:

| Category | Tests | What It Checks |
|----------|-------|----------------|
| LeetCode Examples | 1-2 | The exact example from the problem |
| Basic Functionality | 3-15 | First message, duplicates, independence, window reset |
| Boundary Conditions | 16-30 | Exactly t+10, t+9, t+11, sequential, periodic |
| Same Timestamp | 31-40 | Multiple messages at same time, duplicates |
| Large Timestamps | 41-50 | Values up to 10^9, crossing boundaries |
| Message Variations | 51-65 | 1-char, 30-char, case, whitespace, substrings |
| Interleaved Messages | 66-80 | Multiple messages with different windows |
| Rolling Windows | 81-95 | Window reset chains, near-boundary sequences |
| Many Messages | 96-105 | 100+ unique messages, tracking under load |
| Stress Tests | 106-110 | 10,000 calls (constraint limit) |

---

## Common Mistakes

### ❌ Mistake #1: Wrong Comparison Operator

```python
# WRONG
if timestamp - self.last[message] > 10:
    return True

# RIGHT  
if timestamp - self.last[message] >= 10:
    return True
```

### ❌ Mistake #2: Storing Last Time Instead of Next Allowed

```python
# Harder to reason about
self.last[message] = timestamp
# Then later: if timestamp - self.last[message] >= 10

# Easier to reason about
self.next_allowed[message] = timestamp + 10
# Then later: if timestamp >= self.next_allowed[message]
```

### ❌ Mistake #3: Forgetting to Update on Print

```python
# WRONG - never updates the timestamp!
def shouldPrintMessage(self, timestamp, message):
    if message not in self.times:
        return True  # Forgot to store!
    if timestamp >= self.times[message] + 10:
        return True  # Forgot to update!
    return False

# RIGHT
def shouldPrintMessage(self, timestamp, message):
    if message not in self.times or timestamp >= self.times[message] + 10:
        self.times[message] = timestamp  # Always update when printing
        return True
    return False
```

### ❌ Mistake #4: Using a List Instead of a Dict

```python
# O(n) lookup - will TLE on stress test
self.messages = []  # [(timestamp, message), ...]

# O(1) lookup - correct approach
self.times = {}  # {message: last_timestamp}
```

---

## Take the Challenge

### Get the Code

```bash
# Download the challenge file
curl -O https://raw.githubusercontent.com/YOUR_REPO/logger_rate_limiter_110_tests.py

# Run it
python3 logger_rate_limiter_110_tests.py
```

### What You'll See

```
╔══════════════════════════════════════════════════════════╗
║                 359. Logger Rate Limiter                 ║
║                      110 Test Cases                      ║
╚══════════════════════════════════════════════════════════╝

❌ FAIL - Test 1: LeetCode example sequence
   Expected: [True, True, False, False, False, True]
   Got:      [None, None, None, None, None, None]
...

============================================================
SUMMARY
Tests Passed: 0/110
Tests Failed: 110/110

Keep working!
Hints:
  1. Use a dict to store message -> next_allowed_timestamp
  2. If message not in dict OR timestamp >= next_allowed: print it
  3. When printing, set next_allowed = timestamp + 10
```

---

## What You'll Learn

By completing this challenge, you'll master:

- ✅ **Hash map design patterns** for O(1) lookup
- ✅ **Boundary condition handling** (the >= vs > trap)
- ✅ **State management** in class-based solutions
- ✅ **Rate limiting fundamentals** used in production systems
- ✅ **Window reset logic** that appears in token buckets and leaky buckets

---

## The Real-World Connection

This "easy" LeetCode problem is the foundation of:

| System | Rate Limiting Use |
|--------|-------------------|
| **fail2ban** | Block IPs after N failed SSH attempts in T seconds |
| **AWS CloudWatch** | Deduplicate identical log entries |
| **Stripe API** | 100 requests per second per API key |
| **Discord** | 5 messages per 5 seconds per channel |
| **Your SIEM** | Aggregate duplicate security alerts |

Get this wrong in production, and you'll either:
1. **Miss critical alerts** (rate limit too aggressive)
2. **Drown in noise** (rate limit too permissive)
3. **Burn money** (no rate limit at all)

---

## Ready?

The code is waiting. The tests are watching. The boundary condition is lurking.

**Can you pass all 110 tests?**

```python
class Logger:

    def __init__(self):
        # Your code here
        pass

    def shouldPrintMessage(self, timestamp: int, message: str) -> bool:
        # Your code here
        pass
```

Drop a comment with your solution's time and space complexity when you nail it. 🎯

---

## Spoiler-Free Hints

If you're stuck, reveal these one at a time:

<details>
<summary>Hint 1: Data Structure</summary>

You need O(1) lookup by message. What data structure gives you that?

</details>

<details>
<summary>Hint 2: What to Store</summary>

For each message, you only need to know ONE thing: when can it print again?

</details>

<details>
<summary>Hint 3: The Algorithm</summary>

```
if message is new OR current_time >= next_allowed_time:
    update next_allowed_time
    return True
else:
    return False
```

</details>

<details>
<summary>Hint 4: The Formula</summary>

`next_allowed_time = current_timestamp + 10`

</details>

---

*Found this helpful? Follow me for more interview prep challenges that actually teach you something.*

*Have a war story about logging disasters? Drop it in the comments—I collect them.*
