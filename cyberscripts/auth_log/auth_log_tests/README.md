# Auth Log Failed Authentication Scraper - Test Suite

## Overview

105 test cases across 7 categories testing a comprehensive SSH authentication failure parser. This parser tracks **BOTH** `Failed password` and `Failed publickey` attempts as security events.

## Security Rationale

A comprehensive security monitoring tool must track ALL failed authentication attempts:

| Attack Type | Auth Method | Threat Scenario |
|-------------|-------------|-----------------|
| Credential Stuffing | Password | Leaked credential databases |
| SSH Brute Force | Password | Dictionary attacks |
| Key Enumeration | Publickey | Testing stolen/leaked private keys |
| Lateral Movement | Publickey | Keys harvested from compromised hosts |
| Compromised Key Testing | Publickey | Checking if revoked keys still work |

Ignoring `Failed publickey` would miss an entire class of attacks.

## Real-World Output Fields

Instead of academic metrics like "hourly distribution", this exercise tracks what incident responders actually need:

| Field | Why It Matters |
|-------|----------------|
| `first_failure` | When did this attack start? |
| `last_failure` | Is it still happening? When was the last attempt? |
| `potential_brute_force` | Which IPs need immediate blocking? |

## Regex Pattern

```python
r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port'
```

## Test Categories

### Category 1: Basic Parsing (15 tests)
- Single password/publickey failures
- Mixed auth types from same IP
- Valid vs invalid user patterns
- IP and user sorting requirements

### Category 2: Edge Cases (15 tests)
- Empty files
- Only successful logins (no failures)
- Key enumeration attacks (publickey-only)
- Password brute force (password-only)
- Malformed lines, blank lines

### Category 3: IP Address Handling (15 tests)
- IPv4 public and private ranges
- IPv6 full, compressed, link-local
- Mixed IPv4/IPv6
- Edge cases (0.0.0.0, 255.255.255.255, ::1)

### Category 4: Brute Force Detection (15 tests)
- Threshold boundary (4 vs 5 failures)
- Multiple brute force IPs
- IPv6 brute force
- Large scale attacks (100+ failures)

### Category 5: Timeline Analysis (15 tests)
- First and last failure timestamps
- Single failure (first == last)
- Burst attacks (seconds apart)
- Extended attacks (hours apart)
- All-day attacks (00:00 to 23:59)

### Category 6: Top Offender Logic (15 tests)
- Clear winners (single item in list)
- Ties return all tied items (sorted)
- Case sensitivity
- Special characters in usernames

### Category 7: Username Edge Cases (15 tests)
- Numeric, underscore, hyphen, dot usernames
- Service accounts (www-data, nobody)
- Email-like usernames (user@domain)
- Similar usernames (admin, admin1, administrator)

## Expected Output Format

```python
{
    "total_failed": int,           # Count of ALL failed auth attempts
    "unique_ips": list[str],       # Sorted unique source IPs
    "unique_users": list[str],     # Sorted unique usernames
    "attempts_by_ip": dict,        # {ip: count}
    "attempts_by_user": dict,      # {username: count}
    "top_offender_ips": list[str], # All IPs tied for most failures (sorted)
    "top_targeted_users": list[str], # All users tied for most targeted (sorted)
    "first_failure": str | None,   # "Jan 5 14:22:01" or None
    "last_failure": str | None,    # "Jan 5 18:45:30" or None
    "potential_brute_force": list[str], # IPs with >= 5 failures (sorted)
}
```

## Log Formats Matched

### Password Failures (COUNTED)
```
Jan  5 14:22:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan  5 14:22:02 server sshd[12346]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
```

### Publickey Failures (COUNTED)
```
Jan  5 14:22:03 server sshd[12347]: Failed publickey for root from 192.168.1.100 port 22 ssh2: RSA SHA256:abc123
Jan  5 14:22:04 server sshd[12348]: Failed publickey for invalid user git from 10.0.0.1 port 22 ssh2: ED25519 SHA256:def456
```

### Noise Lines (IGNORED)
- `Accepted password for ...`
- `Accepted publickey for ...`
- `Connection closed by ...`
- `pam_unix(sshd:session): session opened/closed ...`
- `CRON[...]: pam_unix(cron:session) ...`

## Timestamp Format

The timestamp in auth.log follows this format:
```
Mon DD HH:MM:SS
```

Note: Single-digit days have a leading space:
- `Jan  5 14:22:01` (two spaces before 5)
- `Jan 15 14:22:01` (one space before 15)

Your `first_failure` and `last_failure` should preserve this exact format.

## Usage

```python
import json

# Load expected results
with open("expected_results.json") as f:
    expected = json.load(f)

# Test your implementation
for test_name, expected_result in expected.items():
    category = test_name.split("_")[1]
    filepath = f"category{category}_*//{test_name}.log"
    result = parse_auth_log(filepath)
    assert result == expected_result, f"Failed: {test_name}"
```
