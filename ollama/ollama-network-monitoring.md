# Monitoring Ollama Network Activity on Linux

A practical guide for verifying that Ollama is not making unexpected network connections.
Written for security-conscious users running Ollama locally on Linux.

---

## 1. Verify Ollama Only Listens on Localhost

Before running any model, confirm the server is only bound to `127.0.0.1` and not
exposed externally.

```bash
# Check what address Ollama is listening on
ss -tunp | grep ollama
```

**Expected output:**
```
tcp  LISTEN  0  128  127.0.0.1:11434  0.0.0.0:*  users:(("ollama",pid=XXXX,...))
```

**Red flag:** If you see `0.0.0.0:11434` or `:::11434`, Ollama is exposed to your
network. Stop the service and investigate.

---

## 2. Watch Live Network Traffic with tcpdump

Run this in a separate terminal **before** starting Ollama or pulling a model.
This captures any traffic leaving your machine that is not loopback.

```bash
# Monitor all non-localhost traffic
sudo tcpdump -i any -n 'not host 127.0.0.1 and not host ::1'
```

Then in another terminal, start Ollama and run a prompt:

```bash
ollama serve &
ollama run qwen2.5-coder:14b "hello"
```

**Expected output from tcpdump:** Nothing during inference. You may see DNS/TLS
traffic during the initial model *download* (connecting to Ollama's registry), but
**zero outbound traffic** once the model is loaded and you are prompting it.

**Red flag:** Any outbound connection during inference to a non-local address.

---

## 3. Monitor Syscalls with strace

Attach `strace` to the running Ollama process and filter for network-related syscalls.

```bash
# Find the Ollama PID
pgrep -a ollama

# Attach strace and filter for connect/socket/sendto syscalls
sudo strace -p $(pgrep ollama) -e trace=network 2>&1 | grep -v "127.0.0.1\|::1\|EAGAIN"
```

**Expected output:** Only loopback connections (`127.0.0.1`) or empty output during
inference.

**Red flag:** Any `connect()` call to an external IP or hostname during inference.

---

## 4. Run Ollama in a Network Namespace (Strongest Isolation)

This completely removes internet access from the Ollama process. If Ollama requires
network access to function, it will fail — which itself is a red flag.

```bash
# Create an isolated network namespace with only loopback
sudo unshare --net -- sh -c '
  ip link set lo up
  ollama serve
'
```

Then in a separate terminal, test inference as normal:

```bash
ollama run qwen2.5-coder:14b "explain buffer overflow"
```

**Expected result:** Inference works normally. The model is already downloaded and
does not need internet access to run.

**Red flag:** Ollama refuses to start or errors out specifically due to network
unavailability during inference (not during model download).

---

## 5. Audit Open Files and Connections with lsof

```bash
# Show all files and connections Ollama currently has open
sudo lsof -p $(pgrep ollama)

# Filter to only network connections
sudo lsof -p $(pgrep ollama) -i
```

**Expected output:** Only `127.0.0.1:11434` (LISTEN) and connections from your
local client.

**Red flag:** Any established connection to an external IP address.

---

## 6. Use nethogs for Real-Time Per-Process Bandwidth

`nethogs` shows live bandwidth usage broken down by process — the most human-readable
option.

```bash
# Install if not present
sudo apt install nethogs   # Debian/Ubuntu
sudo pacman -S nethogs     # Arch

# Run it
sudo nethogs
```

Start a prompt in Ollama and watch the `nethogs` output. Ollama should show **0.000
KB/s** sent and received during inference.

**Red flag:** Any non-zero outbound bandwidth from the `ollama` process during
inference.

---

## 7. Verify Model File Integrity

The model weights downloaded from Ollama's registry should match what is published
on Hugging Face. Cross-check the SHA256 hash of the downloaded GGUF file.

```bash
# Find where Ollama stores model blobs
ls ~/.ollama/models/blobs/

# Hash a specific blob
sha256sum ~/.ollama/models/blobs/sha256-<hash>
```

Then compare against the corresponding GGUF file hash on the official Hugging Face
model card (e.g. `https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF`).

---

## 8. Verify the Ollama Binary Checksum

Confirm the installed Ollama binary matches the official release checksum published
on GitHub.

```bash
# Get the SHA256 of your installed binary
sha256sum $(which ollama)

# Compare against the official release checksums at:
# https://github.com/ollama/ollama/releases
```

Alternatively, build Ollama from source yourself to eliminate binary trust entirely:

```bash
git clone https://github.com/ollama/ollama.git
cd ollama
go build .
```

---

## 9. Ongoing Monitoring with auditd

For persistent, long-term monitoring of all network syscalls made by Ollama, use
the Linux Audit framework.

```bash
# Install auditd
sudo apt install auditd

# Add a rule to log all network connections by the ollama user/process
sudo auditctl -a always,exit -F arch=b64 -S connect -k ollama_network

# Watch the audit log in real time
sudo ausearch -k ollama_network -f --start recent | tail -f
```

Remove the rule when done:

```bash
sudo auditctl -d always,exit -F arch=b64 -S connect -k ollama_network
```

---

## Quick Reference

| Tool | Purpose | Install |
|------|---------|---------|
| `ss` | Check listening ports | Built-in |
| `tcpdump` | Capture live traffic | `sudo apt install tcpdump` |
| `strace` | Trace syscalls | `sudo apt install strace` |
| `lsof` | List open files/connections | Built-in |
| `nethogs` | Per-process bandwidth | `sudo apt install nethogs` |
| `unshare` | Network namespace isolation | Built-in |
| `auditd` | Persistent syscall logging | `sudo apt install auditd` |

---

## What is Normal vs a Red Flag

| Observation | Normal | Red Flag |
|---|---|---|
| Outbound traffic during model download | ✅ | |
| Outbound traffic during inference | | ❌ |
| Listening on `127.0.0.1:11434` | ✅ | |
| Listening on `0.0.0.0:11434` | | ❌ |
| Works in network namespace | ✅ | |
| Fails in network namespace | | ❌ |
| Model SHA256 matches Hugging Face | ✅ | |
| Model SHA256 mismatch | | ❌ |

---

*Generated for personal security verification of local Ollama deployments on Linux.*
