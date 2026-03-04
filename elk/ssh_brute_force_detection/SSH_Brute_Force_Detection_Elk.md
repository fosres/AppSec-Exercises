# Build a Real SIEM From Scratch on Debian 12: ELK Stack + SSH Brute Force Detection

**Tags:** `security`, `elasticsearch`, `devops`, `linux`

---

> 💡 **Before you dive in** — if you find this useful, please ⭐ star my open source project
> [**SecEng-Exercises**](https://github.com/fosres/SecEng-Exercises) on GitHub. It's a growing
> collection of security engineering exercises designed to help engineers write more secure code
> and prepare for Security Engineering roles.
>
> Also — I'd love to know **why you read security engineering blog posts**.
> [**Take my 30-second poll here**](https://strawpoll.com/wby5QoKAkyA) — results are public!

---

## A Horror Story First

It's 2:47 AM. A sysadmin wakes up to his phone buzzing — a customer is reporting their data
is gone. He logs into the server. The home directories are wiped. The database is dropped.
A ransom note sits in `/root/README.txt`.

He checks the logs the next morning. The attacker had been knocking since 11 PM — thousands
of failed SSH login attempts against the root account, cycling through a credential list.
At 1:13 AM they got lucky. A junior developer had set their password to `Summer2024!`. The
attacker was in within seconds. From there: `sudo su`, wipe, ransom, done.

The entire attack took 94 minutes from first failed login to complete data destruction.

The sysadmin had no SIEM. No detection rule. No alert. He had logs — but nobody watching them.

This is not hypothetical. Shodan indexes millions of exposed SSH servers daily. Automated
botnets run credential stuffing attacks around the clock. A server exposed to the internet
without SSH brute force monitoring is not a question of *if* it gets attacked — it's *when*,
and whether anyone notices before it's too late.

This guide builds the monitoring layer that would have saved that sysadmin's night.

---

## What You'll Build

By the end of this guide you'll have a fully operational **SIEM** (Security Information and Event
Management system) running on your local Debian 12 machine that:

- Ingests your system's `auth.log` in real time
- Parses structured fields (hostname, program, src_ip, failed_user) from raw log lines
- Detects SSH brute force attacks automatically
- Fires alerts in Kibana's Security UI when an attacker exceeds 5 failed logins in 5 minutes

Here's the architecture:

```
auth.log → Logstash (parse) → Elasticsearch (store) → Kibana (detect + alert)
```

Each component runs in its own Docker container. Think of it as a mini version of what
engineering-driven companies like GitLab, Stripe, and Coinbase run in production.

---

## The ELK Component Mental Model

Before touching a single config file, burn this table into your memory:

| Component     | Role                  | Real World Analogy                        |
|---------------|-----------------------|-------------------------------------------|
| Elasticsearch | Stores + indexes data | PostgreSQL — your database                |
| Logstash      | Parses + loads data   | ETL pipeline — transforms raw logs        |
| Kibana        | Queries + visualizes  | pgAdmin + cron jobs — browse data AND run scheduled detection queries |

Kibana is not just a viewer. Its detection rule engine continuously queries Elasticsearch and
fires alerts when attack patterns are detected. That's what makes it a SIEM tool.

---

## Prerequisites

- Debian 12 (Bookworm)
- 8GB+ RAM recommended (Elasticsearch needs 2GB, Logstash 1GB)
- `sudo` access
- VPN **disabled** for localhost access (Mullvad and similar VPNs block localhost traffic)

---

## Part 1: Install Docker Engine

> ⚠️ **Important:** Do NOT install Docker Desktop on Linux. It requires KVM virtualization and
> creates credential helper conflicts. Install Docker Engine directly.

If you have Docker Desktop installed, remove it first:

```bash
sudo apt remove docker-desktop
rm -rf ~/.docker
```

Then install Docker Engine:

```bash
# Add Docker's official GPG key
sudo apt update
sudo apt install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the Docker apt repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
```

Start and enable the Docker daemon:

```bash
sudo systemctl start docker
sudo systemctl enable docker
```

Add your user to the docker group so you don't need sudo for every command:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Common Pitfall: Credential Helper Conflict

If you see this error:

```
docker-credential-desktop: executable file not found in $PATH
```

You have a leftover Docker Desktop config. Fix it:

```bash
cat ~/.docker/config.json
```

If it contains `"credsStore": "desktop"`, replace the file contents with just `{}`:

```bash
echo '{}' > ~/.docker/config.json
```

---

## Part 2: Create the Project Directory

```bash
mkdir -p ~/elk
cd ~/elk
```

---

## Part 3: Create the Docker Compose File

Create `docker-compose.yml` with X-Pack security enabled from the start:

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.authc.api_key.enabled=true
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
      - ELASTIC_PASSWORD=SecureELKPass2026!
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: kibana
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=SecureELKPass2026!
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=a7a6311933d3503b89bc2dbc36572c33a6c10925682e591bffcab6911c06786d

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    container_name: logstash
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
      - /var/log:/var/log/host:ro
    depends_on:
      - elasticsearch
    environment:
      - LS_JAVA_OPTS=-Xms1g -Xmx1g
      - xpack.monitoring.elasticsearch.hosts=http://elasticsearch:9200
      - xpack.monitoring.elasticsearch.username=elastic
      - xpack.monitoring.elasticsearch.password=SecureELKPass2026!

volumes:
  esdata:
```

### Why Three Separate Containers?

Each component has a different job, different resource requirements, and can fail or scale
independently. If Kibana crashes, Elasticsearch keeps storing logs and Logstash keeps ingesting.
This is the microservices pattern used in production at every major tech company.

### About the X-Pack Encryption Key

The `XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY` is required for Kibana's alerting system to
encrypt saved rule configurations. Generate a cryptographically secure one using Python's
`secrets` module (which uses your OS CSPRNG — `/dev/urandom` on Linux):

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Replace the key in the compose file with your generated value. Never use a hardcoded key in
production — store it in a secrets manager like HashiCorp Vault.

### About Logstash X-Pack Monitoring Variables

The three `xpack.monitoring.*` environment variables on Logstash are separate from the pipeline
credentials in `logstash.conf`. They authenticate Logstash's internal license checker component
to Elasticsearch. Without them you'll see persistent `401` errors in `docker logs logstash` even
after adding credentials to your pipeline config.

---

## Part 4: Create the Logstash Pipeline Config

Create `logstash.conf` in the same directory:

```ruby
input {
  file {
    path => "/var/log/host/auth.log"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb_auth"
    type => "auth"
  }
}

filter {
  if [type] == "auth" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:hostname} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}"
      }
    }
    date {
      match => ["timestamp", "ISO8601"]
      target => "@timestamp"
    }
    if [log_message] =~ /Failed password/ {
      grok {
        match => {
          "log_message" => "Failed password for (invalid user )?%{USERNAME:failed_user} from %{IP:src_ip} port %{NUMBER:port}"
        }
        add_tag => ["failed_login"]
      }
    }
    if [log_message] =~ /Accepted password/ {
      grok {
        match => {
          "log_message" => "Accepted password for %{USERNAME:success_user} from %{IP:src_ip} port %{NUMBER:port}"
        }
        add_tag => ["successful_login"]
      }
    }
    if [log_message] =~ /sudo/ {
      mutate {
        add_tag => ["sudo_command"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    user => "elastic"
    password => "SecureELKPass2026!"
    index => "auth-logs-%{+YYYY.MM.dd}"
  }
}
```

### Why `TIMESTAMP_ISO8601` Not `SYSLOGTIMESTAMP`?

Debian 12 ships rsyslog configured to write ISO8601 timestamps:

```
2026-03-01T10:45:26.863684-08:00 fosres sudo: ...
```

Older distros and tutorials use the traditional syslog format:

```
Mar  1 10:45:26 fosres sudo: ...
```

If you use `SYSLOGTIMESTAMP` on Debian 12, grok fails immediately on the first token and tags
every document with `_grokparsefailure` — meaning no structured fields get extracted. Always
grab a real sample line from your actual `auth.log` and verify your pattern matches before
deploying.

### About `sincedb_path`

The sincedb file tracks the byte offset of the last line Logstash read — like a bookmark.
Setting it to `/dev/null` (common in tutorials) discards the bookmark on every restart,
causing Logstash to re-ingest the entire file from the beginning and creating duplicate
documents. The production-ready path `/usr/share/logstash/data/sincedb_auth` persists across
restarts inside the container's data directory.

---

## Part 5: Install rsyslog

Debian 12 uses `systemd-journald` by default and does not write a traditional `auth.log` file
unless rsyslog is installed:

```bash
sudo apt install rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

Verify `auth.log` was created:

```bash
ls -la /var/log/auth.log
```

Make it readable by Logstash inside the container:

```bash
sudo chmod o+r /var/log/auth.log
```

---

## Part 6: Start the Stack

```bash
cd ~/elk
docker compose up -d
```

This downloads ~2.1GB total (Elasticsearch ~650MB, Kibana ~750MB, Logstash ~750MB) on first run.
Images are stored in `/var/lib/docker/` and persist across reboots.

Wait 60 seconds for all three containers to fully initialize, then verify they're running:

```bash
docker ps
```

You should see three containers: `elasticsearch`, `kibana`, `logstash`.

---

## Part 7: Set Passwords for All Components

This is the critical step most tutorials skip. With X-Pack security enabled, every component
needs credentials.

### Step 1: Set the kibana_system Password

```bash
curl -u elastic:SecureELKPass2026! -X POST \
  'http://localhost:9200/_security/user/kibana_system/_password' \
  -H 'Content-Type: application/json' \
  -d '{"password": "SecureELKPass2026!"}'
```

Expected response: `{}`

### Step 2: Restart Kibana to Pick Up the New Password

```bash
docker restart kibana
```

### Step 3: Verify Logstash Connected Successfully

```bash
docker logs logstash 2>&1 | tail -5
```

You should see:

```
[INFO] Pipeline started {"pipeline.id"=>"main"}
[INFO] Pipelines running {:count=>2, ...}
```

If you see `401` errors, restart Logstash:

```bash
docker restart logstash
```

---

## Part 8: Log In to Kibana

Open your browser and navigate to `http://localhost:5601`

> ⚠️ If you use Mullvad VPN or similar, disable it first — these VPNs block localhost traffic.

Log in with:
- **Username:** `elastic`
- **Password:** `SecureELKPass2026!`

*[SCREENSHOT: Kibana login screen]*

---

## Part 9: Create a Kibana Data View

A Data View tells Kibana which Elasticsearch index pattern to query.

1. Click the hamburger menu (top left) → **Stack Management**
2. Under **Kibana** → click **Data Views**
3. Click **"Create data view"**
4. Fill in:
   - **Name:** `auth-logs`
   - **Index pattern:** `auth-logs-*`
   - **Timestamp field:** `@timestamp`
5. Click **Save data view to Kibana**

*[SCREENSHOT: Data View creation form]*

---

## Part 10: Verify Data in Kibana Discover

1. Hamburger menu → **Analytics → Discover**
2. Make sure `auth-logs` data view is selected (top left dropdown)
3. Set time range to **Today** (top right clock icon)

You should see your auth.log events appearing as structured documents with fields like
`hostname`, `program`, `log_message`, `tags`.

*[SCREENSHOT: Kibana Discover showing structured auth.log documents]*

### Test the Failed Login Filter

In the search bar type:

```
tags: failed_login
```

Hit Enter. This uses KQL (Kibana Query Language) to filter documents where the `tags` field
contains `failed_login` — exactly the events our detection rule will fire on.

*[SCREENSHOT: Kibana Discover showing 10 hits for tags: failed_login]*

### How to Read Hit Counts

The document count appears in the top left of the Discover view. Click **Field statistics** tab
to see a breakdown by field value — for example, clicking `src_ip` shows you every attacker IP
and how many events came from each one.

---

## Part 11: Generate Test SSH Brute Force Events

Since you may not have actual failed SSH logins, inject fake ones to test your detection rule:

```bash
for i in $(seq 1 10); do
  echo "$(date -Iseconds) $(hostname) sshd[9999$i]: Failed password for invalid user admin from 192.168.1.100 port 2222$i ssh2" | sudo tee -a /var/log/auth.log
done
```

Wait 15 seconds, then refresh Discover and search `tags: failed_login` — you should see your
injected failed login events all from `192.168.1.100`. If you ran the script multiple times
you'll see more than 10 hits — that's fine. What matters is the Field statistics view showing
`src_ip: 192.168.1.100` at 100% of events with 1 distinct value. One IP responsible for all
failed logins is the textbook brute force signature.

---

## Part 12: Build the SSH Brute Force Detection Rule

This is where Kibana becomes a SIEM rather than just a log viewer.

1. Hamburger menu → **Security → Rules → Detection rules (SIEM)**
2. Click **"Create new rule"**

*[SCREENSHOT: Detection rules (SIEM) landing page with "Create new rule" button]*

### Step 1: Define Rule — Select Rule Type

Select **"Threshold"** — this rule type aggregates query results and fires when a count
exceeds a threshold. Perfect for brute force detection.

*[SCREENSHOT: Rule type selection with Threshold highlighted]*

### Step 2: Configure the Query

- **Source:** Click **Data View** tab → select `auth-logs-*`
- **Custom query:** `tags: failed_login`
- **Group by:** `src_ip.keyword` (groups failed logins by attacker IP)
- **Threshold:** `>= 5`

Click **Continue**.

*[SCREENSHOT: Threshold rule configuration with all fields filled in]*

### Step 3: About Rule

- **Name:** `SSH Brute Force Detection`
- **Description:** `Alerts when a single IP address generates 5 or more failed SSH login attempts, indicating a brute force attack.`
- **Default severity:** `Medium`
- **Risk score:** `47`
- **Tags:** `brute-force`, `ssh`

Click **Continue**.

### Step 4: Schedule Rule

- **Runs every:** `5 minutes`
- **Additional look-back time:** `1 minute`

Click **Continue**.

### Step 5: Rule Actions

Select **Index** as the connector type. Click **Index** → **Create a connector**:

- **Connector name:** `SSH_Brute_Force_Alerts`
- **Index:** `security-alerts`

Click **Save**.

In the **Document to index** field, paste this JSON template:

```json
{
  "rule_name": "{{rule.name}}",
  "alert_time": "{{date}}",
  "severity": "{{rule.severity}}",
  "src_ip": "{{context.value}}",
  "message": "SSH brute force detected from {{context.value}}"
}
```

Click **"Create & enable rule"**.

---

## Part 13: Verify the Alert Fires

First inject a fresh batch of fake SSH events — the rule only looks back 5 minutes, so events
from earlier in your session will be outside its window:

```bash
for i in $(seq 41 50); do
  echo "$(date -Iseconds) $(hostname) sshd[9999$i]: Failed password for invalid user admin from 192.168.1.100 port 2222$i ssh2" | sudo tee -a /var/log/auth.log
done
```

Now wait 5 minutes for the rule to run, then navigate to **Security → Alerts** in the left sidebar.

You should see:

- **1 alert** with Medium severity
- **Rule name:** SSH Brute Force Detection
- **Risk Score:** 47

*[SCREENSHOT: Kibana Security Alerts page showing SSH Brute Force Detection alert]*

Congratulations — your SIEM just autonomously detected a brute force attack.

---

## Common Pitfalls

| Problem | Cause | Fix |
|---|---|---|
| `_grokparsefailure` tag on all documents | Wrong timestamp format in grok pattern | Use `TIMESTAMP_ISO8601` not `SYSLOGTIMESTAMP` on Debian 12 |
| `401` errors in Logstash logs | Missing xpack.monitoring env vars | Add all three `xpack.monitoring.*` vars to docker-compose.yml |
| Kibana login fails with kibana_system | Password not set after enabling X-Pack | Run the `_security/user/kibana_system/_password` curl command |
| "Detection engine permissions required" | X-Pack security not enabled | Set `xpack.security.enabled=true` in Elasticsearch environment |
| "Encryption key required" for alerting | Missing Kibana encryption key | Add `XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY` to Kibana environment |
| Kibana shows no fields in Discover | Data view created before grok fix | Refresh field mappings: Stack Management → Data Views → refresh icon |
| Logstash re-ingests entire file on restart | `sincedb_path => "/dev/null"` | Set a real path like `/usr/share/logstash/data/sincedb_auth` |
| localhost:5601 unreachable | VPN blocking localhost | Disable VPN (Mullvad and similar block localhost) |
| Backwards time range in Kibana | Time picker set incorrectly | Set to "Today" or "Last 24 hours" via the clock icon |
| `docker-credential-desktop` error | Leftover Docker Desktop config | Replace `~/.docker/config.json` with `{}` |

---

## What You Built

You now have a production-grade SIEM pipeline:

```
Debian auth.log
    ↓
rsyslog (writes structured ISO8601 logs)
    ↓
Logstash (grok parses → tags failed logins → writes to Elasticsearch)
    ↓
Elasticsearch (indexes documents with src_ip, failed_user, hostname fields)
    ↓
Kibana Discover (threat hunting with KQL queries)
    ↓
Kibana Security Detection Rule (fires alert when src_ip >= 5 failed logins / 5 min)
    ↓
Security Alerts UI (SOC analyst investigates)
```

This is the same architecture used at companies like GitLab, Stripe, and Anthropic — just
without the scale. Every concept you learned here maps directly to production Security
Engineering work.

---

## Next Steps

- Add detection rules for `sudo` privilege escalation events (`tags: sudo_command`)
- Ingest firewall logs and correlate with auth failures
- Explore Kibana's 1,153 prebuilt Elastic detection rules covering MITRE ATT&CK techniques
- Build the Python SSH correlation engine to understand the sliding window algorithm underlying
  threshold detection rules

---

> 🌟 If this post helped you, please star
> [**SecEng-Exercises**](https://github.com/fosres/SecEng-Exercises) — a collection of
> security engineering exercises for engineers who want to write more secure code and break
> into Security Engineering roles.
>
> 📊 And take 30 seconds to tell me
> [**why you read security engineering blog posts**](https://strawpoll.com/wby5QoKAkyA).
> I read every response and use the results to write better content.
