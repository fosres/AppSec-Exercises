# Detect Port Scans in Real Time With ELK Stack on Debian 12

**Tags:** `security`, `elasticsearch`, `linux`, `networking`

---

> 💡 **Before you dive in** — if you find this useful, please ⭐ star my open source project
> [**SecEng-Exercises**](https://github.com/fosres/SecEng-Exercises) on GitHub. It's a growing
> collection of security engineering exercises designed to help engineers write more secure code
> and break into Security Engineering roles.
>
> 📊 Also — I'd love to know **why you read security engineering blog posts**.
> [**Take my 30-second poll here**](https://strawpoll.com/wby5QoKAkyA) and check the live
> results. I use the data to write better content.

---

> **This is Part 2 of the ELK SIEM series.**
> Part 1 covered deploying ELK with X-Pack security and detecting SSH brute force attacks.
> This post assumes your ELK stack is already running. If not, start with Part 1 first.

---

## A Horror Story First

A penetration tester lands initial access on a corporate network via a phishing email. Before
doing anything noisy, he runs a quiet port scan — probing thousands of ports across dozens of
internal hosts, mapping the attack surface: open RDP ports, exposed databases, unpatched
services.

He takes his time. The entire reconnaissance phase lasts 20 minutes.

The security team notices nothing. No alert fires. No analyst investigates. The logs are
there — the firewall logged every blocked connection — but nobody built a rule to watch for
the pattern.

Three days later the attacker has domain admin. The port scan was the first domino.

Port scanning is not an attack in itself. It's reconnaissance — the attacker mapping your
network before they strike. Detecting it early gives you a critical window to respond before
the real attack begins. This guide builds that detection layer.

---

## What You'll Build

A Kibana detection rule that fires when a single IP address probes more than 15 distinct
destination ports within 60 seconds — the signature of an automated port scan.

The pipeline:

```
UFW firewall → rsyslog → /var/log/ufw.log → Logstash (parse) → Elasticsearch (store)
→ Kibana threshold rule (fires when src_ip hits 15+ distinct ports / 60 sec)
```

---

> 🔧 **Stuck at any point?** Jump to the [**Common Pitfalls**](#common-pitfalls) section
> at the bottom of this post before giving up — every error you're likely to hit is
> documented there with an exact fix.

## Prerequisites

- ELK stack running from Part 1 (Elasticsearch, Logstash, Kibana with X-Pack security)
- Debian 12
- `sudo` access

---

## Part 1: Install and Configure UFW

UFW (Uncomplicated Firewall) is the standard firewall manager on Debian/Ubuntu. It wraps
`iptables` and writes blocked connection attempts to syslog, which rsyslog routes to
`/var/log/ufw.log`.

```bash
sudo apt install ufw
sudo ufw enable
sudo ufw logging on
```

Verify UFW is active and logging:

```bash
sudo ufw status verbose
```

You should see `Status: active` and `Logging: on (low)`.

### What UFW Logs

Every time a connection is blocked by UFW, a line like this gets written to `/var/log/ufw.log`:

```
Mar 2 14:23:01 fosres kernel: [1234567.890] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=10.0.0.1 LEN=44 TOS=0x00 PREC=0x00 TTL=254 ID=54321 PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0
```

The key fields for port scan detection are:

| Field | Meaning |
|---|---|
| `SRC` | Attacker's source IP |
| `DST` | Target IP on your machine |
| `DPT` | Destination port being probed |
| `PROTO` | Protocol (TCP/UDP) |

A port scan is simply the same `SRC` IP hitting many different `DPT` values in rapid
succession.

### Make UFW Log Readable by Logstash

```bash
sudo chmod o+r /var/log/ufw.log
```

---

## Part 2: Update logstash.conf

Open your Logstash pipeline config:

```bash
nano ~/elk/logstash.conf
```

> ⚠️ **Debian 12 rsyslog timestamp warning:** On Debian 12, rsyslog writes UFW logs using
> ISO8601 format (`2026-03-02T15:06:22.881951-08:00`), **not** the traditional
> `SYSLOGTIMESTAMP` format (`Mar  2 15:06:22`) that older tutorials use. Using the wrong
> format causes `_grokparsefailure` on every UFW document — no fields will be extracted.
> The config below uses `TIMESTAMP_ISO8601` and `ISO8601` date matching, which is correct
> for Debian 12. Always verify your actual UFW log format first:
> ```bash
> tail -5 /var/log/ufw.log
> ```

Add a second `file` input block and a new filter section for UFW. Here is the complete
updated `logstash.conf`:

```ruby
input {
  file {
    path => "/var/log/host/auth.log"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb_auth"
    type => "auth"
  }
  file {
    path => "/var/log/host/ufw.log"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb_ufw"
    type => "ufw"
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

  if [type] == "ufw" {
    grok {
      match => {
        "message" => "%{TIMESTAMP_ISO8601:timestamp} %{HOSTNAME:hostname} kernel: \[%{NUMBER:uptime}\] \[UFW %{WORD:ufw_action}\] IN=%{DATA:in_iface} OUT=%{DATA:out_iface}.*SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*PROTO=%{WORD:protocol}(?:.*SPT=%{NUMBER:src_port} DPT=%{NUMBER:dst_port})?"
      }
      add_tag => ["ufw_event"]
    }
    date {
      match => ["timestamp", "ISO8601"]
      target => "@timestamp"
    }
    if [ufw_action] == "BLOCK" {
      mutate {
        add_tag => ["ufw_blocked"]
      }
    }
  }
}

output {
  if [type] == "auth" {
    elasticsearch {
      hosts => ["http://elasticsearch:9200"]
      user => "elastic"
      password => "SecureELKPass2026!"
      index => "auth-logs-%{+YYYY.MM.dd}"
    }
  }
  if [type] == "ufw" {
    elasticsearch {
      hosts => ["http://elasticsearch:9200"]
      user => "elastic"
      password => "SecureELKPass2026!"
      index => "ufw-logs-%{+YYYY.MM.dd}"
    }
  }
}
```

### Key Design Decisions

**Both `auth.log` and `ufw.log` use `TIMESTAMP_ISO8601` on Debian 12** — rsyslog on Debian
12 writes ISO8601 timestamps to all log files including UFW. Many tutorials and older guides
use `SYSLOGTIMESTAMP` for UFW — this will cause `_grokparsefailure` on every document on
Debian 12. Always run `tail -5 /var/log/ufw.log` to verify your actual timestamp format
before writing your grok pattern.

**SPT/DPT are optional in the grok pattern** — some UFW blocked packets (like IGMP multicast
traffic with `PROTO=2`) have no source or destination port fields. Making them optional with
`(?:.*SPT=... DPT=...)?` prevents `_grokparsefailure` on those packets while still correctly
parsing TCP/UDP port scan events.

**Separate indices for each log type** — `auth-logs-*` and `ufw-logs-*` stay separate.
This makes queries faster (smaller index to scan), retention policies easier to manage, and
detection rules cleaner.

**Two sincedb paths** — each file input gets its own bookmark file so they track positions
independently.

---

## Part 3: docker-compose.yml Reference

Your `docker-compose.yml` already mounts `/var/log` into the Logstash container at
`/var/log/host`. Since `ufw.log` lives in `/var/log/`, it's already accessible inside
the container at `/var/log/host/ufw.log`. No changes needed to the compose file.

Here is the complete `docker-compose.yml` for reference:

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

The critical line is the Logstash volume mount:

```yaml
- /var/log:/var/log/host:ro
```

This mounts your entire host `/var/log` directory into the container read-only at
`/var/log/host`. Both `auth.log` and `ufw.log` live in `/var/log/` on the host, so both
are accessible inside the container without any additional configuration.

---

## Part 4: Restart Logstash

```bash
cd ~/elk
docker compose restart logstash
```

Wait 15 seconds then verify both pipelines started:

```bash
docker logs logstash 2>&1 | tail -10
```

You should see:

```
[INFO] Pipeline started {"pipeline.id"=>"main"}
[INFO] Pipelines running {:count=>2, ...}
```

And confirm the new index was created:

```bash
curl -u elastic:SecureELKPass2026! 'http://localhost:9200/_cat/indices?v' | grep ufw
```

If the `ufw-logs-*` index doesn't appear yet, UFW hasn't logged any blocked connections.
Move to Part 6 to generate test events first.

> ⚠️ **Note:** You may see `Connection refused` errors at the top of the Logstash output.
> This is normal — Logstash started before Elasticsearch was fully ready. As long as you see
> `Restored connection to ES instance` and `Elasticsearch version determined` at the bottom,
> Logstash has recovered and is healthy.

### Wait for Kibana to Be Ready

Kibana takes 60-90 seconds to fully initialize after `docker compose up`. Before navigating
to `http://localhost:5601`, verify it's ready:

```bash
docker logs kibana 2>&1 | tail -5
```

Wait until you see:

```
Kibana is now available
```

Only then open your browser to `http://localhost:5601`. If you visit too early you'll see
"Kibana Server is not ready yet" — just wait and keep refreshing every 30 seconds.

If you still see "Kibana Server is not ready yet" after 2 minutes, the `kibana_system`
password likely needs to be reset. This happens whenever the `esdata` Docker volume is
recreated. Run:

```bash
curl -u elastic:SecureELKPass2026! -X POST \
  'http://localhost:9200/_security/user/kibana_system/_password' \
  -H 'Content-Type: application/json' \
  -d '{"password": "SecureELKPass2026!"}'
```

Then restart Kibana:

```bash
docker restart kibana
```

Wait 60-90 seconds and check again:

```bash
docker logs kibana 2>&1 | tail -5
```

You're ready when you see `Kibana is now available`.

---

## Part 5: Create a Kibana Data View for UFW Logs

Open your browser to `http://localhost:5601` and log in with:

- **Username:** `elastic`
- **Password:** `SecureELKPass2026!`

1. In Kibana, go to hamburger menu → **Stack Management → Data Views**
2. Click **"Create data view"**
3. Fill in:
   - **Name:** `ufw-logs`
   - **Index pattern:** `ufw-logs-*`
   - **Timestamp field:** `@timestamp`
4. Click **Save data view to Kibana**

*[SCREENSHOT: Data View creation for ufw-logs-*]*

---

## Part 6: Generate Test Port Scan Events

Since you may not have real port scan traffic, simulate one by appending fake UFW BLOCK
entries directly to the log file:

```bash
for port in 22 23 25 80 443 3306 5432 6379 8080 8443 27017 11211 6380 9200 5601 21 53; do
  echo "$(date -Iseconds) $(hostname) kernel: [123456.789] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.0.0.99 DST=192.168.1.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=$port WINDOW=1024 RES=0x00 SYN URGP=0" | sudo tee -a /var/log/ufw.log
done
```

This simulates a single attacker (`10.0.0.99`) probing 17 distinct destination ports —
exactly the pattern a port scanner like `nmap` produces.

Wait 15 seconds, then open Kibana → **Analytics → Discover**, select the `ufw-logs` data
view and search:

```
tags: ufw_blocked
```

> ⚠️ **Set the time range first** — in the upper right corner of Kibana, click the clock
> icon and set the time range from **last week to now** (e.g. "Last 7 days"). If the time
> range doesn't include when you injected the events, Kibana will return no results even
> though the data is there.

You should see 17 documents all from `src_ip: 10.0.0.99`.

*[SCREENSHOT: Kibana Discover showing ufw_blocked events with src_ip and dst_port fields]*

### Verify Field Statistics

Click **Field statistics** tab and expand `src_ip` — you should see `10.0.0.99` at 100% of
events with 1 distinct value.

For destination ports, expand `dst_port.keyword` (not `dst_port`) — you should see 17
distinct values in TOP VALUES. The plain `dst_port` field is a `text` type and only shows
Examples without statistics. The `.keyword` version is the aggregatable form Elasticsearch
creates automatically, and is what both Field statistics and detection rules use for counting.

17 distinct ports from a single `src_ip` is the port scan signature: one attacker, many
probed ports.

---

## Part 7: Build the Port Scan Detection Rule

Now build the Kibana SIEM detection rule that fires automatically when this pattern occurs.

1. Hamburger menu → **Security → Rules → Detection rules (SIEM)**
2. Click **"Create new rule"**
3. Select **"Threshold"** rule type
4. Click **Continue**

*[SCREENSHOT: Rule type selection with Threshold highlighted]*

### Step 1: Define Rule

- **Source:** Click **Data View** tab → select `ufw-logs-*`
- **Custom query:** `tags: ufw_blocked`
- **Group by:** `src_ip.keyword`
- **Threshold:** `>= 15`
- **Count:** select `dst_port.keyword` from the dropdown — this counts **distinct** destination
  ports per IP, not just total events
- **Unique values:** set to `15` — this is the minimum number of distinct destination ports
  that must be seen from a single IP before the alert fires

Click **Continue**.

*[SCREENSHOT: Threshold rule configured with ufw-logs data view and dst_port cardinality]*

### Step 2: About Rule

- **Name:** `Port Scan Detection`
- **Description:** `Alerts when a single IP address probes 15 or more distinct destination ports within the rule window, indicating automated port scanning activity.`
- **Default severity:** `Medium`
- **Risk score:** `47`
- **Tags:** `port-scan`, `reconnaissance`, `network`

Click **Continue**.

### Step 3: Schedule Rule

- **Runs every:** `5 minutes`
- **Additional look-back time:** `1 minute`

Click **Continue**.

### Step 4: Rule Actions

Select **Index** connector type → use your existing `SSH_Brute_Force_Alerts` connector or
create a new one called `Security_Alerts_Index` writing to index `security-alerts`.

**Document to index:**

```json
{
  "rule_name": "{{rule.name}}",
  "alert_time": "{{date}}",
  "severity": "{{rule.severity}}",
  "src_ip": "{{context.value}}",
  "message": "Port scan detected from {{context.value}} — probing multiple destination ports"
}
```

Click **"Create & enable rule"**.

---

## Part 8: Trigger and Verify the Alert

Inject a fresh batch of port scan events so they fall within the rule's 5-minute look-back
window:

```bash
for port in 22 23 25 80 443 3306 5432 6379 8080 8443 27017 11211 6380 9200 5601 21 53; do
  echo "$(date -Iseconds) $(hostname) kernel: [123456.789] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.0.0.99 DST=192.168.1.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=$port WINDOW=1024 RES=0x00 SYN URGP=0" | sudo tee -a /var/log/ufw.log
done
```

Wait 5 minutes, then navigate to **Security → Alerts**.

You should see a new **Port Scan Detection** alert with Medium severity and Risk Score 47.

*[SCREENSHOT: Security Alerts page showing both SSH Brute Force and Port Scan Detection alerts]*

---

## Common Pitfalls

| Problem | Cause | Fix |
|---|---|---|
| `_grokparsefailure` on UFW events | Wrong timestamp format in grok pattern | On Debian 12, use `TIMESTAMP_ISO8601` and `ISO8601` date match — run `tail -5 /var/log/ufw.log` to verify your format first |
| `ufw-logs-*` index not created | UFW has no blocked connections yet | Run the injection script in Part 6 |
| `/var/log/ufw.log` doesn't exist | UFW not installed or logging not enabled | Run `sudo ufw enable && sudo ufw logging on` |
| No `src_ip` or `dst_port` fields | Grok pattern didn't match log line | Check your UFW log format with `tail /var/log/ufw.log` and verify the pattern |
| `src_ip`, `dst_port`, `protocol` appear under "Unmapped fields" in Discover | Data view was created before grok-extracted fields existed in the index | Go to **Stack Management → Data Views → ufw-logs → Add field** and manually add `src_ip`, `dst_port`, `protocol` as keyword type. This is safer than deleting the data view in production environments where other team members may depend on it. |
| Alert never fires | Events outside 5-minute look-back window | Re-run injection script immediately before waiting 5 minutes |
| UFW log unreadable by Logstash | File permissions | Run `sudo chmod o+r /var/log/ufw.log` |

---

## What You've Built

Your SIEM now detects two attack patterns autonomously:

| Detection Rule | Trigger | Severity |
|---|---|---|
| SSH Brute Force Detection | 5+ failed logins from same IP / 5 min | Medium |
| Port Scan Detection | 15+ distinct ports from same IP / 5 min | Medium |

The port scan rule catches the **reconnaissance phase** — the earliest stage of an attack,
before exploitation begins. In the real world, catching a port scan and blocking the source
IP buys you time and may prevent the attack entirely.

---

## What's Next

**Part 3 of this series** covers SQL injection detection using nginx access logs — building
a custom query rule that fires when HTTP requests contain SQLi patterns like `UNION SELECT`,
`' OR '1'='1`, and `--`. Stay tuned.

---

> 🌟 If this post helped you, please star
> [**SecEng-Exercises**](https://github.com/fosres/SecEng-Exercises) — a collection of
> security engineering exercises for engineers who want to write more secure code and break
> into Security Engineering roles. Every star helps the project grow.
>
> 📊 And take 30 seconds to tell me
> [**why you read security engineering blog posts**](https://strawpoll.com/wby5QoKAkyA/results).
> The live results are public — see what other engineers say.
