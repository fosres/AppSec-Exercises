# Week 10 — Incident Response Labs (Activities 4–7)

**Total: 11 hours | Phase 3 & 4 of Week 10 Security Engineering Block**

---

## Activity 4 — Ransomware Tabletop Exercise
**Type:** Lab | **Duration:** 3 hours

Simulate a ransomware incident against a file server. Walk through the NIST IR lifecycle in real time against the timeline below.

### Timeline

- **T+0** — EDR alert fires: suspicious encryption activity detected
- **T+5 min** — Multiple users report files inaccessible
- **T+10 min** — Ransom note discovered on desktop

### Tasks

Answer each of the following before moving on:

1. Classify severity — P0, P1, or P2? Justify your choice.
2. Determine containment actions — isolate the server? Segment the network?
3. Identify stakeholders to notify — CISO, Legal, PR?
4. Plan eradication — which backup do you restore from?
5. Document the full event timeline.
6. Write a communication plan for internal and external stakeholders.

### Deliverable

A written IR playbook document covering all six tasks above. This is a portfolio artifact.

---

## Activity 5 — Volatile Data Collection Script
**Type:** Lab | **Duration:** 2 hours

Build and run a Linux volatile data collection script on your t2.micro EC2 instance (Debian 13, SSM access via lab-sso). Collect in order of volatility: processes first, disk last. Hash all outputs for chain of custody.

### Script

```bash
#!/bin/bash
OUTDIR="ir_collection_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTDIR
uname -a > $OUTDIR/system_info.txt
hostname > $OUTDIR/hostname.txt
who > $OUTDIR/logged_in_users.txt
ps auxww > $OUTDIR/processes.txt
netstat -anp > $OUTDIR/network_connections.txt
arp -a > $OUTDIR/arp_cache.txt
lsof > $OUTDIR/open_files.txt
sha256sum $OUTDIR/* > $OUTDIR/checksums.txt
```

### Tasks

1. Run the script on your live t2.micro instance via SSM Session Manager.
2. Verify all output files are created and checksums generated.
3. Explain in writing why each piece of data is collected in that order.

### Order of Volatility Reference

CPU registers → RAM → network connections → running processes → disk → logs

---

## Activity 6 — AWS IR Playbooks Workshop
**Type:** Hands-on AWS | **Duration:** 3 hours

Official AWS Workshop Studio lab. Deploys real AWS infrastructure in your own account and simulates two IR scenarios using bash scripts. You respond following the included playbooks.

### Links

- Workshop: https://catalog.us-east-1.prod.workshops.aws/workshops/43742d64-6a5e-45ea-9339-cbb3fb26944e/en-US
- GitHub: https://github.com/aws-samples/aws-incident-response-playbooks-workshop

### Scenarios

- **Scenario 1:** IAM credential exposure — detect, scope, contain, rotate
- **Scenario 2:** EC2 crypto mining — identify rogue instance, isolate, eradicate

### Tasks

1. Deploy the workshop environment via CloudFormation in your lab-sso account.
2. Run the bash simulation scripts to generate real CloudTrail evidence.
3. Use Athena to query CloudTrail logs for each scenario.
4. Follow the included playbooks to respond to each scenario.
5. Terminate all resources when done to avoid charges.

---

## Activity 7 — IR Automation Tool (Python)
**Type:** Coding Challenge | **Duration:** 3 hours

Build an incident response tracking tool in Python implementing the full NIST IR lifecycle as a state machine, with timeline logging, severity management, and JSON report generation.

### Requirements

- `IncidentSeverity` enum: `P0_CRITICAL`, `P1_HIGH`, `P2_MEDIUM`, `P3_LOW`, `P4_INFO`
- `IncidentStatus` enum: `NEW` → `CONTAINED` → `ERADICATED` → `RECOVERED` → `CLOSED`
- `Incident` class with:
	- Auto-generated ID in format `INC-YYYYMMDD-HHMMSS`
	- `timeline` list and `created_at` timestamp
	- `update_status(status, notes)` method
	- `add_action(action)` method
	- `escalate()` method
	- `generate_report()` method returning JSON string

### Test Scenario

Run your tool against this scenario to verify correctness:

1. Create incident: "Suspicious Outbound Traffic to Known C2 Server" at P1_HIGH
2. Add action: "Isolated affected workstation from network"
3. Add action: "Captured memory dump for analysis"
4. Update status to CONTAINED with note: "System isolated, investigating scope"
5. Add action: "Identified malware: AsyncRAT"
6. Update status to ERADICATED with note: "Malware removed, system reimaged"
7. Call `generate_report()` and verify JSON output

### Notes

- Use tabs not spaces.
- Commit to GitHub — this is a portfolio artifact.
- Write to production quality standards per *Effective Python* guidelines.
