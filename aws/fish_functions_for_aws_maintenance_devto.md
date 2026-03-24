---
title: "Week 9: Fish Shell Functions for Managing AWS EC2 Instances -- Save Time and Billing"
published: true
description: "A complete set of fish shell functions for creating, connecting to, stopping, snapshotting, and terminating AWS EC2 instances from the CLI — designed for personal security engineering labs."
tags: aws, security, devsecops, tutorial
cover_image:
series: Security Engineering Interview Prep
---

> **Prerequisites:** This post assumes you have a working AWS lab with IAM Identity Center and SSM Session Manager configured. If you have not done that yet, start here first:
>
> **👉 [Secure AWS Lab Setup for Security Engineers: IAM Identity Center + SSM + Zero Open Ports](https://dev.to/fosres/secure-aws-lab-setup-for-security-engineers-iam-identity-center-ssm-zero-open-ports-1hfn)**

---

If you find this useful, I'd really appreciate a ⭐ on my open source secure coding exercise repo — it helps a lot:

{% cta https://github.com/fosres/SecEng-Exercises %}
🌟 Star the SecEng-Exercises Repo on GitHub
{% endcta %}

Also — why do you read security engineering blog posts? One click helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)** (takes 10 seconds)

---

## Introduction

Running a personal AWS security lab involves the same set of CLI operations over and over: launch an instance, connect to it, do some work, save your progress, and shut it down to avoid unnecessary billing. Without automation, each of these steps requires remembering long `aws ec2` commands with multiple flags.

This post provides a complete set of fish shell functions that reduce all of that to single commands. They are designed specifically for the AWS lab exercises in this blog series and give you three practical benefits:

**Save progress** — `lab-snapshot` creates a full AMI snapshot of your running instance so you can terminate it and restore exactly where you left off next session. No reinstalling tools from scratch.

**Save time** — `lab-create` and `lab-restore` handle the full instance launch sequence automatically: create, wait for running state, wait for SSM Agent, and tell you when it is ready. One command instead of five.

**Save billing** — `lab-terminate` permanently deletes the instance so you pay nothing between sessions. Combined with snapshots, you get zero ongoing compute cost with full state preservation.

To put the cost difference in perspective:

| State | Monthly Cost |
|---|---|
| EC2 running 24/7 (t2.micro) | ~$8.35 |
| EC2 stopped (EBS volume persists) | ~$0.64 |
| AMI snapshot (used data only) | ~$0.10–0.15 |
| EC2 terminated, no snapshot | $0.00 |

A snapshot of a Debian 13 instance with Suricata installed uses roughly 2-3GB of actual data — AWS only charges for used data, not the full volume size. At $0.05/GB/month that comes to about $0.10-0.15/month. Compared to leaving the instance running at $8.35/month, snapshots are roughly **60x cheaper** while preserving your full environment between sessions.

All functions are available to download from GitHub:

**👉 [github.com/fosres/SecEng-Exercises/tree/main/aws/functions](https://github.com/fosres/SecEng-Exercises/tree/main/aws/functions)**

---

## Setup

### Install Fish Shell

```bash
# Debian / Ubuntu
sudo apt install fish -y

# Verify
fish --version
```

### Create the Functions Directory

```bash
mkdir -p ~/.config/fish/functions
```

Fish loads functions automatically from this directory. Each function lives in its own `.fish` file named after the function. No `source` command needed — drop the file in and it is immediately available.

### Set the Instance ID Universal Variable

All functions that operate on a running instance use `$INSTANCE_ID` — a fish universal variable that persists across all sessions permanently:

```fish
set -U INSTANCE_ID "i-your_instance_id_here"
```

`set -U` means universal — it survives terminal restarts, new tabs, and reboots. `lab-create` and `lab-restore` update it automatically when launching a new instance so you rarely need to set it manually.

---

## The Functions

### lab-login — Authenticate via IAM Identity Center

Run this at the start of every session. Opens a browser where you tap your YubiKey to issue 8-hour temporary credentials.

```fish
function lab-login
    aws sso login --profile lab-sso
end
```

```
$ lab-login
# Browser opens → tap YubiKey → "Your credentials have been shared successfully"
```

> **Token expires after 8 hours.** If any function returns `Token has expired and refresh failed` — run `lab-login` again.

---

### lab-status — Check Instance State

```fish
function lab-status
    aws ec2 describe-instances --instance-ids $INSTANCE_ID \
        --profile lab-sso \
        --query "Reservations[0].Instances[0].State.Name" \
        --output text
end
```

Returns: `running`, `stopped`, `terminated`, or `None`.

> **`None` means the instance was terminated.** Run `lab-create` or `lab-restore` to launch a new one.

---

### lab-start — Start a Stopped Instance

```fish
function lab-start
    aws ec2 start-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Starting... wait 60 seconds"
end
```

Use this only if you chose `lab-stop` to pause billing rather than `lab-terminate`. A stopped instance still incurs EBS storage charges (~$0.08/GB/month).

---

### lab-stop — Stop a Running Instance

```fish
function lab-stop
    aws ec2 stop-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Stopping..."
end
```

Pauses compute billing. The EBS volume persists with all data intact. Resume with `lab-start`.

---

### lab-connect — Open a Shell on the Instance

```fish
function lab-connect
    aws ssm start-session --target $INSTANCE_ID --profile lab-sso
end
```

Opens a terminal session via SSM Session Manager — no SSH, no open ports, no key pair file required.

```
$ lab-connect
Starting session with SessionId: your_username_here-...
$ whoami
ssm-user
```

---

### lab-terminate — Permanently Delete the Instance

Before running `lab-terminate`, always verify it is pointing at the right instance:

```fish
echo $INSTANCE_ID   # prints the instance ID it will terminate
lab-status          # confirms the instance is running
```

Both should agree before proceeding.

```fish
function lab-terminate
    echo "WARNING: This will permanently delete the instance and all data on it."
    echo "Instance: $INSTANCE_ID"
    read --prompt-str "Type YES to confirm: " confirm
    if test "$confirm" = "YES"
        aws ec2 terminate-instances \
            --instance-ids $INSTANCE_ID --profile lab-sso
        echo "Instance terminated. Use lab-create to launch a fresh one."
    else
        echo "Cancelled."
    end
end
```

> ⚠️ **Fish syntax bug:** Use `--prompt-str` not `--prompt` for the `read` command. Using `--prompt` causes a syntax error that **silently skips the confirmation** and immediately terminates the instance.

---

### lab-create — Launch a Fresh Instance from a Launch Template

```fish
function lab-create
    echo "Launching new suricata-ids-lab instance..."
    set new_id (aws ec2 run-instances \
        --launch-template LaunchTemplateName=suricata-lab-template \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=suricata-ids-lab}]" \
        --profile lab-sso \
        --query "Instances[0].InstanceId" \
        --output text)

    if test -z "$new_id"
        echo "ERROR: Failed to launch instance."
        return 1
    end

    echo "Instance launched: $new_id"
    echo "Updating INSTANCE_ID..."
    set -U INSTANCE_ID $new_id

    echo "Waiting for instance to reach running state..."
    aws ec2 wait instance-running \
        --instance-ids $new_id \
        --profile lab-sso

    echo "Instance is running."
    echo "Waiting 3 minutes for SSM Agent to initialize..."
    sleep 180

    echo "Ready. Run lab-connect to start your session."
end
```

Launches a clean Debian 13 instance from the Launch Template. Automatically updates `$INSTANCE_ID`. The 3-minute wait allows the User Data script to install the SSM Agent on first boot.

---

## Snapshot Functions

These functions let you save and restore instance state so you never lose progress between sessions.

---

### lab-snapshot-list — List All Saved Snapshots

```fish
function lab-snapshot-list
    echo "Your saved AMIs:"
    aws ec2 describe-images \
        --owners self \
        --query "Images[*].[ImageId,Name,CreationDate]" \
        --output table \
        --profile lab-sso
end
```

```
$ lab-snapshot-list

Your saved AMIs:
+------------------------+---------------------------+----------------------+
| ami-0xxxxxxxxxxxxxxxxx | suricata_setup-2026-03-15 | 2026-03-15T12:00:00Z |
+------------------------+---------------------------+----------------------+
```

---

### lab-snapshot — Save the Current Instance State

```fish
function lab-snapshot
    echo "Your running instances:"
    aws ec2 describe-instances \
        --filters "Name=instance-state-name,Values=running" \
        --query "Reservations[*].Instances[*].[InstanceId,State.Name]" \
        --output table \
        --profile lab-sso

    read --prompt-str "Enter Instance ID to snapshot (i-...): " instance_id

    if test -z "$instance_id"
        echo "ERROR: No Instance ID entered. Cancelled."
        return 1
    end

    read --prompt-str "Enter a name for this snapshot: " snapshot_name

    if test -z "$snapshot_name"
        echo "ERROR: No snapshot name entered. Cancelled."
        return 1
    end

    # Auto-detect the root volume device name from the running instance
    set device_name (aws ec2 describe-instances \
        --instance-ids $instance_id \
        --query "Reservations[0].Instances[0].RootDeviceName" \
        --output text \
        --profile lab-sso)

    set today (date +%Y-%m-%d)
    echo "Creating encrypted snapshot of $instance_id..."

    set ami_id (aws ec2 create-image \
        --instance-id $instance_id \
        --name "$snapshot_name-$today" \
        --description "Lab snapshot: $snapshot_name" \
        --no-reboot \
        --block-device-mappings "[{\"DeviceName\":\"$device_name\",\"Ebs\":{\"Encrypted\":true,\"DeleteOnTermination\":true}}]" \
        --profile lab-sso \
        --query "ImageId" \
        --output text)

    if test -z "$ami_id"
        echo "ERROR: Failed to create snapshot."
        return 1
    end

    echo "Snapshot created: $ami_id (encrypted)"
    echo "Waiting for snapshot to become available..."
    aws ec2 wait image-available \
        --image-ids $ami_id \
        --profile lab-sso

    echo "Snapshot is ready: $ami_id"
    echo "Use this ID with lab-restore to launch from this state."
end
```

**`--no-reboot`** — takes the snapshot while the instance keeps running. You stay connected the whole time.

**Encryption** — snapshots are encrypted at rest using the AWS-managed EBS key (`aws/ebs`). No password, no key to manage — AWS handles decryption transparently when the instance boots from the snapshot. The device name is auto-detected from the running instance so the encryption flag always targets the correct volume.

> ⏳ **Expect to wait 3-5 minutes** for the snapshot to complete. AWS is copying the entire EBS volume to S3. A heavily loaded instance may take up to 10-15 minutes. Do not interrupt it.

---

### lab-restore — Launch an Instance from a Snapshot

```fish
function lab-restore
    echo "Your saved AMIs:"
    aws ec2 describe-images \
        --owners self \
        --query "Images[*].[ImageId,Name,CreationDate]" \
        --output table \
        --profile lab-sso

    read --prompt-str "Enter AMI ID to restore from (ami-...): " ami_id

    if test -z "$ami_id"
        echo "ERROR: No AMI ID entered. Cancelled."
        return 1
    end

    set sg_id (aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=suricata-lab-sg" \
        --query "SecurityGroups[0].GroupId" \
        --output text \
        --profile lab-sso)

    if test -z "$sg_id"
        echo "ERROR: Could not find security group suricata-lab-sg."
        return 1
    end

    echo "Launching from snapshot $ami_id..."
    set new_id (aws ec2 run-instances \
        --image-id $ami_id \
        --instance-type t2.micro \
        --iam-instance-profile Name=suricata-lab-ssm-role \
        --security-group-ids $sg_id \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=suricata-ids-lab}]" \
        --profile lab-sso \
        --query "Instances[0].InstanceId" \
        --output text)

    if test -z "$new_id"
        echo "ERROR: Failed to launch instance. Check AMI ID and try again."
        return 1
    end

    echo "Instance launched: $new_id"
    echo "Updating INSTANCE_ID..."
    set -U INSTANCE_ID $new_id

    echo "Waiting for instance to reach running state..."
    aws ec2 wait instance-running \
        --instance-ids $new_id \
        --profile lab-sso

    echo "Instance is running."
    echo "Waiting 60 seconds for SSM Agent to initialize..."
    sleep 60

    echo "Ready. Run lab-connect to start your session."
end
```

Lists your saved AMIs first so you never need to look up the AMI ID separately. The security group ID is resolved automatically by name.

`sleep 60` instead of `sleep 180` — the SSM Agent is already baked into the snapshot so it initializes much faster than a fresh install.

---

### lab-snapshot-delete — Delete Old Snapshots

Over time you will accumulate outdated snapshots. Each one costs ~$0.05/GB/month so it is good practice to delete ones you no longer need. You can delete multiple snapshots in one go — type each AMI ID on its own line and press **Ctrl+D** when done.

```fish
function lab-snapshot-delete
    echo "Your saved AMIs:"
    aws ec2 describe-images \
        --owners self \
        --query "Images[*].[ImageId,Name,CreationDate]" \
        --output table \
        --profile lab-sso

    echo ""
    echo "Enter AMI IDs to delete, one per line."
    echo "Press Ctrl+D when done."
    echo ""

    set ami_ids

    while read --prompt-str "" ami_id
        set --append ami_ids $ami_id
    end

    if test (count $ami_ids) -eq 0
        echo "No AMI IDs entered. Cancelled."
        return 1
    end

    echo ""
    echo "The following snapshots will be permanently deleted:"
    for ami_id in $ami_ids
        echo "  - $ami_id"
    end
    echo ""

    read --prompt-str "Type YES to confirm deletion of all "(count $ami_ids)" snapshot(s): " confirm

    if test "$confirm" != "YES"
        echo "Cancelled."
        return 0
    end

    for ami_id in $ami_ids
        echo ""
        echo "Processing $ami_id..."

        set snapshot_id (aws ec2 describe-images \
            --image-ids $ami_id \
            --query "Images[0].BlockDeviceMappings[0].Ebs.SnapshotId" \
            --output text \
            --profile lab-sso)

        if test -z "$snapshot_id" -o "$snapshot_id" = "None"
            echo "WARNING: Could not find snapshot for $ami_id — skipping."
            continue
        end

        aws ec2 deregister-image \
            --image-id $ami_id \
            --profile lab-sso
        echo "AMI deregistered: $ami_id"

        aws ec2 delete-snapshot \
            --snapshot-id $snapshot_id \
            --profile lab-sso
        echo "Snapshot deleted: $snapshot_id"
    end

    echo ""
    echo "Done. Storage charges for deleted snapshots will stop within the hour."
end
```

The flow when deleting multiple snapshots at once:

```
$ lab-snapshot-delete

Your saved AMIs:
+------------------------+---------------------------+----------------------+
| ami-0xxxxxxxxxxxxxxxxx | suricata_setup-2026-03-15 | 2026-03-15T12:00:00Z |
| ami-0yyyyyyyyyyyyyyyyy | suricata_rules-2026-03-20 | 2026-03-20T10:14:00Z |
| ami-0zzzzzzzzzzzzzzzzz | suricata_full-2026-03-25  | 2026-03-25T08:30:00Z |
+------------------------+---------------------------+----------------------+

Enter AMI IDs to delete, one per line.
Press Ctrl+D when done.

ami-0xxxxxxxxxxxxxxxxx
ami-0yyyyyyyyyyyyyyyyy
ami-0zzzzzzzzzzzzzzzzz
^D

The following snapshots will be permanently deleted:
  - ami-0xxxxxxxxxxxxxxxxx
  - ami-0yyyyyyyyyyyyyyyyy
  - ami-0zzzzzzzzzzzzzzzzz

Type YES to confirm deletion of all 3 snapshot(s): YES

Processing ami-0xxxxxxxxxxxxxxxxx...
AMI deregistered: ami-0xxxxxxxxxxxxxxxxx
Snapshot deleted: snap-0xxxxxxxxxxxxxxxxx

Processing ami-0yyyyyyyyyyyyyyyyy...
AMI deregistered: ami-0yyyyyyyyyyyyyyyyy
Snapshot deleted: snap-0yyyyyyyyyyyyyyyyy

Processing ami-0zzzzzzzzzzzzzzzzz...
AMI deregistered: ami-0zzzzzzzzzzzzzzzzz
Snapshot deleted: snap-0zzzzzzzzzzzzzzzzz

Done. Storage charges for deleted snapshots will stop within the hour.
```

**Two steps are required to fully delete a snapshot — this is an important AWS quirk:**

**Step 1 — Deregister the AMI** (`aws ec2 deregister-image`) — removes the AMI entry. But the underlying EBS snapshot is still there and still billing you until Step 2.

**Step 2 — Delete the EBS snapshot** (`aws ec2 delete-snapshot`) — this is what actually frees the storage and stops charges.

`lab-snapshot-delete` handles both steps automatically for every ID in the list.

---

## Complete Reference

| Function | What it does |
|---|---|
| `lab-login` | Authenticate via IAM Identity Center (YubiKey tap) |
| `lab-status` | Check if instance is running, stopped, or terminated |
| `lab-start` | Start a stopped instance |
| `lab-stop` | Stop a running instance (EBS persists, small charge) |
| `lab-connect` | Open a shell via SSM Session Manager |
| `lab-terminate` | Permanently delete the instance (zero ongoing cost) |
| `lab-create` | Launch a fresh instance from Launch Template |
| `lab-snapshot-list` | List all saved AMI snapshots |
| `lab-snapshot` | Save current instance state to an encrypted AMI snapshot |
| `lab-restore` | Launch an instance from a saved AMI snapshot |
| `lab-snapshot-delete` | Delete one or more AMIs and their underlying EBS snapshots (line-separated input, Ctrl+D to finish) |

---

## Complete Zero-Cost Session Workflow

```fish
lab-login           # tap YubiKey → 8hr credentials
lab-restore         # launch from snapshot → wait → "Ready"
lab-connect         # shell as ssm-user
lab-snapshot        # save progress before ending session
lab-terminate       # zero ongoing cost
```

---

## The Open Source Project Behind This

These functions are part of an open source repository of LeetCode-style **secure coding exercises** designed to:

1. Train developers to write secure code
2. Prepare security engineers for technical interviews

Every exercise in the repo has 60+ test cases and a companion Dev.to post.

**If this post was useful, the best thing you can do is star the repo:**

{% cta https://github.com/fosres/SecEng-Exercises %}
🌟 Star the SecEng-Exercises Repo on GitHub
{% endcta %}

---

## One More Thing — Quick Poll

Why do you read security engineering blog posts? Your answer helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)**

Takes 10 seconds.

---

*Series: Security Engineering Interview Prep | Week 9 | March 2026*
*GitHub: [fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)*
