---
title: "Secure AWS Lab Setup for Security Engineers: IAM Identity Center + SSM + Zero Open Ports"
published: true
description: "How to set up a personal AWS security lab with no SSH keys, no open ports, YubiKey FIDO2 on the CLI, and one-command instance creation/termination — with zero ongoing cost between sessions."
tags: aws, security, devsecops, tutorial
cover_image: 
series: Security Engineering Interview Prep
---

AWS, GCP, and Azure are the three dominant cloud providers in the industry. As a Security Engineer you will encounter at least one of them in virtually every role — whether you are securing infrastructure, reviewing architecture, responding to incidents, or building detection rules. You do not need to master all three. But you do need to go deep on at least one.

This post is about AWS — the most widely deployed of the three and the one most commonly required in Security Engineering job postings. Learning AWS deeply means understanding not just how to launch a virtual machine, but how identity works, how access is controlled, how services communicate securely, and how to build infrastructure that is defensible by design.

This post is written for a **complete beginner to AWS**. By the end you will know how to do the following entirely from your local computer using the CLI — no browser required after initial setup:

- **Login** to AWS securely using either static credentials or a hardware security key (YubiKey)
- **Create** an EC2 instance (a virtual machine in the cloud) with one command
- **Connect** to that instance without SSH, without open ports, and without a key pair file
- **Stop** the instance to pause billing when not in use
- **Terminate** the instance permanently to pay zero ongoing cost between sessions

Along the way the post covers IAM (Identity and Access Management), IAM Identity Center, SSM Session Manager, security groups, IAM roles, Launch Templates, and fish shell automation — all grounded in real decisions made during a Week 9 Suricata IDS lab setup.

Everything documented here is a real setup that was built step by step, including the failures. If something broke, it is noted and the fix is included.

---

If you find this useful, I'd really appreciate a ⭐ on my open source secure coding exercise repo — it helps a lot:

**👉 [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

Also — quick question: why do you read security engineering blog posts? One click helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)** (takes 10 seconds)

---

## What This Post Covers

This is the exact setup I built during Week 9 of my Security Engineering curriculum while preparing to run a Suricata IDS lab on AWS EC2. What started as "just spin up an instance" turned into a proper secure access architecture covering:

- Why root credentials are dangerous (and what to use instead)
- Two CLI auth methods: IAM Access Keys (simple) vs IAM Identity Center (secure)
- EC2 instance with **zero open inbound ports** — no SSH, no bastion host
- SSM Session Manager for terminal access through AWS
- Fish shell lab functions: `lab-login`, `lab-create`, `lab-connect`, `lab-terminate`
- A Launch Template for repeatable, cost-free instance lifecycle
- The `iam:PassRole` error you will hit with PowerUserAccess — and the exact fix

**Curriculum intersections:** This covers Week 15 content (EC2, IAM basics) and Week 49 content (IAM Identity Center) — completed early as infrastructure prerequisites for the IDS lab.

---

## Part 1: Why Not Root Credentials

Every AWS account has a root user with unlimited permissions that cannot be restricted by any IAM policy. AWS explicitly states you should never use root for everyday tasks.

Root should only ever be used for:
- Billing and payment settings  
- Account closure  
- IAM recovery if all other admin access is lost  

> ⚠️ **Never** run `aws configure` with root credentials. Never create root access keys. Root should only authenticate via the console with MFA.

On this account root is protected with two YubiKeys registered as FIDO2 devices. That is the last line of defense.

---

## Part 1.5: First — Create an AWS Account

Before anything else you need an AWS account. Go to [aws.amazon.com](https://aws.amazon.com) and sign up — it takes about 5 minutes and requires a credit card for identity verification. AWS has a generous free tier that covers most personal lab usage including the t2.micro instance type used throughout this post.

The account you create becomes your **root account**. Read Part 1 above before using it for anything.

---

## Part 2: Create a Scoped IAM User

Create an IAM user with only the permissions needed for lab work. This limits blast radius if credentials are ever compromised.

### Step 1 — Create the User

```
IAM Console → Users → Create user
→ Username: your_username_here
→ Check: Provide user access to AWS Management Console
→ Select: I want to create an IAM user
→ Custom password: (set a strong password)
→ Uncheck: Users must create new password at next sign-in
→ Next
```

### Step 2 — Attach Permissions

```
→ Attach policies directly
→ Search and check: AmazonEC2FullAccess
→ Search and check: AmazonSSMFullAccess
→ Next → Create user
```

> **Do NOT attach AdministratorAccess.** The two policies above give enough permissions to manage EC2 and SSM without touching IAM or billing.

### Step 3 — Add MFA for Console Login

AWS supports two MFA methods for IAM users. Choose one:

**Option A — Authenticator App (TOTP)**
The most common method. Install Google Authenticator, Authy, or 1Password on your phone. AWS shows a QR code — scan it, enter two consecutive 6-digit codes to confirm, done. No hardware required.

```
IAM → Users → your_username_here
→ Security credentials tab
→ Multi-factor authentication (MFA) → Assign MFA device
→ MFA device type: Authenticator app
→ Scan the QR code with your authenticator app
→ Enter two consecutive 6-digit codes to confirm
```

**Option B — Hardware Security Key (FIDO2/YubiKey)**
More secure than TOTP. Requires a physical YubiKey or similar FIDO2 device (~$50). Immune to phishing because the key cryptographically binds to the origin domain — a fake AWS login page cannot steal it.

```
IAM → Users → your_username_here
→ Security credentials tab
→ Multi-factor authentication (MFA) → Assign MFA device
→ MFA device type: Passkey or security key
→ Insert YubiKey and tap when prompted
```

> **This post uses Option B (YubiKey).** TOTP is acceptable for a personal lab and requires no extra hardware. YubiKey is the stronger choice and becomes important in Part 11 where it enables hardware-backed MFA directly on CLI calls — something TOTP cannot do.

Note the console sign-in URL shown on the user creation confirmation page:

```
https://<YOUR_ACCOUNT_ID>.signin.aws.amazon.com/console
```

This is different from the root login page. Bookmark it.

---

## Part 3: Method 1 — IAM Access Keys (Static Credentials)

The simpler method. Permanent access key stored locally. Never expires unless manually deleted — which is both convenient and dangerous.

### Install AWS CLI v2 on Debian 12/13

```bash
# Install dependencies
sudo apt update && sudo apt install curl unzip -y

# Download from AWS directly
# Note: never use apt install awscli — the Debian repo does not include v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify
aws --version
# aws-cli/2.34.9 Python/3.13.11 Linux/6.1.0-43-amd64 exe/x86_64.debian.12
```

### Create the Access Key

```
IAM → Users → your_username_here
→ Security credentials tab
→ Access keys → Create access key
→ Use case: Command Line Interface (CLI)
→ Check the amber warning confirmation box
→ Next → Create access key
→ DOWNLOAD .csv FILE IMMEDIATELY
```

> ⚠️ AWS shows the Secret Access Key exactly **once**. If you close the page without saving it you must delete the key and create a new one. Always download the .csv before clicking Done.

### Configure the CLI

```bash
aws configure
# AWS Access Key ID:     AKIA...  (from the .csv)
# AWS Secret Access Key: ...      (from the .csv)  
# Default region name:   us-east-1
# Default output format: json
```

### Verify Identity — What is STS?

```bash
aws sts get-caller-identity
```

**STS = Security Token Service.** The `get-caller-identity` command asks AWS "who am I authenticated as right now?" It is the fastest way to verify credentials are working correctly.

```json
{
    "UserId":  "AIDA xxxxxxxxxxxxxxxxxxxx",
    "Account": "YOUR_ACCOUNT_ID",
    "Arn":     "arn:aws:iam::YOUR_ACCOUNT_ID:user/your_username_here"
}
```

✅ If the ARN shows `user/your_username_here` (not root) — the access key is working.

---

## Part 4: Create the IAM Role for EC2

The EC2 instance needs its own identity to communicate with AWS Systems Manager. This is **separate** from your user identity.

```
IAM Console → Roles → Create role
→ Trusted entity: AWS service → Use case: EC2
→ Next
→ Search: AmazonSSMManagedInstanceCore → Check the box
→ Next
→ Role name: suricata-lab-ssm-role
→ Create role
```

**Key distinction — two separate identities:**

```
YOU (your_username_here)      → authenticated via IAM credentials
                           can start SSM sessions, launch EC2

EC2 INSTANCE             → authenticated via suricata-lab-ssm-role
                           can communicate with SSM
                           can receive your session connection
```

The role is the instance's identity, not yours. This is why `iam:PassRole` matters (covered in Part 14).

---

## Part 5: Security Group — Zero Open Ports

```
EC2 → Security Groups → Create security group
→ Name: suricata-lab-sg
→ Inbound rules: DELETE any default rules → NONE
→ Outbound rules: keep default (all traffic)
→ Create security group
```

This is the key to the whole architecture. SSM Session Manager works over **outbound HTTPS (port 443)** to reach AWS endpoints. No inbound ports needed. No port 22. No bastion host. Your VPN IP is completely irrelevant.

> **Note:** EC2 Instance Connect will NOT work with no inbound rules. This is intentional. SSM replaces SSH entirely.

---

## Part 6: Launch EC2 Instance — The User Data Bootstrap

This is where Debian 13 causes a surprise. Several approaches fail before finding the correct solution.

**What failed:**
- EC2 Instance Connect → Debian 13 AMI has no `ec2-instance-connect` package
- CloudShell `aws ssm send-command` → requires SSM Agent to already be installed
- Temporarily opening port 22 → EC2 Instance Connect still fails (no package)

**The correct solution: User Data**

User Data runs as root on first boot before you ever connect. It installs the SSM Agent automatically.

### Launch Configuration

```
EC2 → Launch Instance

Name:          suricata-ids-lab
AMI:           Debian 13 (Bookworm)
               → Browse AMIs → AWS Marketplace AMIs
               → Search: Debian 13
               → Publisher: Debian (official only — verify this)
Instance type: t2.micro (free tier eligible)
Key pair:      Proceed without a key pair
Security group: Select existing → suricata-lab-sg

Advanced details:
  IAM instance profile: suricata-lab-ssm-role
```

### User Data Script (paste in Advanced details → User data)

```bash
#!/bin/bash
apt-get update -y
wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
dpkg -i amazon-ssm-agent.deb
systemctl enable amazon-ssm-agent
systemctl start amazon-ssm-agent
```

> Wait **3-5 minutes** after launch before trying to connect. The User Data script needs time to complete on first boot.

---

## Part 7: Install Session Manager Plugin Locally

One-time install on your **local machine** (not the EC2 instance):

```bash
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" \
  -o "/tmp/session-manager-plugin.deb"

sudo dpkg -i /tmp/session-manager-plugin.deb

# Verify
session-manager-plugin --version
```

---

## Part 8: Fish Shell Lab Functions

All lab operations wrapped in fish functions using the universal variable `INSTANCE_ID`. One `set -U` command updates everything simultaneously.

### Set the Instance ID (run once after launch)

```fish
# set -U creates a universal variable — persists across all sessions permanently
# No source command, no file editing, no restart needed
set -U INSTANCE_ID "i-your_instance_id_here"
```

### Create the Functions

```bash
mkdir -p ~/.config/fish/functions
```

Fish loads functions automatically from `~/.config/fish/functions/`. Each function lives in its own file named after the function. For each snippet below, copy the contents and save it to the filename shown in bold — for example, copy the `lab-status` function into a file called `lab-status.fish` inside that directory.

**lab-status.fish**
```fish
function lab-status
    aws ec2 describe-instances --instance-ids $INSTANCE_ID \
        --profile lab-sso \
        --query "Reservations[0].Instances[0].State.Name" \
        --output text
end
```

**lab-start.fish**
```fish
function lab-start
    aws ec2 start-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Starting... wait 60 seconds"
end
```

**lab-stop.fish**
```fish
function lab-stop
    aws ec2 stop-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Stopping..."
end
```

**lab-connect.fish**
```fish
function lab-connect
    aws ssm start-session --target $INSTANCE_ID --profile lab-sso
end
```

**lab-login.fish** (SSO only — covered in Part 11)
```fish
function lab-login
    aws sso login --profile lab-sso
end
```

**lab-terminate.fish**
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

> ⚠️ **Fish syntax bug:** Use `--prompt-str` not `--prompt` for the `read` command. Using `--prompt` causes a syntax error that **silently skips the confirmation** and immediately terminates the instance. Ask me how I know.

---

## Part 9: Verify the Access Key Method Works

```fish
lab-status    # → running
lab-connect   # → Starting session with SessionId: your_username_here-....
whoami        # → ssm-user
```

✅ **ssm-user** means SSM Session Manager is working end-to-end. No SSH keys, no open ports, no IP whitelisting. Your VPN connection is irrelevant.

---

## Part 10: Why Switch to IAM Identity Center?

The Access Key method works — but it has fundamental security weaknesses. IAM Identity Center addresses all of them.

| Property | IAM Access Key | IAM Identity Center |
|---|---|---|
| Credential lifetime | **Permanent** — never expires | **8 hours max** — auto-expire |
| MFA on CLI | **No** — TOTP only (phishing vulnerable) | **Yes** — YubiKey FIDO2 ✓ |
| Phishing resistant | **No** — fake page can steal key | **Yes** — YubiKey is origin-bound |
| Stored on disk | **Yes** — `~/.aws/credentials` forever | Temporary token only |
| GitHub leak risk | **Catastrophic** — permanent until revoked | **Minimal** — expired when found |
| Blast radius if stolen | Full EC2+SSM access forever | At most 8hr remaining session |
| Revocation | Manual — must find and delete | Instant — delete user or session |

**The FIDO2 on CLI insight:** The reason YubiKey works with Identity Center but not a plain access key is that `aws sso login` opens a browser — and the browser is where WebAuthn/FIDO2 works. Every CLI session starts with a YubiKey tap.

This maps directly to what SAED — a Security Engineer at Google with 6+ years of experience — wrote in a LinkedIn post listing 40 concepts junior Security Engineers should focus on in 2026. Under the Identity, Access and Secrets category he includes specifically: **"Least privilege, just in time and time bound access patterns."** ([source](https://www.linkedin.com/feed/update/urn:li:activity:7422250871062695937/)) IAM Identity Center is the practical implementation of that concept.

---

## Part 11: Method 2 — IAM Identity Center Full Setup

Before setting up Identity Center, delete the static access key. The two methods should not coexist long-term.

> **Safer sequence:** Deactivate the key first (reversible) → set up Identity Center → confirm `lab-connect` works → then permanently delete the key. Deleting before SSO is confirmed risks losing all CLI access.

### Enable IAM Identity Center

```
AWS Console → search "IAM Identity Center"
→ Enable IAM Identity Center
→ Enable with AWS Organizations
→ Continue → wait 1-2 minutes

Save from the Settings summary:
  Access portal URL: https://d-xxxxxxxxxx.awsapps.com/start
  Primary Region:    us-east-1
```

> IAM Identity Center can only be enabled in a single AWS Region. Match it to your EC2 region.

### Configure MFA Settings (Critical)

```
IAM Identity Center → Settings → Configure MFA

Prompt users for MFA:
  ● Every time they sign in (always-on)

MFA types:
  ☑ Security keys and built-in authenticators (FIDO2)
  ☐ Authenticator apps  ← leave UNCHECKED

If no MFA device:
  ● Require them to register at sign in

→ Save
```

Authenticator apps (TOTP) is intentionally left unchecked. TOTP is phishing-vulnerable. Enforcing FIDO2-only means every user must have a hardware security key. No weaker fallback permitted.

### Create a Permission Set

A permission set is the bridge between an Identity Center user and an AWS account. It answers the question: **once this user authenticates, what are they actually allowed to do?**

Without a permission set you can authenticate successfully via IAM Identity Center and still have zero ability to do anything in AWS — authentication and authorization are separate steps. The permission set defines the authorization layer: which AWS actions the user can perform, which resources they can touch, and how long their session lasts before requiring re-authentication.

This separation is itself a security principle. It means you can grant a user access to an account without giving them unlimited power inside it — and you can revoke or change their permissions without touching their login credentials.

```
IAM Identity Center → Permission sets → Create permission set
→ Predefined permission set
→ Policy: PowerUserAccess
→ Permission set name: lab-power-user
→ Session duration: 8 hours
→ Create
```

**What PowerUserAccess allows and denies:**

```
Allows:   ALL AWS actions EXCEPT iam:*, organizations:*, account:*

Explicitly allows (narrow exceptions):
  iam:CreateServiceLinkedRole
  iam:DeleteServiceLinkedRole
  iam:ListRoles
  organizations:DescribeOrganization

Does NOT include: iam:PassRole  ← this matters (see Part 14)
```

### Create an Identity Center User

```
IAM Identity Center → Users → Add user
→ Username: your_username_here
→ Password: Send an email to this user
→ Email address: your-email@example.com
→ First name / Last name: fill in
→ Next → Add user

Check email → click activation link → set password
```

### Register YubiKey for Identity Center User

```
IAM Identity Center → Users → your_username_here
→ MFA devices tab → Register device
→ Security key (FIDO2)
→ Insert YubiKey and tap when prompted
→ Register
```

### Assign User to AWS Account

```
IAM Identity Center → Users → your_username_here
→ AWS accounts tab → Assign accounts
→ Select: your account (your_account_name_here / YOUR_ACCOUNT_ID)
→ Next
→ Select permission set: lab-power-user
→ Assign
```

**Why this assignment matters:**

The Identity Center user (`your_username_here`) is the authentication layer. The AWS account (`your_account_name_here`) is where all resources live. The permission set (`lab-power-user`) defines what actions are allowed inside that account. You can assign one user to multiple AWS accounts with different permission sets — that is the real power of Identity Center in multi-account organizations.

### Configure AWS CLI for SSO

```bash
aws configure sso

# Prompts:
# SSO session name:         lab-sso
# SSO start URL:            https://d-xxxxxxxxxx.awsapps.com/start
# SSO region:               us-east-1
# SSO registration scopes:  sso:account:access  (press Enter)

# Browser opens automatically
# Log in → tap YubiKey
# Browser: "Your credentials have been shared successfully"

# Back in terminal:
# CLI default client Region:  us-east-1
# CLI default output format:  json
# CLI profile name:           lab-sso
```

### Verify Identity Center Works

```bash
aws sts get-caller-identity --profile lab-sso
```

```json
{
    "UserId":  "AROA xxxxxxxxxxxxxxxxxxxx:your_username_here",
    "Account": "YOUR_ACCOUNT_ID",
    "Arn":     "arn:aws:sts::YOUR_ACCOUNT_ID:assumed-role/AWSReservedSSO_lab-power-user_xxxxxxxxxxxxxxxxx/your_username_here"
}
```

Notice **`assumed-role`** in the ARN. These are temporary credentials that expire in 8 hours. The access key showed `user/your_username_here` — a permanent identity. This is the difference.

✅ **IAM Identity Center confirmed working.**

---

## Part 12: Create the Launch Template

A Launch Template saves all instance configuration. `lab-create` uses it to launch an identical fresh instance with one command.

```
EC2 → Launch Templates → Create launch template

Launch template name:  suricata-lab-template
Description:           Debian 13 + SSM Agent via User Data

AMI:              Debian 13 (official Debian publisher)
Instance type:    t2.micro
Key pair:         Don't include in launch template
Security group:   Select existing → suricata-lab-sg

Advanced details:
  IAM instance profile: suricata-lab-ssm-role
  User data:
    #!/bin/bash
    apt-get update -y
    wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
    dpkg -i amazon-ssm-agent.deb
    systemctl enable amazon-ssm-agent
    systemctl start amazon-ssm-agent

→ Create launch template
```

---

## Part 13: Update Fish Functions for SSO Profile

Add `--profile lab-sso` to all functions that make AWS CLI calls. Overwrite the files created in Part 8:

```fish
# Rewrite lab-connect
echo 'function lab-connect
    aws ssm start-session --target $INSTANCE_ID --profile lab-sso
end' > ~/.config/fish/functions/lab-connect.fish

# Rewrite lab-status
echo 'function lab-status
    aws ec2 describe-instances --instance-ids $INSTANCE_ID \
        --profile lab-sso \
        --query "Reservations[0].Instances[0].State.Name" \
        --output text
end' > ~/.config/fish/functions/lab-status.fish

# Rewrite lab-start
echo 'function lab-start
    aws ec2 start-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Starting... wait 60 seconds"
end' > ~/.config/fish/functions/lab-start.fish

# Rewrite lab-stop  
echo 'function lab-stop
    aws ec2 stop-instances --instance-ids $INSTANCE_ID --profile lab-sso
    echo "Stopping..."
end' > ~/.config/fish/functions/lab-stop.fish

# Rewrite lab-terminate
echo 'function lab-terminate
    echo "WARNING: Permanently deletes instance and all data on it."
    echo "Instance: $INSTANCE_ID"
    read --prompt-str "Type YES to confirm: " confirm
    if test "$confirm" = "YES"
        aws ec2 terminate-instances \
            --instance-ids $INSTANCE_ID --profile lab-sso
        echo "Instance terminated. Use lab-create to launch a fresh one."
    else
        echo "Cancelled."
    end
end' > ~/.config/fish/functions/lab-terminate.fish
```

---

## Part 14: Fix the iam:PassRole Error

When you first run `lab-create` you will hit this:

```
aws: [ERROR]: An error occurred (UnauthorizedOperation) when calling
the RunInstances operation: You are not authorized to perform:
iam:PassRole on resource: ...suricata-lab-ssm-role...
```

**Why this happens:** PowerUserAccess blocks all `iam:*` actions including `iam:PassRole`. Without it, `your_username_here` cannot assign `suricata-lab-ssm-role` to the new EC2 instance.

**Why this matters for security:** Without restricting `iam:PassRole`, a user with EC2 launch permissions could attach an `AdministratorAccess` role to an instance and then connect to it — escalating from PowerUser to full Administrator through the instance. The restriction closes this path.

**The fix:** Add a narrow inline policy to `lab-power-user` that grants `iam:PassRole` only for this specific role, only to EC2:

```
IAM Identity Center → Permission sets → lab-power-user
→ Inline policy → Add inline policy
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::YOUR_ACCOUNT_ID:role/suricata-lab-ssm-role",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "ec2.amazonaws.com"
        }
      }
    }
  ]
}
```

```
→ Save changes
(Reprovisioning happens automatically — wait ~30 seconds)
```

Two restrictions make this safe:
- `Resource` — only `suricata-lab-ssm-role`, not any other role in the account
- `iam:PassedToService` — only to EC2, not Lambda, ECS, or anything else

---

## Part 15: lab-create — Launch Fresh Instances On Demand

**lab-create.fish**

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

**What this does step by step:**
1. Calls `aws ec2 run-instances` using the Launch Template — no need to specify AMI, security group, IAM profile, or User Data manually
2. Captures the new instance ID
3. Automatically runs `set -U INSTANCE_ID` — all other functions point to the new instance immediately
4. `aws ec2 wait instance-running` — blocks until AWS confirms the instance is running
5. `sleep 180` — waits for the User Data SSM Agent install to complete
6. Prints "Ready"

---

## Part 16: Complete Daily Workflow

```fish
# Start of session
lab-login      # browser opens → tap YubiKey → 8hr credentials issued

# Launch fresh instance
lab-create     # launches, waits for running, waits 3min for SSM Agent

# Do work
lab-connect    # shell as ssm-user — no SSH, no ports, no keys

# End of session
lab-terminate  # permanently deletes instance → zero ongoing cost
```

**Between sessions:**
- No running EC2 instance — no compute charges
- No EBS volume — no storage charges  
- No static credentials on disk — credentials expired
- Every `lab-create` starts completely fresh from the Launch Template

| Metric | Access Key | Identity Center |
|---|---|---|
| Auth on CLI | Static key, no MFA | YubiKey tap per session |
| Credentials expire | Never | Every 8 hours |
| Port 22 required | No (SSM) | No (SSM) |
| SSH keys required | No | No |
| VPN compatibility | Irrelevant | Irrelevant |
| Cost when not working | Stop: ~$0.08/GB EBS | Terminate: **$0.00** |

---

## What Curriculum Weeks This Covers

This went well beyond the Week 9 IDS lab it was meant to support:

| Topic | Curriculum Week |
|---|---|
| EC2, security groups, IAM roles, SSM | Week 15 |
| AWS IAM users, access keys, MFA | Week 15 |
| IAM Identity Center (SSO) setup | **Week 49** |
| Permission sets, PassRole patterns | **Week 49** |
| Launch Templates, instance lifecycle | **Week 50** |

Weeks 49-50 are normally scheduled for January 2027. Completed early as infrastructure prerequisites for the IDS lab.

---

## Common Issues and Fixes

### Issue 1 — SSO Token Expired

```
aws: [ERROR]: Error when retrieving token from sso: Token has expired and refresh failed
```

This is IAM Identity Center **working exactly as designed**. The 8-hour session expired. Fix:

```fish
lab-login
```

Browser opens → tap YubiKey → new 8-hour session issued. Then continue normally:

```fish
lab-status
lab-connect
```

This is the entire cost of IAM Identity Center over static access keys — one YubiKey tap per 8-hour session. A fair tradeoff for credentials that auto-expire and can never be leaked permanently.

---

### Issue 2 — lab-status Returns "None"

```fish
lab-status
# → None
```

The previous instance was terminated. `INSTANCE_ID` is pointing to a dead instance ID. Fix:

```fish
lab-create
```

`lab-create` launches a fresh instance and automatically runs `set -U INSTANCE_ID` with the new ID. All other functions update immediately. No manual intervention needed.

---

### Issue 3 — lab-connect Fails After lab-create

If `lab-connect` fails immediately after `lab-create` completes:

```
SessionManagerPlugin is not found
```

Install the Session Manager plugin locally (see Part 7). One-time setup.

If the plugin is installed but you still get "instance not reachable":

```fish
# The SSM Agent may still be initializing
# Wait 2-3 more minutes and try again
lab-connect
```

The `sleep 180` in `lab-create` handles most cases but on a slow boot it may need another minute.

---

### Issue 4 — lab-terminate Skips Confirmation and Immediately Terminates

You used `--prompt` instead of `--prompt-str` in the function definition. Fish requires `--prompt-str`. Rewrite the function:

```fish
echo 'function lab-terminate
    echo "WARNING: Permanently deletes instance and all data on it."
    echo "Instance: $INSTANCE_ID"
    read --prompt-str "Type YES to confirm: " confirm
    if test "$confirm" = "YES"
        aws ec2 terminate-instances \
            --instance-ids $INSTANCE_ID --profile lab-sso
        echo "Instance terminated. Use lab-create to launch a fresh one."
    else
        echo "Cancelled."
    end
end' > ~/.config/fish/functions/lab-terminate.fish
```

---

## The Open Source Project Behind This

These exercises are part of a larger project: an open source repository of LeetCode-style **secure coding exercises** designed to:

1. Train developers to write secure code
2. Prepare security engineers for technical interviews



**If this post was useful, the best thing you can do is star the repo:**

**👉 [github.com/fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)**

Stars help the repo appear in GitHub search and signal to AI companies that this dataset is worth using.

---

## One More Thing — Quick Poll

Why do you read security engineering blog posts? Your answer helps me write better content:

**👉 [Take the poll](https://strawpoll.com/wby5QoKAkyA)**

Takes 10 seconds.

---

## Next in This Series

**Week 9 Part 2** — Now that the lab is running, the actual Suricata IDS setup: installing Suricata on Debian 13, writing 5 custom detection rules (SQL injection focus), PCAP analysis, and the AWS Network Firewall connection — every Suricata rule in this lab is directly portable to AWS Network Firewall because AWS uses Suricata-compatible IPS rules natively since November 2020.

---

*Series: Security Engineering Interview Prep | Week 9 | March 2026*  
*GitHub: [fosres/SecEng-Exercises](https://github.com/fosres/SecEng-Exercises)*
