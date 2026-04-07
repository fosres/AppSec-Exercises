
# Week 10: AWS Incident Response Labs

**Objective:** Apply your AWS Security Incident Response training to real-world scenarios and reinforce NIST SP 800-61r3 practices.

---

## 📌 Core Foundational Labs

| **Lab**                     | **Objective**                                                                                     | **AWS Tools to Use**                          | **NIST Phase Focus**               | **Link/Resource**                                                                                     |
|-----------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------------------|
| **S3 Bucket Data Breach**   | Detect and remediate a misconfigured S3 bucket leaking sensitive data.                           | AWS Config, Macie, CloudTrail, S3 Access Logs | Detection → Recovery                | [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html) |
| **IAM Credential Theft**    | Respond to leaked IAM keys (e.g., GitHub exposure) and rotate credentials.                     | IAM Access Analyzer, CloudTrail, Lambda       | Preparation → Containment           | [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)        |
| **DDoS Attack on ALB**      | Mitigate a simulated DDoS attack targeting a web app behind an Application Load Balancer.     | AWS Shield Advanced, WAF, CloudWatch Alarms   | Detection → Containment             | [AWS Shield Advanced](https://aws.amazon.com/shield/)                                                 |

---

## 🌐 WebApp-Specific Labs

| **Lab**                     | **Objective**                                                                                     | **AWS Tools to Use**                          | **NIST Phase Focus**               | **Link/Resource**                                                                                     |
|-----------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------------------|
| **API Gateway Abuse**       | Detect and block malicious requests to an API (e.g., SQLi, brute force).                         | WAF, Lambda, CloudTrail                      | Detection → Eradication             | [AWS WAF for API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-api.html) |
| **Lambda Privilege Escalation** | Simulate and respond to a compromised Lambda function (e.g., event injection, reverse shell). | GuardDuty, X-Ray, CloudTrail                 | Detection → Recovery                | [AWS Lambda Security](https://docs.aws.amazon.com/lambda/latest/dg/security-best-practices.html)      |
| **Container Escape (ECS)**  | Investigate and contain a container breakout in ECS/EKS (e.g., privileged pod exploit).        | ECS Audits, GuardDuty, Security Hub           | Detection → Containment             | [ECS Security Best Practices](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-best-practices.html) |

---

## ⚡ Advanced Lab (Optional)

| **Lab**                     | **Objective**                                                                                     | **AWS Tools to Use**                          | **NIST Phase Focus**               | **Link/Resource**                                                                                     |
|-----------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------------------|
| **Automated GuardDuty Response** | Build a Lambda function to auto-contain threats (e.g., isolate EC2 on `Trojan:EC2` alert).     | GuardDuty, Lambda, Step Functions            | Detection → Containment             | [AWS Lambda + GuardDuty Integration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-lambda.html) |

---

## 🎯 How to Approach These Labs

1. **Pick 1–2 labs** from the **Foundational** or **WebApp-Specific** categories.
2. **Document each step** using your **Dev.to template** (add screenshots, commands, and lessons learned).
3. **Map each lab to NIST SP 800-61r3** (e.g., “This covers Detection → Containment”).
4. **Automate a small part** (e.g., a Lambda function for isolating EC2 on GuardDuty alerts).

---

## 📝 Deliverables for Each Lab

- **Lab Report**: Markdown/PDF with:
  - Alert summary (GuardDuty findings).
  - Timeline of events (CloudTrail/VPC Flow Logs).
  - Containment/eradication steps.
  - Recommendations for prevention.
- **Cleanup Script**: Bash/Python automation for future use.
- **Screenshot**: GuardDuty finding or Security Hub alert.

---

**Need a step-by-step guide for any of these?** Let me know, and I’ll draft it for you!
