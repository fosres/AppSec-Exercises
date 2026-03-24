# ============================================================
# Suricata IDS Lab — Terraform Configuration
# Recreates the full AWS lab setup from Week 9
# ============================================================

terraform {
	required_providers {
		aws = {
			source  = "hashicorp/aws"
			version = "~> 5.0"
		}
	}
	required_version = ">= 1.6.0"
}

# ── Provider ─────────────────────────────────────────────────
provider "aws" {
	region = var.aws_region
}

# ── Variables ─────────────────────────────────────────────────
variable "aws_region" {
	description = "AWS region for all resources"
	type        = string
	default     = "us-east-1"
}

variable "lab_name" {
	description = "Name prefix for all lab resources"
	type        = string
	default     = "suricata-lab"
}

variable "debian_ami_id" {
	description = "Debian 13 AMI ID (official Debian publisher, us-east-1)"
	type        = string
	# Update this if the AMI changes — find current ID in AWS Marketplace
	# Publisher: Debian, search 'Debian 13' in AWS Marketplace AMIs
	default = "ami-0f9c27b471bdcd702"
}

variable "vpc_subnet_cidr" {
	description = "VPC subnet CIDR — used as HOME_NET in Suricata rules. Run 'ip route | grep enX0' inside the instance to find yours."
	type        = string
	default     = "172.31.16.0/20"
}

# ── IAM Role for EC2 (SSM access) ────────────────────────────
resource "aws_iam_role" "ssm_role" {
	name = "${var.lab_name}-ssm-role"

	assume_role_policy = jsonencode({
		Version = "2012-10-17"
		Statement = [{
			Effect    = "Allow"
			Principal = { Service = "ec2.amazonaws.com" }
			Action    = "sts:AssumeRole"
		}]
	})

	tags = {
		Name = "${var.lab_name}-ssm-role"
		Lab  = var.lab_name
	}
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
	role       = aws_iam_role.ssm_role.name
	policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_profile" {
	name = "${var.lab_name}-ssm-role"
	role = aws_iam_role.ssm_role.name
}

# ── Security Group — zero inbound ports ──────────────────────
resource "aws_security_group" "lab_sg" {
	name        = "${var.lab_name}-sg"
	description = "Lab security group - no inbound rules. SSM only needs outbound 443."

	# No ingress rules intentional — SSM Session Manager works over outbound HTTPS only

	egress {
		description = "Allow all outbound traffic"
		from_port   = 0
		to_port     = 0
		protocol    = "-1"
		cidr_blocks = ["0.0.0.0/0"]
	}

	tags = {
		Name = "${var.lab_name}-sg"
		Lab  = var.lab_name
	}
}

# ── User Data — bootstraps SSM Agent on first boot ───────────
locals {
	user_data = base64encode(<<-EOT
		#!/bin/bash
		apt-get update -y
		wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_amd64/amazon-ssm-agent.deb
		dpkg -i amazon-ssm-agent.deb
		systemctl enable amazon-ssm-agent
		systemctl start amazon-ssm-agent
	EOT
	)
}

# ── Launch Template ───────────────────────────────────────────
resource "aws_launch_template" "lab_template" {
	name        = "${var.lab_name}-template"
	description = "Debian 13 + SSM Agent via User Data"

	image_id      = var.debian_ami_id
	instance_type = "t2.micro"

	iam_instance_profile {
		name = aws_iam_instance_profile.ssm_profile.name
	}

	network_interfaces {
		associate_public_ip_address = true
		security_groups             = [aws_security_group.lab_sg.id]
		delete_on_termination       = true
	}

	user_data = local.user_data

	tag_specifications {
		resource_type = "instance"
		tags = {
			Name = "${var.lab_name}-instance"
			Lab  = var.lab_name
		}
	}

	tags = {
		Name = "${var.lab_name}-template"
		Lab  = var.lab_name
	}
}

# ── AWS Network Firewall Rule Group ──────────────────────────
# Stores the 7 Suricata rules as a reusable ruleset in AWS.
# Cost: $0.00 to store — charges only begin when a firewall
# endpoint is deployed (Week 49-50, Cloud Security Mastery).
resource "aws_networkfirewall_rule_group" "suricata_rules" {
	name        = "${var.lab_name}-rules"
	description = "Suricata IDS rules for SQL injection, port scan, C2 beaconing, and DNS tunneling detection"
	type        = "STATEFUL"
	capacity    = 100

	rule_group {
		# Define HOME_NET as the VPC subnet — matches suricata.yaml HOME_NET value
		rule_variables {
			ip_sets {
				key = "HOME_NET"
				ip_set {
					definition = [var.vpc_subnet_cidr]
				}
			}
		}

		rules_source {
			# All 7 rules from custom.rules — pass rules first, then alert rules.
			# Pass rules must come before alert rules so Suricata processes them
			# in order and whitelists legitimate AWS traffic before alerting on it.
			rules_string = <<-EOT
				pass http $HOME_NET any -> 169.254.169.254 any (msg:"IMDS traffic - whitelist"; sid:9000010; rev:1;)
				pass tcp $HOME_NET any -> any 443 (msg:"AWS HTTPS services whitelist"; sid:9000011; rev:1;)
				alert tcp any any -> $HOME_NET any (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
				alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Comment Bypass Attempt"; content:"OR"; nocase; content:"="; nocase; sid:9000002; rev:6;)
				alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; threshold:type threshold,track by_src,count 5,seconds 10; sid:9000003; rev:3;)
				alert tcp $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:2;)
				alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:2;)
			EOT
		}
	}

	tags = {
		Name = "${var.lab_name}-rules"
		Lab  = var.lab_name
	}
}

# ── Outputs ───────────────────────────────────────────────────
output "security_group_id" {
	description = "Security group ID — use in lab-restore fish function"
	value       = aws_security_group.lab_sg.id
}

output "launch_template_id" {
	description = "Launch template ID"
	value       = aws_launch_template.lab_template.id
}

output "launch_template_name" {
	description = "Launch template name — use in lab-create fish function"
	value       = aws_launch_template.lab_template.name
}

output "iam_instance_profile_name" {
	description = "IAM instance profile name"
	value       = aws_iam_instance_profile.ssm_profile.name
}

output "ssm_role_arn" {
	description = "SSM role ARN — use in iam:PassRole inline policy"
	value       = aws_iam_role.ssm_role.arn
}

output "network_firewall_rule_group_arn" {
	description = "Network Firewall rule group ARN — attach to a firewall policy to enforce rules"
	value       = aws_networkfirewall_rule_group.suricata_rules.arn
}
