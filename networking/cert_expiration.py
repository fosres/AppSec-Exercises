#/usr/bin/python3

"""
Certificate Expiration Checker - Security Engineering Exercise

TASK 3.1: Certificate Expiration Check
========================================
Create a script to check certificate expiration for any given hostname.

Requirements:
- Accept hostname as command-line argument
- Connect to hostname:443 using OpenSSL
- Extract certificate expiration date
- Display when the certificate expires
- Calculate days until expiration
- Handle errors gracefully (invalid hostnames, network failures, timeouts)

Security Considerations:
- MUST be resistant to OS Command Injection attacks
- Use subprocess with list form (NOT shell=True)
- Validate hostname input format
- Secure temporary file handling
- Proper error handling and cleanup

Learning Objectives:
- Understand TLS certificate validity periods
- Why certificate expiration monitoring is critical for production systems
- Prevent security incidents from expired certificates
- Build production-ready security tools with proper input validation

Context:
This exercise is from Week 2 of the Security Engineering Interview Preparation
curriculum, focusing on OpenSSL command-line tools and practical TLS/SSL analysis.

Author: Tanveer Salim (fosres)
Date: December 2025
Course: 48-Week Security Engineering Curriculum
Lab: Week 2 - OpenSSL HTTPS Security Analysis & Testing
"""

import sys
import subprocess


cert_chain = subprocess.run(["openssl","s_client","-connect",sys.argv[1]+":443","-servername",sys.argv[1]],capture_output=True,text=True)


file_name = "/tmp/cert_chain.txt"

with open(file_name,"w") as file:
	file.write(cert_chain.stdout)

subprocess.run(["openssl","x509","-noout","-dates","-in",file_name])
