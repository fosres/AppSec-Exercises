#!/usr/bin/bash

for i in $(seq 1 10); do
  echo "$(date -Iseconds) $(hostname) sshd[9999$i]: Failed password for invalid user admin from 192.168.1.100 port 2222$i ssh2" | sudo tee -a /var/log/auth.log
done
