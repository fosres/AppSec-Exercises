#!/usr/bin/bash

mkdir -p ~/log_lab
cat > ~/log_lab/auth.log << 'EOF'
Jan 5 14:22:01 server sshd[4521]: Failed password for root from 45.33.32.156 port 52341
Jan 5 14:22:03 server sshd[4522]: Failed password for root from 45.33.32.156 port 52342
Jan 5 14:22:05 server sshd[4523]: Failed password for admin from 45.33.32.156 port 52343
Jan 5 14:22:07 server sshd[4524]: Failed password for root from 192.168.1.100 port 52344
Jan 5 14:22:09 server sshd[4525]: Failed password for ubuntu from 10.0.0.50 port 52345
Jan 5 14:22:11 server sshd[4526]: Failed password for root from 45.33.32.156 port 52346
Jan 5 14:22:13 server sshd[4527]: Failed password for admin from 10.0.0.50 port 52347
Jan 5 14:22:15 server sshd[4528]: Failed password for root from 45.33.32.156 port 52348
Jan 5 14:22:17 server sshd[4529]: Accepted password for admin from 192.168.1.1 port 52349
Jan 5 14:22:19 server sshd[4530]: Failed password for root from 45.33.32.156 port 52350
EOF

