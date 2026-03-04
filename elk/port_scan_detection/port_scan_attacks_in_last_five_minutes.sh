#!/usr/bin/bash

for port in 22 23 25 80 443 3306 5432 6379 8080 8443 27017 11211 6380 9200 5601 21 53; do
  echo "$(date -Iseconds) $(hostname) kernel: [123456.789] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=10.0.0.99 DST=192.168.1.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=$port WINDOW=1024 RES=0x00 SYN URGP=0" | sudo tee -a /var/log/ufw.log
done
