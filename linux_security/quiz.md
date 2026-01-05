1. A)

2. The binary program has the user-owner `setuid` bit activatated for

the executable space in its ACL. That means even if a non-root

user runs the executable it run with root privileges! Not good.

The program can access and edit *any* file in the computer!

Reference: https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits

3. I would use:

```
systemctl --type=service --state=running
```

To disable `telnet` from starting on boot:

```
systemctl disable telnet
```

4. A)

One can install `unattended-upgrades` package by doing:

```
sudo apt install unattended-upgrades
```

One can next ensure the service is active by doing:

```
systemctl status unattended-upgrades
```

And ensuring the service has status `active`

B) 

There are techniques to whitelist and blacklist which

software repositories are allowed to be updated--mitigating the

risk of downloading malicious software.

For example, the "Allowed Origins" feature specifies which software

repos can be automatically updated through the `unattended-upgrades`

feature.

One can also use the `Package-Blacklist` feature to prevent specific

packages from being automatically updated.

The sysadmin can receive automatic email updates from the server

about updates by configuring the `Unattended-Upgrade::Mail` feature.

https://itsfoss.gitlab.io/post/install-updates-and-security-patches-automatically-in-ubuntu/
5. It is very dangerous to allow a root user-owner program to

speak to the public Internet. And attacker can launch an exploit

such as remote code execution through a root program operating on

port 80. Its true port 80 requires sudo privileges. Instead of doing

that you can instead run the program on port 8080 instead--which

does not require superuser privileges.

6. 
