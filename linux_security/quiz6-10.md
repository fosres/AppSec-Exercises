6.

A) 

Configure the `sshd_config` file

B)

Configuration lines for `sshd_config`:

```
Port 2222

PermitRootLogin no

PasswordAuthentication no

PubkeyAuthentication yes

# I would next configure the location of authorized_keys:

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

```

To apply these changes:

```
sudo systemctl restart sshd
```

7.

A) Brute-force login attempt

B) `fail2ban` can ban the IP Address the attacker is using to attempt

to login

Below is a sample command the sysadmin can use:

```
fail2ban-client set sshd banip 192.168.1.100
```

C) The sysadmin can check banned IPs using the following command:

```
fail2ban-client status sshd
```

8.

A)

```
find / -perm /4000
```

B)

With all fairness there is not enough info to answer this question.

The first thing that must be done is to discuss what should be

done with the file. No matter what decision is made it is not okay

to leave the file as is in the machine since any user that executes

the file, even if not root user, will cause the file to have root

privileges (the script can edit and/or execute any file!).

C) As mentioned earlier an attacker can execute the file and said

executable will have root user privileges.

9. A) Do I actually have enough info to answer this question.

Which groups exist or are allowed by organization?

B) I admit I am not sure.

C) Not sure either

10.

A) `find . -type f -mmin -1440`

B)

Three possible locations:

```
/var/spool/cron/crontabs/  
```

```
/var/spool/cron/crontabs/root  
```


Here are more:

```
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
```
