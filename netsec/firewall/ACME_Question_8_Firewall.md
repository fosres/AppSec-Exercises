# ACME Product Security Tech Test — Question 8

## Scenario

The engineering team decides to add a local iptables firewall to their file server, but it is misconfigured and they are now unable to access the server as expected. They ask you for help.

## Network Configuration

```
                    192.168.1.1      104.44.226.100
┌────────────┐               ┌────────────┐              ┌────────────┐              ┌────────────────┐
│            │               │            │              │            │              │                │
│   Client   ├───────────────┤ Router/NAT ├──────────────┤   Router   ├──────────────┤  File Server/  │
│            │               │            │              │            │              │ Local Firewall │
└────────────┘               └────────────┘              └────────────┘              └────────────────┘
192.168.1.145                                   104.44.226.150     20.141.12.1          20.141.12.34
```

## Server Firewall Rules

```
Chain INPUT (policy DROP)
target    prot   opt    source           destination
ACCEPT    all     --    anywhere         anywhere       ctstate RELATED,ESTABLISHED
ACCEPT    tcp     --    anywhere         20.141.12.34   tcp dpt:https
ACCEPT    tcp     --    192.168.1.145    20.141.12.34   tcp dpt:ssh

Chain OUTPUT (policy ACCEPT)
target    prot   opt    source           destination
ACCEPT    all     --    anywhere         anywhere       ctstate ESTABLISHED
```

---

## Questions

### Question 8a: The client is unable to ping the server. What firewall misconfiguration exists? How would you fix it?

Insert your answer here: There is no iptables rule under the INPUT

chain allowing the File Server to accept `icmp` packets. The following

iptables rule must be done to add the rule:

```
iptables -A INPUT -p icmp -s 104.44.226.100 -d 20.141.12.34 -j ACCEPT 
```

---

### Question 8b: The client is unable to SSH to the server. What firewall misconfiguration exists? How would you fix it?

Insert your answer here:

The problem with the following rule is that it accepts incoming

connections from a private IP address that exists in a Local

Area Network outside of the File Server:

```
ACCEPT    tcp     --    192.168.1.145    20.141.12.34   tcp dpt:ssh
```

The above rule must be replaced with:

```
ACCEPT    tcp     --    104.44.226.100    20.141.12.34   tcp dpt:ssh
```


---

## Your Solution

```bash
# Your corrected iptables rules here:

iptables -F

iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p icmp -s 104.44.226.100 -d 20.141.12.34 -j ACCEPT 

iptables -A INPUT -p tcp -s 104.44.226.100 -d 20.141.12.34 --dport ssh -j ACCEPT 

iptables -A INPUT -p tcp -d 20.141.12.34 --dport https -j ACCEPT 
```
