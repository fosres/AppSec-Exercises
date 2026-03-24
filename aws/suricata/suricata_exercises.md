Exercise 1:

1. HTTP protocol

2. Traffic flows from Public Internet to Home Network.

3. The Suricata rule is looking for the existence of an 

XSS payload within the submitted URL. That is what the `http_uri`

represents: the submitted URL. Judging by the filtering for the

`<script>` tag the computer is looking for XSS attacks targeting

HTML bodies or HTML attributes.

4. See previous answer.

5. The attacker can apply percent encoding to evade this rule.

Exercise 2:

Solution:

```
alert tcp any any -> $HOME_NET 1:1024 (msg:"Possible Port Scan
Detected"; flags:S; threshold:type threshold,track by_src,count 50,seconds 10; sid:9000003; rev:4;)
```

Exercise 3:

1. Here is the rule shown disabled:

```
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection UNION SELECT Attempt"; content:"UNION"; nocase; content:"SELECT"; nocase; sid:9000001; rev:4;)
# alert http $HOME_NET any -> any any (msg:"Possible C2 Beaconing Detected"; flow:to_server,established; threshold:type both,track by_src,count 10,seconds 60; sid:9000004; rev:1;)
alert udp any any -> any 53 (msg:"Possible DNS Tunneling - Large Query"; dsize:>200; sid:9000005; rev:1;)
```

So as a note I decided to use `systemctl restart suricata` because

there is no point in doing this in a way that is more complicated.

To check if the false positives no longer exist check the logs:

```
ssm-user@ip-172-31-25-36 ~> sudo systemctl restart suricata
ssm-user@ip-172-31-25-36 ~> sudo truncate -s 0 /var/log/suricata/fast.log
ssm-user@ip-172-31-25-36 ~> sudo cat /var/log/suricata/fast.log
```

Since there was no output called "Possible C2 Beaconing Detected"

the above tactic worked.

Exercise 4:

1. "Only fires after 20 matching packets from the same source in 10
seconds" 

count 5,seconds 10

2. Makes string matching case-insensitive

nocase

3. Restricts the rule to outbound traffic from your subnet:

pass tcp $HOME_NET any -> any any

4. Ensures a second content match starts immediately after the first with zero bytes between them

distance:0

5. Matches UDP packets larger than 200 bytes

alert udp any any -> (... dsize:>200)

6. Only applies to established TCP connections flowing toward the server

alert tcp any any -> ... flow:to_server,established;

7. Allows matching traffic to pass without triggering any alert rules below it

One must make a rule at the top of the suricata rules file

that uses the `pass` keyword.

Exercise 5:

Part 1. 

There are 22 rules:

```
root@ip-172-31-24-247:~# suricata-update list-sources | grep -i "Name"
Name: et/open
Name: et/pro
Name: oisf/trafficid
Name: scwx/enhanced
Name: scwx/malware
Name: scwx/security
Name: abuse.ch/sslbl-blacklist
Name: abuse.ch/sslbl-ja3
Name: abuse.ch/feodotracker
Name: abuse.ch/urlhaus
Name: etnetera/aggressive
Name: tgreen/hunting
Name: stamus/lateral
Name: stamus/nrd-30-open
Name: stamus/nrd-14-open
Name: stamus/nrd-entropy-30-open
Name: stamus/nrd-entropy-14-open
Name: stamus/nrd-phishing-30-open
Name: stamus/nrd-phishing-14-open
Name: pawpatrules
Name: ptrules/open
Name: aleksibovellan/nmap
```

Part 4.

There are 6 rules. Here is the CLI output:

```
root@ip-172-31-24-247:~# sudo grep "signatures processed" /var/log/suricata/suricata.log | tail -1
[875 - Suricata-Main] 2026-03-21 18:31:15 Info: detect: 6 signatures processed. 1 are IP-only rules, 2 are inspecting packet payload, 1 inspect application layer, 0 are decoder event only```

Part 5.

```
root@ip-172-31-24-247:~# grep -i "sql injection" /var/lib/suricata/rules/suricata.rules | wc -l
4361
```

So the answer is 4361 rules.

Reflection:

1. The first consequence in using a community ruleset is that it

becomes difficult, if not impossible, for each individual to audit

and verify the correctness of all rules. The community ruleset

for Exercise 5 Part 5 itself already has 4361 rules--which cannot

be audited by a person in one day. The benefit is that one can rely

on someone else for features but if the ruleset is too large the

user must question if said person can be trusted with devising

a secure, responsible ruleset. Another great lesson that reminds

us of the lesson of Thompson's "Reflections on Trusting Trust"

An alternative is to build your own rules from scratch--but having

comprehensive features will take more time than using a community

pre-published ruleset.
