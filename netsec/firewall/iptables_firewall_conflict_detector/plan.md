We have to evaluate the rules from top to bottom just as a real

firewall would every time we are considering a new rule.

You really do need to append these rules to a list to maintain that

order.

Originally I was planning on organizing the rules from lowest to

highest subnet but instead we will just review the rules from top to

bottom.

So we will still use the dict structure but only to organize

info.

Shadow takes place when a packet will be terminated by a previous rule.

Conflict takes place when CIDR subnet, protocol, and port are same

--just policy differs from another.
