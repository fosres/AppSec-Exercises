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

You can tell there is a comment whenever there is a line that begins

with `#` character.

What are the flags that matter:

-A [FORWARD|INPUT|OUTPUT]

-s [cidr_subnet]

-j [ACCEPT|REJECT|DROP|RETURN]

-p [tcp|udp|icmp|ah|esp|all] (Only tcp and udp are concerned with ports)

--dport [port_num] ( Make sure its in a proper range :) )

Rules in different chains can never collide!

Make three separate lists for each chain for that reason.

Compare the currentmost rule you just saw to the rules in that chain

from top to bottom in that order!

--------------------------------------

0. Does the line begin with `#`? If so skip that line since it is

a comment.

1. So first parse for which chain [INPUT|OUTPUT|FORWARD]

	a. Ignore lines that do not have an append chain with

		the `-A` flag.

2. Next parse if the action is terminal [ACCEPT|REJECT|DENY]

	a. If so now we need to figure out if the CIDR, dport, and

		protocol in the current rule overlaps with that of any

		of the others in the list for said chain.

	NOTE: Its okay if a more narrow terminating rule is presented

	first. Its NOT okay if a broader terminating rule is presented

	first.

			0. If the CIDR, dport, and/or protocol are not

			specified for a rule assume the entire possible

			range for said value.

				A. An exception is `icmp` which does

				not consider dports at all!

			i. If so determine if identical to another rule
	
			(Duplicate)

			ii. If clashes ONLY with another existing 

			rule's action

			(Shadows)

			iii.  If clashes with another existing

			terminal rule

			(Conflict)

			YES its true Shadowing is Conflict but

			labeling done for pedagogical reasons.

3. If action for that role is not terminal move onto next line :)
