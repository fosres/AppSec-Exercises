This archive contains some Wireshark captures of various port scans done with nmap.
Wireshark was configured to capture everything. It was done from the target with interface in promiscuous mode.


-nmap_standard_scan
This scan is done with the default nmap settings.
Command: 
	nmap 192.168.100.102

-nmap_ACK_scan_on_port_80
This is a simple ACK scan on port 80 skipping the ping scan for checking if host is alive.
Command: 
	nmap -p80 -sA -Pn 192.168.100.102

-nmap_ACK_scan_on_port_80
This is an ACK scan on port 80 using fragmentation and spoofing our IP address to evade IDS.
Notice how our scan seems to be coming from a different IP than ours.
Command:
	nmap -p80 -sA -Pn -f -S 192.168.100.101 -e eth0 192.168.100.102

-nmap_zombie_scan
This is a zombie scan on port 80. For the target (192.168.100.102) it appears as if 192.168.100.101 (the zombie) was doing the scanning.
This keeps us (192.168.100.103) invisible but the communication between us and our zombie is pretty "noisy".
Some requirements for this scan is that the zombie is online, idle and has a port which responds to probing so we can use(in this case 2869)
Command:
	nmap -p80 -Pn -sI 192.168.100.101:2869 192.168.100.102

-nmap_OS_scan
This is a failed OS scan against our target. For an OS scan to be succesful there needs to be at least one closed port and one open port.
Our target had only filtered ports.
Command:
	nmap -O -Pn 192.168.100.102

-nmap_OS_scan_suucesful
This is a succesful OS scan against a target which has one open port and one closed port.
Command:
	nmap -O -Pn 192.168.100.101
