## Focused Quiz - Critical Misconceptions Only

**Email Protocol Misconception:**

1. True or False: IMAP can send emails.

False

2. True or False: SMTP can receive emails.

False

3. Which protocol is used to SEND emails from your client to a mail server?
   a) POP3
   b) IMAP
   c) SMTP
   d) SSH

C) SMTP

4. Which protocols are used to RECEIVE emails from a mail server? (Select all that apply)
   a) SMTP (port 25)
   b) POP3 (port 110)
   c) IMAP (port 143)
   d) All of the above

B) and C)

5. Fill in the blanks:
   - To SEND an email: Use SMTP protocol on port 25
   - To RECEIVE an email: Use POP3 or IMAP protocols on ports 110 (POP3) or 143
     (IMAP)
6. Complete the email flow:
```
   SENDING: Your client → SMTP (port 25) → Mail server
   RECEIVING: Your client ← POP3 or IMAP (port 110 or 143) ← Mail server
```

7. Your company email uses port 25 for outgoing mail and port 143 for incoming mail. 
   - Outgoing uses: SMTP protocol
   - Incoming uses: IMAP protocol

**nmap State Misconception:**

8. You run `nmap -p 3389 10.0.0.5` and get "3389/tcp closed"
   What does this mean?
   a) RDP service is running but refusing connections
   b) Nothing is listening on port 3389
   c) A firewall is blocking the scan
   d) The RDP service crashed

B)

9. Which nmap state indicates "nothing is listening on this port"?
   a) open
   b) closed
   c) filtered
   d) refused

B)

10. You're securing a server. You run nmap and see "23/tcp closed" for Telnet. Is this good or bad?
    - Good or Bad: Good
    - Why: Telnet (Port 23) should be closed meaning nothing is

listening at that port. Telnet is not secure for communication

11. Match each scenario to the correct nmap state:
    - SSH service is running and accepting connections: open
    - Nothing is listening on the port, host responded with RST: closed
    - Firewall dropped the packet, nmap can't tell: filtered
    
    Options: open, closed, filtered

12. True or False: If nmap shows "closed", you should investigate because something suspicious is happening.

False

13. Rank these nmap states from MOST secure to LEAST secure:
    closed → filtered → open
    
    Options: open, closed, filtered

14. You scan port 22 on three servers:
    - Server A: "22/tcp open"
    - Server B: "22/tcp closed"  
    - Server C: "22/tcp filtered"
    
    Which server has SSH definitely NOT running?

Server B
