# Week 1: Wireshark Network Analysis Lab

**Course:** Security Engineering Curriculum  
**Lab Duration:** 2 hours  

---

## Lab Objectives

By completing this lab, you will:
- Install and configure Wireshark for packet capture
- Analyze HTTP, HTTPS, and DNS traffic at the packet level
- Identify and document TCP 3-way handshakes
- Use Wireshark display filters to isolate specific protocols
- Recognize network reconnaissance patterns (port scanning)
- Build foundational skills for Security Engineering interviews

---

## Prerequisites

Before starting this lab, ensure you have:
- [ ] Completed Omnisecu TCP/IP Model readings
- [ ] Read High Performance Browser Networking Chapters 1-3
- [ ] Understanding of OSI Model (all 7 layers)
- [ ] Familiarity with TCP vs UDP concepts
- [ ] **Firefox browser installed** (required for HTTP capture - Chrome/Brave will redirect to HTTPS)

---

## Part 1: Installation and Setup (15 minutes)

### Step 1.1: Install Wireshark

**Task:** Download and install Wireshark on your system.

**Instructions:**
1. Visit: https://www.wireshark.org/download.html
2. Download the appropriate version for your operating system
3. Install Wireshark with default settings
4. Install WinPcap/Npcap when prompted (required for packet capture)

**Installation verified:** [X] Yes [ ] No

### Step 1.2: Install Firefox Browser

**Task:** Install Firefox browser for HTTP traffic capture.

**Instructions:**
1. Visit: https://www.mozilla.org/firefox/
2. Download and install Firefox
3. **Why Firefox?** Chrome and Brave automatically redirect HTTP to HTTPS for many sites, making it impossible to capture plain HTTP traffic for this lab.

**Firefox installed:** [X] Yes [ ] Already have it

**Notes/Issues encountered:**
```


```

---

## Part 2: HTTP Traffic Capture and Analysis (30 minutes)

### Step 2.1: Capture HTTP Traffic

**Task:** Capture unencrypted HTTP traffic by visiting http://neverssl.com

**Instructions:**
1. Launch Wireshark
2. Select your active network interface (usually Wi-Fi or Ethernet)
3. Click the blue shark fin icon to start capturing
4. **Open Firefox browser** (Chrome and Brave will redirect to HTTPS)
5. **CRITICAL:** In the URL bar, manually type the FULL URL including `http://`:
   ```
   http://neverssl.com
   ```
   - **Do NOT** type just "neverssl.com" (browser may redirect to HTTPS)
   - **Do NOT** click a hyperlink to the site
   - **You MUST manually type** `http://neverssl.com` in the address bar
   - **You MUST use Firefox** (not Chrome, Brave, or Safari)
6. Wait for the page to fully load
7. Return to Wireshark and click the red square to stop capture
8. Save your capture: File → Save As → `http_neverssl.pcap`

**Capture completed:** [ ] Yes [ ] No

**Capture completed:** [ ] Yes [ ] No

### Step 2.2: Apply HTTP Display Filter

**Task:** Filter the capture to show only HTTP traffic.

**Instructions:**
1. In the display filter bar (top of Wireshark), type: `http`
2. Press Enter
3. Observe the filtered packets

**Question 1:** How many HTTP packets did you capture?

**Answer:**
```
14 HTTP packets captured
```

### Step 2.3: Analyze HTTP GET Request

**Task:** Find and analyze the HTTP GET request packet.

**Instructions:**
1. Locate a packet with "GET / HTTP/1.1" in the Info column
2. Click on that packet to select it
3. Expand the "Hypertext Transfer Protocol" section in the middle pane

**Question 2:** What is the HTTP request method and URI?

**Answer:**
```
GET / HTTP/1.1
```

**Question 3:** What is the User-Agent string in the HTTP request?

**Answer:**

```
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
```

### Step 2.4: Analyze HTTP Response

**Task:** Locate the corresponding HTTP 200 OK response.

**Instructions:**
1. Find the packet with "HTTP/1.1 200 OK" in the Info column
2. Expand the "Hypertext Transfer Protocol" section

**Question 4:** What is the Content-Type of the response?

**Answer:**
```
Content-Type: text/html; charset=UTF-8
```

**Question 5:** What is the Server header value?

**Answer:**
```
Server: Apache/2.4.62 ()
```

---

## Part 3: TCP 3-Way Handshake Analysis (30 minutes)

### Step 3.1: Identify SYN Packet

**Task:** Find the initial SYN packet that starts the TCP connection to neverssl.com.

**Instructions:**
1. Clear the HTTP filter
2. Apply the filter: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
3. Find the SYN packet going to neverssl.com (destination port 80)
4. Click on the packet to select it

**Question 6:** What is the source port number of the SYN packet?

**Answer:**
```
Source Port Number: 33198

```

**Question 7:** What is the initial sequence number (ISN) in the SYN packet?

**Answer:**
```
2206820284
```

### Step 3.2: Identify SYN-ACK Packet

**Task:** Find the SYN-ACK response from the server.

**Instructions:**
1. Apply the filter: `tcp.flags.syn == 1 && tcp.flags.ack == 1`
2. Locate the response from neverssl.com's IP address

**Question 8:** What is the sequence number in the SYN-ACK packet?

**Answer:**
```
Sequence Number: 2466142114
```

**Question 9:** What is the acknowledgment number in the SYN-ACK packet?

**Answer:**
```
(Hint: It should be the client's ISN + 1)

Ack Number: 3938739061 (No it was not client's ISN + 1).
```

### Step 3.3: Identify ACK Packet

**Task:** Find the final ACK that completes the 3-way handshake.

**Instructions:**
1. Clear all filters
2. Look for the next packet after the SYN-ACK
3. It should have only the ACK flag set

**Question 10:** What is the acknowledgment number in the final ACK packet?

**Answer:**
```
Time: 5.6581..
(Hint: It should be the server's ISN + 1)

2466142115
```

### Step 3.4: Document the Complete Handshake

**Task:** Create a diagram of the TCP 3-way handshake you observed.

**Diagram:**
```
Client (IP: 192.168.8.133 [Private]) → Server (IP: 34.223.124.45)

1. SYN: Seq=2206820284, Flags=[SYN]

2. SYN-ACK: Seq=2466142114, Ack=3938739061, Flags=[SYN, ACK]

3. ACK: Seq=3938739061, Ack=2466142115, Flags=[ACK]

Connection Established ✓
```

---

## Part 4: HTTPS and TLS Handshake (20 minutes)

### Step 4.1: Capture HTTPS Traffic

**Task:** Capture encrypted HTTPS traffic.

**Instructions:**
1. Start a new capture in Wireshark
2. Open your browser and visit: `https://example.com`
3. Stop the capture after the page loads
4. Save as: `https_example_com.pcap`

**Capture completed:** [X] Yes [ ] No

### Step 4.2: Observe TLS Handshake

**Task:** Identify the TLS/SSL handshake packets.

**Instructions:**
1. Apply filter: `tls.handshake.type == 1`
2. This shows the "Client Hello" packet

**Question 11:** Can you read the actual HTTP data in the HTTPS capture? Why or why not?

**Answer:**
```
No, almost the entire text is illegible binary raw data because it is

encrypted.
```

**Question 12:** What TLS/SSL version is being used?

**Answer:**
```
(Hint: Look in the "Secure Sockets Layer" → "Handshake Protocol: Client Hello")
TLSv1.3
```

---

## Part 5: DNS Traffic Analysis (15 minutes)

### Step 5.1: Capture DNS Query

**Task:** Capture DNS resolution for google.com.

**Instructions:**
1. Start a new capture
2. Open command prompt/terminal
3. Run: `nslookup google.com`
4. Stop the capture
5. Save as: `dns_google.pcap`

**Capture completed:** [X] Yes [ ] No

### Step 5.2: Analyze DNS Query

**Task:** Find and analyze the DNS query packet.

**Instructions:**
1. Apply filter: `dns`
2. Find the query packet (where Info shows "Standard query")

**Question 13:** What is the DNS query name?

**Answer:**
```
google.com
```

**Question 14:** What type of DNS record is being requested (A, AAAA, MX, etc.)?

**Answer:**
```
A
```

### Step 5.3: Analyze DNS Response

**Task:** Examine the DNS response packet.

**Instructions:**
1. Find the corresponding response packet
2. Expand "Domain Name System (response)" section

**Question 15:** What IP address(es) were returned for google.com?

**Answer:**
```
142.250.188.238
```

**Question 16:** What is the TTL (Time To Live) value for the A record?

**Answer:**
```
64
```

---

## Part 6: Display Filters Practice (10 minutes)

### Step 6.1: TCP Filter

**Task:** Apply a filter to show only TCP traffic.

**Filter used:** `tcp`

**Question 17:** Approximately how many TCP packets are in your HTTP capture?

**Answer:**
```
14 TCP packets

```

### Step 6.2: Specific DNS Query Filter

**Task:** Filter to show DNS queries containing "google".

**Filter used:** `dns.qry.name contains "google"`

**Question 18:** Did this filter successfully isolate Google DNS queries?

**Answer:**
```
Yes!

```

### Step 6.3: Port-Based Filter

**Task:** Show only traffic on port 80 (HTTP).

**Filter used:** `tcp.port == 80`

**Question 19:** What is the difference between using `http` vs `tcp.port == 80` as a filter?

**Answer:**
```
Just to let you know there were no packets for neither `http` nor

for `tcp.port == 80`. So to answer the question when filtering for

port 80 Wireshark specifically filters for packets sent/received

from TCP port 80. But when filtering for `HTTP` Wireshark filters

for packets that are formatted under the HTTP protocol standard--which

in theory can be from any port but usually are to/from ports 80/8080. 
```

---

## Part 7: Sample PCAP Analysis (20 minutes)

### Step 7.1: Download Sample PCAP

**Task:** Download a sample PCAP file for analysis.

**Instructions:**
1. Visit: https://wiki.wireshark.org/SampleCaptures
2. Download: `http.cap` or similar sample file
3. Open the file in Wireshark

**Sample file downloaded:** [ ] Yes [ ] No

**Filename:** _________________

### Step 7.2: Evidence of Port Scanning

**Task:** Look for indicators of port scanning activity.

**Instructions:**
1. Look for patterns like:
   - Many TCP SYN packets to sequential ports
   - Packets to the same destination IP on many different ports
   - TCP RST responses indicating closed ports

**Question 20:** Did you find evidence of port scanning? If yes, describe what you observed.

**Answer:**
```
First, let me say that I am observing the results of the

`nmap_standard_scan` that you can download from WireShark's Sample

Captures page (link:
https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/NMap-Captures.zip)
```
I clearly the same source IP address: 192.168.100.103 constantly

send SYN packets to the same destination IP address (192.168.100.102)

under various different ports--a dead giveaway of a port scan.

Both IP addresses are in the same Local Area Network since they

are both Class C Private IP Addresses.

### Step 7.3: Identify HTTP Requests

**Task:** Find all HTTP requests in the sample capture.

**Instructions:**
1. Apply filter: `http.request`
2. Count the number of HTTP requests

**Question 21:** How many HTTP GET requests are in the sample file?

There are no sample HTTP requests in the sample capture for

`nmap_standard_scan`. For the sake of this exercise let me use

another sample capture from Wireshark's website: `http.cap`

**Answer:**
```
2 packets for HTTP GET requests are in the sample file.
```

**Question 22:** List 3 different HTTP methods found in the capture:

**Answer:**
```
1. Only GET found
2. 
3. 
```

### Step 7.4: Identify DNS Queries

**Task:** Find all DNS queries in the sample file.

**Instructions:**
1. Apply filter: `dns.flags.response == 0`
2. List the domains being queried

**Question 23:** List at least 3 domain names that were queried:

**Answer:**
```
For the sake of this exercise I downloaded and inspected the

SkypeIRC.cap

There are so many domains that I will list a few of them here.

1. ui.skype.com
2. oharel.stat.uconn.edu 
3. Torik16R1.opoy.net
```

---

## Part 8: Security Mindset Questions (10 minutes)

### Question 24: Attack Surface Analysis

Based on your HTTP capture, what information could an attacker learn about your system from the HTTP headers?

**Answer:**
```

After analyzing HTTP headers from the `http.cap` file:

An attacker can learn what port(s) are open for HTTP connections.

The attacker can also learn for how long connections are kept alive.

If kept alive for too long an attacker can attempt a denial of service

attack known as the Slow Loris attack.

The attacker can also learn what encodings the HTTP server accepts

for information (e.g. text/plain or text/html, etc.)
```

### Question 25: Reconnaissance Detection

How could you use Wireshark to detect if someone is performing reconnaissance on your network?

**Answer:**
```
Check if the same source IP address is sending SYN packets to  multiple

ports on the same destination machines on my network. That is

suspicious activity of port scanning.

Also check if the same source IP address is making multiple requests

within very short intervals.


```

### Question 26: Encryption Importance

Why is it critical to use HTTPS instead of HTTP for sensitive transactions? Use evidence from your captures.

**Answer:**
```
From Part 4 after I captured HTTPS traffic to example.com I noticed

I couldn't read packets because they were encrypted! This explains

why HTTPS is so important--it hides sensitive info clients might

send to servers such as credit card details.
```

---

## Lab Deliverables Checklist

Before submitting, ensure you have:

- [ ] All questions answered completely
- [ ] All PCAP files saved:
  - [ ] `http_neverssl.pcap`
  - [ ] `https_example_com.pcap`
  - [ ] `dns_google.pcap`
- [ ] TCP 3-way handshake diagram completed
- [ ] Security mindset questions answered with specific examples

---

## Additional Resources

For reference while completing this lab:

1. **Wireshark Display Filter Reference:** https://www.wireshark.org/docs/dfref/
2. **Omnisecu TCP/IP Tutorial:** https://www.omnisecu.com/tcpip/
3. **HPBN Chapter 2 (TCP):** https://hpbn.co/building-blocks-of-tcp/
4. **Beej's Guide to Network Programming:** https://beej.us/guide/bgnet/

---

## Grading Rubric

| Category | Points | Description |
|----------|--------|-------------|
| Installation & Setup | 10 | Wireshark properly installed and configured |
| HTTP Analysis | 20 | Correct identification of HTTP packets and headers |
| TCP Handshake | 25 | Complete documentation of 3-way handshake with correct sequence/ack numbers |
| HTTPS/TLS Analysis | 15 | Correct identification of TLS handshake and understanding of encryption |
| DNS Analysis | 15 | Accurate DNS query/response analysis |
| Sample PCAP Analysis | 10 | Correct identification of port scanning, HTTP requests, DNS queries |
| Security Mindset | 5 | Thoughtful answers demonstrating security awareness |
| **Total** | **100** | |

---

## Notes Section

Use this space for any additional observations, challenges encountered, or questions that arose during the lab:

```
Sequence Numbers were not as expected for SYN-ACK packets versus

initial Sequence Numbers.

Sometimes less variation of packets were found (e.g. less HTTP

Request Methods than what the question expected).
```

---

**Source References:**
- Week_1_Networking_Study_Guide.pdf, Section 5 "Week 1 Study Schedule"
- Complete_48_Week_Security_Engineering_Curriculum_All_Weeks.pdf, Page 2 "Week 1: Networking Fundamentals"

**Lab Version:** 1.0  
**Last Updated:** December 2025
