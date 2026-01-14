# Exercise 4: C Language Security Audit - Network Packet Parser

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 47-49 (Buffer overflows, memory safety)  
**Focus**: Pure C language vulnerabilities (NO application logic)

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 20 minutes

---

## Scenario

You are reviewing a network packet parser. The code reads binary network packets and extracts header information.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024

typedef struct {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	uint8_t *payload;
} Packet;

Packet *parse_packet(uint8_t *buffer, size_t buf_len) {

	// No check if buf_len == 0

	// No check if malloc() yields NULL

	Packet *pkt = (Packet *) malloc(sizeof(Packet));
	
	// Read header fields
	pkt->version = buffer[0];
	pkt->type = buffer[1];
	
	// below 0 <= packet->length <= 65535

	pkt->length = (buffer[2] << 8) | buffer[3]; 
	
	// No check if pkt->length > buf_len  - 4; data overflow
	
	// Allocate and copy payload

	// No check if malloc() yields NULL

	pkt->payload = (uint8_t *) malloc(pkt->length);

	// potential data overflow below

	memcpy(pkt->payload, buffer + 4, pkt->length); 
	
	return pkt;
}

void process_packets(uint8_t *data, size_t total_len) {
	size_t offset = 0;
	
	while (offset < total_len) {

		// NO check for parse_packet() returning NULL pointer
		// below

		Packet *pkt = parse_packet(data + offset, total_len - offset);
		
		printf("Packet type: %d\n", pkt->type);
		
		// Move to next packet
		offset += 4 + pkt->length;
		
		free(pkt->payload);
		free(pkt);
	}
}

int main() {
	uint8_t data[] = {
		0x01, 0x02, 0x00, 0x05,  // version=1, type=2, length=5
		0x41, 0x42, 0x43, 0x44, 0x45,  // payload: "ABCDE"
		0x01, 0x03, 0xFF, 0xFF,  // version=1, type=3, length=65535
		0x46, 0x47, 0x48  // payload: "FGH" (incomplete!)
	};
	
	process_packets(data, sizeof(data));
	
	return 0;
}
```

---

## Questions

### **4a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class (use CWE numbers if you know them)
- Explain the root cause
- Describe potential impact

**Focus on C language issues:**
- Memory safety bugs
- Pointer arithmetic errors
- Type handling issues
- Bounds checking failures
- Uninitialized data access

---

### **4c. Mitigations** (10 points)

Propose secure alternatives for this code. Address:
- Buffer bounds validation
- Integer overflow in length calculations
- Pointer arithmetic safety
- Memory allocation validation

**Your rewritten code should:**
- Validate buffer bounds before all reads
- Check for integer overflow in calculations
- Validate malloc return values
- Handle truncated/malformed packets safely

Write your complete secure implementation below:

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 1024

typedef struct {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	uint8_t *payload;
} Packet;

Packet *parse_packet(uint8_t *buffer, size_t buf_len) {

	if ( buf_len < 4 )
	{
		fprintf(stderr,"Error: buf_len < 4\n");

		return NULL;
	}

	// No check if malloc() yields NULL

	Packet *pkt = (Packet *) malloc(sizeof(Packet));

	if ( pkt == NULL )
	{
		fprintf(stderr,"Error: pkt == NULL\n");

		return NULL;
	}
	
	// Read header fields
	pkt->version = buffer[0];
	pkt->type = buffer[1];
	
	// below 0 <= packet->length <= 65535

	pkt->length = (buffer[2] << 8) | buffer[3]; 
	
	// No check if pkt->length > buf_len - 4; data overflow

	if ( pkt->length > buf_len - 4 )
	{
		fprintf(stderr,"Error: Data is too large for packet\n");

		free(pkt);

		return NULL;
	}
	
	// Allocate and copy payload

	// No check if malloc() yields NULL

	pkt->payload = (uint8_t *) malloc(pkt->length);
	
	if ( pkt->payload == NULL )
	{
		fprintf(stderr,"Error: pkt == NULL\n");

		free(pkt);

		return NULL;
	}

	memcpy(pkt->payload, buffer + 4, pkt->length); 
	
	return pkt;
}

void process_packets(uint8_t *data, size_t total_len) {
	size_t offset = 0;
	
	while (offset < total_len) {
		
		Packet *pkt = parse_packet(data + offset, total_len - offset);

		if ( pkt == NULL )
		{
			fprintf(stderr,"Error: parse_packet() returns NULL\n");

			return;
		}
		
		printf("Packet type: %d\n", pkt->type);
		
		// Move to next packet
		offset += 4 + pkt->length;
		
		free(pkt->payload);
		free(pkt);
	}
}

int main() {
	uint8_t data[] = {
		0x01, 0x02, 0x00, 0x05,  // version=1, type=2, length=5
		0x41, 0x42, 0x43, 0x44, 0x45,  // payload: "ABCDE"
		0x01, 0x03, 0xFF, 0xFF,  // version=1, type=3, length=65535
		0x46, 0x47, 0x48  // payload: "FGH" (incomplete!)
	};
	
	process_packets(data, sizeof(data));
	
	return 0;
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- Buffer bounds checking
- Integer overflow in size calculations
- Pointer arithmetic rules
- Memory allocation failures
- Reading beyond buffer boundaries
- Off-by-one errors

---

## Grading Rubric

### 4a. Vulnerability Identification (5 points)
- **1 point**: Identified buffer over-read in parse_packet
- **1 point**: Identified integer overflow in offset calculation
- **1 point**: Identified missing malloc validation
- **1 point**: Identified missing buffer bounds check before memcpy
- **1 point**: Clearly explained root causes and impacts

### 4c. Mitigations (10 points)
- **3 points**: Validates buffer bounds before all reads
- **2 points**: Checks for integer overflow in offset calculations
- **2 points**: Validates all malloc return values
- **2 points**: Handles truncated packets safely
- **1 point**: Code is clean and compiles

---

## Hints About The Vulnerabilities

This code has **PURE C LANGUAGE BUGS**:

1. **Buffer over-read**: Reading `buffer[0..3]` without checking `buf_len`
2. **Integer overflow**: `offset += 4 + pkt->length` can overflow
3. **Unchecked malloc**: `malloc()` returns NULL on failure
4. **Memcpy bounds**: `memcpy()` reads past buffer end if packet is truncated
5. **Missing length validation**: No check if `pkt->length` exceeds buffer

**NO application logic issues** - these are all C language mechanics!

---

## References

**Primary Sources**:
- *API Security in Action* by Neil Madden, Chapter 2, pp. 47-49
- CWE-125: Out-of-bounds Read
- CWE-190: Integer Overflow or Wraparound
- CWE-787: Out-of-bounds Write
- CWE-476: NULL Pointer Dereference

**Additional Reading**:
- *Secure by Design*, Chapter 5 - Safe integer arithmetic
- CERT C Coding Standard: ARR30-C (Do not form or use out-of-bounds pointers)
- CERT C Coding Standard: INT30-C (Unsigned integer operations do not wrap)

---

*This exercise tests pure C language security - buffer management, pointer arithmetic, and integer handling.*
