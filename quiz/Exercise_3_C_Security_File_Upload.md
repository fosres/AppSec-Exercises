# Exercise 3: C Security Code Review - File Upload Handler

**Curriculum Alignment**: Week 4 - Linux Internals, Common Linux Attacks  
**Source**: *API Security in Action*, Chapter 2, pp. 43-49 (Input validation, injection attacks)  
**Additional Reference**: CWE-134 (Format String), CWE-22 (Path Traversal)

**Difficulty**: Week 4 Level  
**Points**: 15 total  
**Estimated Time**: 20 minutes

---

## Scenario

You are reviewing a file upload handler for a web application. The engineering team built functionality to allow users to upload profile pictures to the server.

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#define UPLOAD_DIR "/var/www/uploads/"
#define MAX_FILENAME 256

typedef struct {
	char *username;
	char *filename;
	unsigned char *data;
	size_t size;
} UploadRequest;


int save_upload(UploadRequest *req) {
	
	// No check if req is a NULL pointer.

	// This can cause a dereference of NULL pointer.
	
	char filepath[MAX_FILENAME];

	// Risk of buffer overflow vulnerability below
	
	// Build the file path
	strcpy(filepath, UPLOAD_DIR);
	strcat(filepath, req->username);
	strcat(filepath, "_");
	strcat(filepath, req->filename);

	// No null-termination of filepath after concatenation
	
	// Log the upload attempt
	printf("User upload: ");
	
	// Format String vulnerability below: this can lead

	// to disclosure of sensitive memory addresses

	printf(req->username);
	printf(" uploaded file: ");
	
	// Format String vulnerability below: this can lead

	// to disclosure of sensitive memory addresses

	printf(req->filename);

	printf("\n");
	
	// Save the file
	
	// No check if fopen() returns NULL. This can cause a

	// dereference of NULL pointer.

	FILE *fp = fopen(filepath, "wb");

	// No check if req->data is NULL pointer. This can cause

	// dereference of NULL pointer.

	size_t written = 0;

	if ( ( written = fwrite(req->data, 1, req->size, fp) ) == 0 )
	{
		fprintf(stderr,"fwrite failed\n");

		fclose(fp);

		return 1;
	}

	if ( written != req->size )
	{
		fprintf(stderr,"Error: Failed to write req->size bytes\n");

		fclose(fp);

		return 1;
	}

	fclose(fp);
	
	chmod(filepath, 0644);
	
	return 0;
}

int main() {
	UploadRequest req;
	req.username = "alice";
	req.filename = "../../etc/passwd";
	req.data = (unsigned char *)"malicious data";
	req.size = 14;

	// No check if save_upload() was successful. Error reporting

	// should be done such as by checking integer code returned.
	
	save_upload(&req);
	
	return 0;
}
```

---

## Questions

### **3a. Vulnerability Identification** (5 points)

Identify ALL vulnerabilities present in this code. For each vulnerability:
- Name the vulnerability class (use CWE numbers if you know them)
- Explain the root cause
- Describe potential impact

---

### **3c. Mitigations** (10 points)

Propose secure alternatives for this code. Address:
- Path traversal prevention
- Format string vulnerability mitigation
- Input validation requirements
- Error handling

**Your rewritten code should:**
- Validate and sanitize the filename to prevent path traversal
- Use safe printf formatting to prevent format string attacks
- Check all function return values
- Validate input lengths before string operations
- Properly handle error conditions

Write your complete secure implementation below:

```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#define UPLOAD_DIR "/var/www/uploads/"
#define MAX_FILENAME 256

typedef struct {
	char *username;
	char *filename;
	unsigned char *data;
	size_t size;
} UploadRequest;


int save_upload(UploadRequest *req) {

	if ( req == NULL )
	{
		fprintf(stderr,"Error: req == NULL\n");
	
		return 1;
	}	
	
	char filepath[MAX_FILENAME];
	
	// Build the file path

	size_t total_len = 

				strnlen(UPLOAD_DIR,256)

				+
				
				strnlen(req->username,256) 

				+ 
	
				strnlen("_",256)

				+

				strnlen(req->filename,256);

	if ( total_len > 255 )
	{
		fprintf(stderr,"Error: Arguments for filepath too long\n");

		return 1;
	}

	snprintf(filepath,256,"%s%s%s%s",UPLOAD_DIR,req->username,"_",req->filename);

	printf("User upload: %s uploaded file: %s\n",req->username,req->filename);	
	
	// Save the file

	FILE *fp = NULL;

	if ( ( fp = fopen(filepath, "wb") ) == NULL )
	{
		fprintf(stderr,"Error: fopen() returns NULL\n");

		return 1;
	}

	if ( req->data == NULL )
	{
		fprintf(stderr,"Error: req->data == NULL\n" );

		fclose(fp);

		return 1;
	}

	if ( req->size == 0 )
	{
		fprintf(stderr,"Error: req->size == 0\n");

		fclose(fp);

		return 1;
	}

	size_t written = 0;

	if ( ( written = fwrite(req->data, 1, req->size, fp) ) == 0 )
	{
		fprintf(stderr,"fwrite failed\n");

		fclose(fp);

		return 1;
	}

	if ( written != req->size )
	{
		fprintf(stderr,"Error: Failed to write req->size bytes\n");

		fclose(fp);

		return 1;
	}

	fclose(fp);
	
	chmod(filepath, 0644);
	
	return 0;
}

int main() {
	UploadRequest req;
	req.username = "alice";
	req.filename = "../../etc/passwd";
	req.data = (unsigned char *)"malicious data";
	req.size = 14;
	
	save_upload(&req);
	
	return 0;
}
```

---

## Expected Knowledge

By Week 4, you should understand:
- Format string vulnerabilities (*API Security in Action*, p. 43)
- Path traversal attacks (CWE-22)
- Input validation and sanitization
- Safe string handling (strcpy vs strncpy vs snprintf)
- File I/O error handling
- Principle of least privilege (file permissions)

---

## Grading Rubric

### 3a. Vulnerability Identification (5 points)
- **1 point**: Identified format string vulnerability in printf calls
- **1 point**: Identified path traversal vulnerability
- **1 point**: Identified buffer overflow potential in strcpy/strcat
- **1 point**: Identified missing error checking (fopen, fwrite, chmod)
- **1 point**: Clearly explained root causes and impacts

### 3c. Mitigations (10 points)
- **2 points**: Prevents path traversal (validates/sanitizes filename)
- **2 points**: Uses safe printf formatting (printf("%s", str) not printf(str))
- **2 points**: Uses safe string operations (snprintf, bounds checking)
- **2 points**: Checks all function return values
- **2 points**: Code is clean, compiles, and handles all edge cases

---

## References

**Primary Sources**:
- *API Security in Action* by Neil Madden, Chapter 2, pp. 43-49
- CWE-134: Use of Externally-Controlled Format String
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-252: Unchecked Return Value

**Additional Reading**:
- *Secure by Design*, Chapter 4 - Input validation
- *Full Stack Python Security*, Chapter 3 - File upload security
- OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
- CERT C Coding Standard: FIO30-C (Exclude user input from format strings)

---

*This exercise tests your ability to identify input validation vulnerabilities, format string attacks, and path traversal issues in file handling code.*
