# Question 2

The Software Engineering Team sends you the following code for a security review.

Assume you can reach this code via HTTP, fully controlling the value of `file`.

```python
import subprocess

def get_file(file):
	path = subprocess.check_output(f"find . -name '{file}'", shell=True)
	with open(path, "rb") as f:
		return f.read()
```

### What vulnerabilities exist in the code? How would you exploit them?

0. Lack of HTTPS: There is no evidence HTTPS is being used. It

must be enforced to protect the confidentiality of the file

retrieved.

1. OS Path Traversal Vulnerability: An attacker can write a command

to first exit out of the base directory that was intended for file

retrieval and next retrieve the contents of a sensitive file.

For example:

```
file: /etc/shadow
```

The above payload for `file` can allow the attacker to see the

stored password hashes on the server.

2. OS Command Line Injection

Payload:


```
file: file_name_here ; cd /etc/ ; cat /etc/shadow
```
The above payload for `file` also qualifies as a payload for

OS Command Line Injection. Where the attacker injects Shell Commands

that have consequences the developers did not intend. 

2.5. No allowlist restricting which files can be accessed.

This avoids SSRF.

3. No authentication or authorization? Is this a sensitive

file whose access is supposed to be restricted. In that case

The API endpoint should check for a valid session cookie and

then check if the user has the required role.

4. No Rate Limiting: Every API Endpoint that demands significant

system resources should be rate limited. This can be done using

a modern framework such as Flask, FastAPI, or Django.

### What mitigations would you suggest?

The following is the fixed code:


```python
import subprocess
import os
import shlex

# Assuming HTTPS is enforced

def get_file(file):


        base_dir = os.path.abspath('./')

        pwd_file = os.path.abspath(os.path.join(base_dir, file))

        if not pwd_file.startswith(base_dir + os.sep):
		
		raise Exception('File retrieval failure') 


	cmd_string = 'find . -name '

	cmd_string += shlex.quote(file)

	cmd_split = shlex.split(cmd_string)

	pwd_file = ''


	try:

		path = subprocess.run(cmd_split,shell=False,capture_output=True,text=True).stdout.strip()
        
		pwd_file = os.path.abspath(os.path.join(base_dir, path))

		if not pwd_file.startswith(base_dir + os.sep):
			
			raise Exception('File retrieval failure') 

	except Exception:
		
		raise Exception('File retrieval failure') 

	with open(pwd_file, "rb") as f:

		return f.read()

```

The above quote defends against OS Path Traversal and OS

Command Injection at once.

Other protections such as Cookie Verification and Authorization

not shown.

---

# Question 3

The engineering team now decides it would be better to integrate an open-source third-party file server. They send you the following code for a security review.

Assume you can reach this code via HTTP, fully controlling the value of `file`.

```python
import requests

_FILE_SERVER = "http://files.local"
_ACCESS_KEY = "aGVsbG8gd29ybGQK"

def get_file(file):
	
	file_allowlist = ['file1.txt','file2.txt']

	if file not in file_allowlist:

		raise Exception("Failed to retrieve file")

	url = f"{_FILE_SERVER}{file}?accesskey={_ACCESS_KEY}"
	return requests.get(url).content
```

### What vulnerabilities exist in the code? How would you exploit them?

0. No HTTPS protection. The File Server should be accessible only

under HTTPS since it does house the file(s) as protected resource(s).

1. Server Side Request Forgery and OS Path Traversal: An attacker can

cause a file's contents to be revealed from the File Server that was

not intended.

For example the `file` parameter can be set to `/etc/shadow`.

As a second example the `file` parameter can be made to point

to a protected resource hosted in a DMZ zone under a private IP

addres which the attacker can make `file` point to.

The mitigation is to check if the file parameter is within the

expected directory. The developers must perform a similiar

check for OS Path Traversal as I presented as a mitigation

for Question 2 on the file server.

2. Exposure of ACCESS KEY: ACCESS KEY is too weak. Use a CSPRNG

to generate a secret with sufficient entropy. Second don't have the

ACCESS KEY hardcoded! Any attacker that has access to the codebase will

be able to make unauthorized requests to the File server. Unwise

to have the ACCESS_KEY as GET request parameter. It is better to use a

POST request in `get_file()`.


### What mitigations would you suggest?


```python
import requests
from dotenv import load_dotenv
import os

load_dotenv()

_FILE_SERVER = "https://files.local"
_ACCESS_KEY = os.getenv('ACCESS_KEY') 

def get_file(file):

	# The File Server should check for potential OS Path

	file_allowlist = ['file1.txt','file2.txt']

	if file not in file_allowlist:

		raise Exception("Failed to retrieve file")

	# Traversal

	body = {'access_key': _ACCESS_KEY, 'file': file }

	url = f"{_FILE_SERVER}"

	return requests.post(url,json=body).content
```

