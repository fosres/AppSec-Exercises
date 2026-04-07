# Question 3

The engineering team now decides it would be better to integrate an open-source third-party file server. They send you the following code for a security review.

Assume you can reach this code via HTTP, fully controlling the value of `file`.

```python
import requests

# No HTTPS connection

_FILE_SERVER = "http://files.local"

# No hardcoding of secrets below

# The _ACCESS_KEY shold be retrieved by `os.getenv()`

_ACCESS_KEY = "aGVsbG8gd29ybGQK"

def get_file(file):

	# SSRF Vulnerability: `file` should be checked against

	# a whitelist of files

	# Apply a POST request below instead

	# File Server must check against OS Path Traversal

	url = f"{_FILE_SERVER}{file}?accesskey={_ACCESS_KEY}"

	return requests.get(url).content
```

### What vulnerabilities exist in the code? How would you exploit them?

See comments in the above code snippet:

1. Hardcoding of secrets. An attacker that can access the file

can see the `_ACCESS_KEY` and start sending requests to the

file server. Please generate a secret using a CSPRNG with high

entropy (>= 128 bits of security)

2. OS Path Traversal Vulnerability: An attacker can request for a file

that reveals sensitive information such as setting file

to be `/etc/shadow`.

3. `_ACCESS_KEY` exposed through GET request--this can reveal

the `_ACCESS_KEY`. Best to use POST instead

4. OS Path Traversal: Check if the file returned is outside

the base directory on the file server


### What mitigations would you suggest?

```python
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# No HTTPS connection

_FILE_SERVER = "https://files.local"

# No hardcoding of secrets below

# The _ACCESS_KEY shold be retrieved by `os.getenv()`

_ACCESS_KEY = os.getenv('ACCESS_KEY') 

def get_file(file):

	# SSRF Vulnerability: `file` should be checked against

	# a whitelist of files

	# Apply a POST request below instead

	# File Server must check against OS Path Traversal

	allowlist_files = ['file1.txt','file2.txt']

	if file not in allowlist_files:

		raise Exception("Failed to retrieve file")

	body = { 'file' : file, 'access_key' : _ACCESS_KEY }

	return requests.post(_FILE_SERVER,json=body).content
	
```
