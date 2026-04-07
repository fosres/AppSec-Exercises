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

Insert your answer here

### What mitigations would you suggest?

Insert your answer here

---

# Question 3

The engineering team now decides it would be better to integrate an open-source third-party file server. They send you the following code for a security review.

Assume you can reach this code via HTTP, fully controlling the value of `file`.

```python
import requests

_FILE_SERVER = "http://files.local"
_ACCESS_KEY = "aGVsbG8gd29ybGQK"

def get_file(file):
	url = f"{_FILE_SERVER}{file}?accesskey={_ACCESS_KEY}"
	return requests.get(url).content
```

### What vulnerabilities exist in the code? How would you exploit them?

Insert your answer here

### What mitigations would you suggest?

Insert your answer here
