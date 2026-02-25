Question 2:

```
import subprocess

def get_file(file):
	path = subprocess.check_output(f"find . -name '{file}'", shell=True)
	with open(path, "rb") as f:
		return f.read()

if __name__=="__main__":

	print(get_file("/tmp/test.txt ; ls"))
```

Vulnerabilities:

1. The `subprocess.check_output()` is vulnerable to OS Command

Injection. Attacker can pass dangerous shell metacharacters

as input for `file` parameter.

2. The shell flag is set to True. This is dangerous since it

propagates current shell settings and variables.

3. There is a software bug where the output of `check_output` is

not passed through Python's `strip()` function. This removes the 

ending newline character that is found at the end of outputs of

`check_output`.



Below is the fixed code:

```
import subprocess
import shlex

def get_file(file):

	user_input = f"find . -name '{file}'"

	arg_list = shlex.split(user_input)
	path = subprocess.check_output(arg_list, shell=False).strip()
	with open(path, "rb") as f:
		return f.read()
```
