import subprocess
import shlex

def get_file(file):

	'''
	
		OS Command Injection Vulnerability below:

		One is supposed to use an array with a sequence

		of program arguments instead of a single string.

	'''

	print(shlex.quote(file))

	cmd = f"find . -name {shlex.quote(file)}"

	cmd = cmd.strip()

	cmd_list = shlex.split(cmd)

	path = subprocess.check_output(cmd_list,shell=False).decode('utf-8').strip()

	with open(path, "rb") as f:
		return f.read()

def main():
	print(get_file("test.txt"))

if __name__=="__main__":
	main()
	
