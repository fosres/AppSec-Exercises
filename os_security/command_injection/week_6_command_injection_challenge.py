import subprocess
import shlex

def get_file(file):

	user_input = f"find . -name '{file}'"

	arg_list = shlex.split(user_input)

	try:
		path = subprocess.check_output(arg_list, shell=False).strip()

	except FileNotFoundError: 

		raise Exception(f"File {file} not found")

	with open(path, "rb") as f:
		return f.read()

if __name__=="__main__":

	print(get_file("test.txt ; ls"))
