import subprocess

def get_file(file):
	path = subprocess.check_output(f"find . -name '{file}'", shell=True)

	with open(path, "rb") as f:
		return f.read()

if __name__=="__main__":

	print(get_file("test.txt ; ls"))
