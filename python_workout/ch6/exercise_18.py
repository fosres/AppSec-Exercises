import sys

def main():
	
	if len(sys.argv) != 2:
		
		print("Error: Improper number of arguments")

		exit(1)

	lst = []

	file = open(sys.argv[1],'r')

	for line in file:

		if len(lst) > 0:

			lst.pop()

		lst.append(line)

	file.close()
	
	if len(lst) > 0:
		return lst[0].strip()

	else:
		return ""

if __name__=="__main__":
	print(main())
