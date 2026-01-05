import sys
import string
import os

def find_all_longest_words(directory: str):

	table = {}

	for entry in os.scandir(directory):

		if entry.is_file():
	
			table[entry] = find_longest_word(entry)

	return table
	
def find_longest_word(filename: str) -> str:


	try:
		file = open(filename,'r')

	except FileNotFoundError:
		
		print(f"Error: File {sys.argv[1]} not found\nAborting.")

		exit(2)

	max_word = ""
	
	unique_words = set()

	for line in file:

		lst = line.split()

		i = 0

		while i < len(lst):

			if lst[i][-1] in string.punctuation:

				lst[i] = lst[i][0:-1]

			if len(lst[i]) > len(max_word):

				unique_words.add(lst[i])

				max_word = lst[i]

			if lst[i] not in unique_words:

				unique_words.add(lst[i])
			
			i += 1

	file.close()

	return max_word

def main():
	
	if len(sys.argv) != 2:

		print("Improper args. Aborting")

		exit(1)

	print(find_all_longest_words(sys.argv[1]))
	
if __name__ == "__main__":
	main()

