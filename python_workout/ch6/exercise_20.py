import sys
import string

def main():
	
	unique_words = set()

	if len(sys.argv) != 2:

		print("Error: Improper number of arguments. Aborting")

		exit(1)

	try:
		file = open(sys.argv[1],'r')

	except FileNotFoundError:
		
		print(f"Error: File {sys.argv[1]} not found\nAborting.")

		exit(2)

	char_count = 0

	word_count = 0

	line_count = 0
	
	unique_words = set()

	for line in file:
		
		line_count += 1

		char_count += len(line)

		lst = line.split()
		
		word_count += len(lst)

		i = 0

		while i < len(lst):

			if lst[i][-1] in string.punctuation:

				lst[i] = lst[i][0:-1]

				print(lst[i])

			if lst[i] not in unique_words:

				unique_words.add(lst[i])

			i += 1

	print(f"This file contains {word_count} words and {len(unique_words)} different words.")

	print(f"It also contains {char_count} characters.")
	
	print(f"It also contains {line_count} lines.")

	file.close()

if __name__ == "__main__":
	main()

