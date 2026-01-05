import sys
import os
import json

def print_scores(directory):

	extracted_objs = []

	for entry in os.scandir(directory):

		if entry.is_file() and entry.name.endswith(".json"):

			print(entry.name)

			with open(entry.path) as file:

				json_body = json.load(file)

				for student_scores in json_body:

					for subject,score in student_scores.items():

						print(f"{subject}:{score}")

def main():
	
	if len(sys.argv) != 2:

		print("Improper args. Aborting")

		exit(1)

	print_scores(sys.argv[1])
	
if __name__ == "__main__":
	main()

