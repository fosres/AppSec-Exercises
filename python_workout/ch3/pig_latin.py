import sys

def pig_latin(word: str):
	
	if len(word) == 0:
		print("ay")
	
	elif word[0] in "AEIOUaeiou": 
		print(word + "way")

	else:
		print(word[1:] + word[0:1] + "ay")

if len(sys.argv) == 2:
	pig_latin(sys.argv[1])
