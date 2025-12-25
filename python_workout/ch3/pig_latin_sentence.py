'''
Input: lowercase english words separated by whitespace
'''

import sys


if len(sys.argv) <= 1:
	sys.exit("Not enough arguments. Aborting.")

def pig_latin(word: str) -> str:
	
	if len(word) == 0:
		return "ay"
	
	elif word[0] in "AEIOUaeiou": 
		return word + "way"

	else:
		return word[1:] + word[0:1] + "ay"


def pig_latin_sentence():

	sentence = ""


	for arg in sys.argv[1:]:

		if len(sentence) == 0:
			sentence += pig_latin(arg)

		else:
			sentence += (" " + pig_latin(arg) )
	
	print(sentence)

	

pig_latin_sentence()
