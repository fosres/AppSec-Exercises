from collections import Counter

#print(Counter('tark').most_common(1)[0])

def most_repeating_word(words: list) -> str:

	best_word = ["",0]

	for word in words:
	
		current_common = Counter(word).most_common(1)[0]

		if current_common[1] > best_word[1]:

			best_word[0] = word

			best_word[1] = current_common[1]

	return best_word[0]		

print(most_repeating_word(['this', 'is', 'an', 'elementary','test','example']))
