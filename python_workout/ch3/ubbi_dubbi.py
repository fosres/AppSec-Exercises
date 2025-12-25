def ubbi_dubbi(word: str) -> str:

	newword = ""

	for ch in word:

		if ch in "AEIOUaeiou":
			newword += "ub" + ch

		else:
			newword += ch

	return newword
			

print(ubbi_dubbi("swiss"))
