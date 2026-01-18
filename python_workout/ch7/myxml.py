def myxml(*args,**kwargs):

	tags = ""

	for key,val in kwargs.items():

		print(f"{key}: {val}\n")

		tags += f" {key}=\"{val}\""

	return f"<{args[0]}{tags}>{args[1]}</{args[0]}>"

def main():
	
	print(myxml('foo', 'bar', a=1, b=2, c=3))	

if __name__=="__main__":

	main()
