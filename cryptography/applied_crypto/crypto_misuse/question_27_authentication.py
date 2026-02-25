# authentication.py
from django.contrib.auth.models import User
import hmac

def validate_api_key(api_key, expected_key):
	"""Validate API key with timing information"""

	if not hmac.compare_digest(api_key,expected_key):
		return False
	
	return True

def main():

	print(validate_api_key(b"The",b"The"))

if __name__=="__main__":

	main()
