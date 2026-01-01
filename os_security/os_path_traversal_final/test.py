import urllib.parse
import re
from pathlib import Path

string = "%2e%2e%2fetc%2fpasswd"

string_two = "%252e%252e%252fetc%252fpasswd"


renew = urllib.parse.unquote(string_two)

while re.search(r'%[0-9a-fA-F][0-9a-fA-F]',renew) != None:
	
	renew = urllib.parse.unquote(renew)
 
# print(renew)

path = Path("/home/../etc").resolve()

print(str(path))
# print(re.search(r'%[0-9a-fA-F][0-9a-fA-F]',renew))
