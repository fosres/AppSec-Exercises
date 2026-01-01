import urllib.parse

string = "%2e%2e%2fetc%2fpasswd"


renew = urllib.parse.unquote(string)

print(renew)



