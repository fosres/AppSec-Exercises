import fnmatch

pattern = "*.com"

url = "www.example.com"

print(fnmatch.fnmatch(url,pattern))
