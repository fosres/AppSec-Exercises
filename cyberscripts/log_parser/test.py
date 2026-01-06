import json

# Sort items in dictionary in descending order of value:

# https://www.geeksforgeeks.org/python/sort-dictionary-by-value-python-descending/

severity = {}

severity.update({"severity": "HIGH"})

severity.update({"ip": "192.168.155.155"})

print(severity)

json_severity = json.dumps(severity)

print(json_severity)

failed_login = { "192.168.255.255" : 1, "path" : "/login.php" }

print(failed_login)

print(failed_login['path'])

failed_login["192.168.255.255"] += 1

print(failed_login)

print(failed_login["192.168.255.255"]["path"])
