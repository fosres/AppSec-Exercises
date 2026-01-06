import sys
import copy
import json

from collections import Counter

def parse_auth_log(filepath: str) -> dict:

	table = {

            "total_failed": 0,           # Total failed login attempts
            "unique_ips": [],       # Unique source IPs (sorted)
            "unique_users": [],     # Unique usernames attempted (sorted)
            "attempts_by_ip": {},        # {ip: count} for each IP
            "attempts_by_user": {},      # {username: count} for each user
            "top_offender_ip": None, # IP with most failures (None if no failures)
            "top_targeted_user": None, # Most targeted username (None if no failures)
            "first_failure": None,   # Timestamp of first failure (None if no failures)
            "last_failure": None,    # Timestamp of last failure (None if no failures)
            "potential_brute_force": [], # IPs with 5+ failures (sorted)
        }

	latest_failure = ""

	with open(filepath,'r') as file:

		for line in file:

			if	(

					"Failed password" not in line 

					and 

					"Failed publickey" not in line

				):
				
				continue

			else:

				latest_failure = line[:]
		
				table["total_failed"] += 1

				lst = line.split()
				
				ip_index = lst.index("from") + 1

				ip_addr = lst[ip_index]

				if ip_addr not in table["unique_ips"]:

					table["unique_ips"].append(ip_addr)

				user_index = 0

				if "user" in lst:

					user_index = lst.index("user") + 1

				else:
					user_index = lst.index("for") + 1

				
				username = lst[user_index]

				if username not in table["unique_users"]:				
					table["unique_users"].append(username)
		
				if ip_addr not in table["attempts_by_ip"]:
		
					table["attempts_by_ip"][ip_addr] = 1

				else:
					table["attempts_by_ip"][ip_addr] += 1

				if username not in table["attempts_by_user"]:

					table["attempts_by_user"][username] = 1

				else:
					table["attempts_by_user"][username] += 1

				
				if table["first_failure"] == None:

					table["first_failure"] = lst[0] + " " + lst[1] + " " + lst[2]


	if latest_failure != "":

		lst = latest_failure.split()

		table["last_failure"] = lst[0] + " " + lst[1] + " " + lst[2] 	
				
	table["unique_ips"].sort()
	
	table["unique_users"].sort()
		
	ip_table = copy.deepcopy(table["attempts_by_ip"])

	if len(ip_table) > 0:

		for ip_addr, count in ip_table.items():

			if	(

					table["top_offender_ip"] == None

					or	

					count > ip_table[table["top_offender_ip"]]

				):

					table["top_offender_ip"] = ip_addr
	
	user_table = copy.deepcopy(table["attempts_by_user"])
	
	if len(user_table) > 0:

		for user, count in user_table.items():

			if	(

					table["top_targeted_user"] == None

					or	

					count > user_table[table["top_targeted_user"]]

				):

					table["top_targeted_user"] = user 
				
	
	for ip_addr, count in ip_table.items():

		if count >= 5:

			table["potential_brute_force"].append(ip_addr)				
	table["potential_brute_force"].sort()

	return table	


def main():
	
	if len(sys.argv) != 2:

		print("Improper arguments. Aborting.")
		
		exit(1)	
	
	table_dict = parse_auth_log(sys.argv[1])

	json_table = json.dumps(table_dict,indent=4,sort_keys=True)

	print(json_table)
	
if __name__=="__main__":
	main()
