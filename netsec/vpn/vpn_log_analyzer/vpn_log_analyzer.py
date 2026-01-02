import sys

def vpn_log_analysis():
	
	if len(sys.argv) != 2:
		print("Only 1 argument was supposed to be supplied")
		exit("Aborting")

	file = open(sys.argv[1],'r')

	failed_login_table = {}

	session_hijacking_table = {}

	cred_stuff_table = {}

	
	'''
	0 - Datetime

	1 - Username

	2 - IP Address

	3 - status
	
	'''

	for line in file:

		cleansed_line = line.strip().split("|")
	
		if len(cleansed_line) != 4:

			print(f"Incorrectly formatted line {cleansed_line}")
	
			continue
	
		username = cleansed_line[1].split(":")[1].strip()	

		ip_addr = cleansed_line[2].split(":")[1].strip()

		status = cleansed_line[3].split(":")[1].strip()

		if "failed" in status:

			if username in failed_login_table:

				failed_login_table[username] += 1

			else:
				failed_login_table[username] = 1

			if ip_addr not in cred_stuff_table:

				cred_stuff_table[ip_addr] = set()
				
				cred_stuff_table[ip_addr].add(username)		

			elif username not in cred_stuff_table[ip_addr]:

				cred_stuff_table[ip_addr].add(username)		
					
		elif "success" in status:

			if username in session_hijacking_table:

				if ip_addr not in session_hijacking_table[username]:

					session_hijacking_table[username].add(ip_addr)

			else:

				session_hijacking_table[username] = set()							
				session_hijacking_table[username].add(ip_addr)
	brute_force = []				

	credential_stuffing = []

	session_hijacking = []

	for username,val in failed_login_table.items():

		if val >= 5:

			brute_force.append(username)

	for username,ip_addrs_set in session_hijacking_table.items():

		if len(ip_addrs_set) >= 3:

			session_hijacking.append(username)

	for ip_addr,usernames_set in cred_stuff_table.items():

		if len(usernames_set) >= 5:

			credential_stuffing.append(ip_addr)

	log_dict = {}

	log_dict['brute_force'] = brute_force

	log_dict['session_hijacking'] = session_hijacking

	log_dict['credential_stuffing'] = credential_stuffing

	return log_dict
		
if __name__ == "__main__":
	
	print(vpn_log_analysis())
	
