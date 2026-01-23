import json
import csv
from pathlib import Path
from dateutil import parser

'''
Both auth.log and security.log informs of user_id per entry

There are two types of events from these logs:

1. auth_event

2. security_event
'''

def parse_auth_log(filepath,table_events):

	try:
		
		with open(filepath,'r') as file:
			
				reader = csv.DictReader(file)

				for row in reader:

					auth_table = dict(row)

					user_id = auth_table["user_id"]

					if user_id not in table_events:

						table_events[user_id] = {}	

					if "auth_events" not in table_events[user_id]:

						table_events[user_id]["auth_events"] = []
					
					table_events[user_id]["auth_events"].append(auth_table)

				
	except FileNotFoundError:

		raise Exception(f"parse_auth_log: File Not Found: {filepath}")

	except PermissionError:

		raise Exception(f"parse_auth_log: Permission Denied to read {filepath}")

	except Exception as e:

		raise Exception(f"parse_auth_log: Unexpected error for {filepath}")		

def parse_security_log(filepath,table_events):
	
	try:
		with open(filepath,'r') as file:
			

				for line in file:

					security_table = json.loads(line) 

					user_id = security_table["user_id"]

					if user_id not in table_events:

						table_events[user_id] = {}	

					if "security_events" not in table_events[user_id]:

						table_events[user_id]["security_events"] = []
					
					table_events[user_id]["security_events"].append(security_table)

				
	except FileNotFoundError:

		raise Exception(f"parse_security_log: File Not Found: {filepath}")

	except PermissionError:

		raise Exception(f"parse_security_log: Permission Denied to read {filepath}")

	except Exception as e:

		raise Exception(f"parse_security_log: Unexpected error for {filepath}")		

def detect_brute_force(user_id,user_events, time_window_minutes=5, failure_threshold=5):

	if user_id not in user_events:

		return {"user_id": user_id}  # Not None!

	if "auth_events" not in user_events[user_id]:

		return {"user_id": user_id}  # Not None!

	auth_events = user_events[user_id]["auth_events"]

	table_brute_force = {}

	table_brute_force["user_id"] = user_id
	
	i = 0

	brute_force_chain = []

	while i < len(auth_events):
			
		if	(
				auth_events[i]["status"] == "success" 

				and 

				len(brute_force_chain) == 0

			):

			i += 1

			continue
			
		if	(
				auth_events[i]["status"] == "failure" 

				and 

				len(brute_force_chain) == 0

			):
			
			brute_force_chain.append(i)

			i += 1

			continue

		current = auth_events[i]

		first = auth_events[brute_force_chain[0]]

		first_datetime = parser.parse(first["timestamp"])

		cur_datetime = parser.parse(current["timestamp"])

		diff = cur_datetime - first_datetime

		diff_seconds = diff.total_seconds()


		if	(

				auth_events[i]["status"] == "failure"

				and

				len(brute_force_chain) > 0

				and
			
				diff_seconds <= (60 * time_window_minutes)
				
			):


			brute_force_chain.append(i)

		elif	(
				auth_events[i]["status"] == "failure"
				
				and

				len(brute_force_chain) > 0

				and
			
				diff_seconds > (60 * time_window_minutes)
			):

			brute_force_chain = [i]	

		
		elif	(
				auth_events[i]["status"] == "success"
				
				and

				len(brute_force_chain) > 0
				
				and
			
				diff_seconds <= (60 * time_window_minutes)

				and

				len(brute_force_chain) >= failure_threshold
			):
			
			# We need to account for the success

			# as part of the brute force chain
			
			brute_force_chain.append(i)
			
			current = auth_events[brute_force_chain[-1]]

			first = auth_events[brute_force_chain[0]]

			first_datetime = parser.parse(first["timestamp"])

			cur_datetime = parser.parse(current["timestamp"])

			diff = cur_datetime - first_datetime

			diff_seconds = diff.total_seconds()

			brute_force_list = []

			for index in brute_force_chain:

				brute_force_list.append(auth_events[index])

			if "attacks" not in table_brute_force:

				table_brute_force["attacks"] = []

			brute_force_table = {}

			brute_force_table["failure_chain"] = brute_force_list

			brute_force_table["failure_count"] = len(brute_force_list)

			brute_force_table["attack_duration_seconds"] = diff_seconds
			
			brute_force_table["success_event"] = auth_events[i]

			table_brute_force["attacks"].append(brute_force_table)

			brute_force_chain = [] 	
		
		
		elif	(
				auth_events[i]["status"] == "success"
				
				and
			
				diff_seconds > (60 * time_window_minutes)
				
			):

			brute_force_chain = []
		
		i += 1

	return table_brute_force

def detect_privilege_escalation(user_id, user_events, time_window_minutes=10):

	if user_id not in user_events:

		return {
		    "user_id": user_id,
		    "login_sessions": [],
		    "total_login_sessions": 0,
		    "total_escalations": 0
		}  # Not None!

	if "auth_events" not in user_events[user_id]:

		return {
		    "user_id": user_id,
		    "login_sessions": [],
		    "total_login_sessions": 0,
		    "total_escalations": 0
		}  # Not None!

	if "security_events" not in user_events[user_id]:

		return {
		    "user_id": user_id,
		    "login_sessions": [],
		    "total_login_sessions": 0,
		    "total_escalations": 0
		}  # Not None!
    
	# TODO: Implement
	# Step 1: Get auth events: auth_events = user_events[user_id]["auth_events"]
	# Step 2: Find successful logins (status == "success"), get their timestamps
	# Step 3: Get security events: security_events = user_events[user_id]["security_events"]
	# Step 4: Look for event_type == "privilege_change" events
	# Step 5: Check if privilege_change timestamp is within 10 minutes of ANY successful login
	# Step 6: Verify resource field contains "sudo_access", "admin_role", etc.

	'''
	Attack details structure (ALWAYS uses login_sessions):
        {
            "user_id": "user456",
            "login_sessions": [
                {
                    "login_event": {...},           # Login timestamp
                    "privilege_escalations": [
                        {
                            "privilege_event": {...},
                            "time_to_escalation_seconds": 90.5
                        }
                        # ... more escalations after this login
                    ],
                    "escalation_count": 1  # Number of escalations after this login
                }
                # ... more login sessions
            ],
            "total_login_sessions": 1,      # Total logins with escalations
            "total_escalations": 1          # Total escalations across all logins
        }
	'''

	auth_events = user_events[user_id]["auth_events"]

	security_events = user_events[user_id]["security_events"]	

	escalate_table = {}

	escalate_table["user_id"] = user_id

	escalate_table["login_sessions"] = []

	escalate_table["total_login_sessions"] = 0

	escalate_table["total_escalations"] = 0

	i = 0

	while i < len(auth_events):

		if auth_events[i]["status"] == "success":

			current = auth_events[i]
			
			cur_datetime = parser.parse(current["timestamp"])
					
			log_session = {}

			log_session["login_event"] = auth_events[i]
					
			log_session["privilege_escalations"] = [] 		

			j = 0

			while j < len(security_events):

				security = security_events[j]

				sec_datetime = parser.parse(security["timestamp"])

				if sec_datetime < cur_datetime:

					j += 1

					continue	

				diff = sec_datetime - cur_datetime

				diff_seconds = diff.total_seconds()

				if diff_seconds > 600:

					j += 1

					continue

				if security_events[j]["event_type"] == "privilege_change":				
					priv_table = {}

					priv_table["privilege_event"] = security_events[j]
					priv_table["time_to_escalation_seconds"] = diff_seconds
					log_session["privilege_escalations"].append(priv_table)
				j += 1

			log_session["escalation_count"] = len(log_session["privilege_escalations"])

			if log_session["escalation_count"] > 0:

				escalate_table["login_sessions"].append(log_session)		

		i += 1


	i = 0

	while i < len(escalate_table["login_sessions"]):

		escalate_table["total_escalations"] += escalate_table["login_sessions"][i]["escalation_count"]

		i += 1
	
	escalate_table["total_login_sessions"] = len(escalate_table["login_sessions"])

	return escalate_table

def detect_anomalous_access(user_id, user_events):

	if user_id not in user_events:

		return None

	if "security_events" not in user_events[user_id]:

		return None

	"""
        Attack details structure:
        {
            "user_id": "user789",
            "sensitive_files_accessed": [
                {
                    "file": "/etc/shadow",
                    "timestamp": "...",
                    "event": {...}  # Full security event
                },
                {
                    "file": "/root/.ssh/authorized_keys",
                    "timestamp": "...",
                    "event": {...}
                }
            ],
            "access_count": 2
        }
	"""

	danger_access = {}

	danger_access["user_id"] = user_id

	danger_access["sensitive_files_accessed"] = []

	danger_table =	{
				"/etc/passwd" : 1,

				"/etc/shadow" : 1,

				"/etc/sudoers" : 1,

				"/etc/group" : 1,

				"/root/.ssh/authorized_keys" : 1,

				"/home/*/.ssh/authorized_keys" : 1,

				"/home/*/.ssh/id_rsa" : 1,

				"/home/*/.ssh/id_ed25519": 1,

				"/boot/grub/grub.cfg" : 1,

				"/etc/crontab" : 1,

				"/var/spool/cron/*" : 1,

				"/var/log/auth.log" : 1,

				"/var/log/secure" : 1,

				"/var/log/audit/audit.log" : 1
			}

	security_events = user_events[user_id]["security_events"]

	i = 0

	while i < len(security_events):

		file_path = Path(security_events[i]["resource"])

		for key,_ in danger_table.items():

			if	(
					security_events[i]["event_type"] == "file_access"
					and

					file_path.match(key)
				):
							
				danger_file = {}

				danger_file["timestamp"] = security_events[i]["timestamp"]	
				danger_file["event"] = security_events[i]

				danger_file["file"] = security_events[i]["resource"]
		
				danger_access["sensitive_files_accessed"].append(danger_file)
				
		i += 1

	danger_access["access_count"] = len(danger_access["sensitive_files_accessed"])

	return danger_access
   
def main():

	table_events = {}

	table_brute_force = {}

	'''	
	parse_auth_log("test_data_complete/01_parsing/test_001_parsing/auth.log",table_events)
	parse_security_log("test_data_complete/01_parsing/test_001_parsing/security.log",table_events)
	
	parse_auth_log("test_data_complete/03_brute_force/test_032_brute_force/auth.log",table_events)

	parse_security_log("test_data_complete/03_brute_force/test_032_brute_force/security.log",table_events)
	
	parse_auth_log("test_data_complete/03_brute_force/test_045_brute_force/auth.log",table_events)

	parse_security_log("test_data_complete/03_brute_force/test_045_brute_force/security.log",table_events)
	
	parse_auth_log("test_data_complete/03_brute_force/test_040_brute_force/auth.log",table_events)

	parse_security_log("test_data_complete/03_brute_force/test_040_brute_force/security.log",table_events)

	print(json.dumps(table_events,indent=4))
	
	user_brute_force_table = detect_brute_force("target00",table_events)

	print("table_brute_force:\n")

	print(json.dumps(user_brute_force_table,indent=4))
			
	parse_auth_log("test_data_complete/04_privilege_escalation/test_048_privilege_escalation/auth.log",table_events)

	parse_security_log("test_data_complete/04_privilege_escalation/test_048_privilege_escalation/security.log",table_events)

	print(json.dumps(table_events,indent=4))

	escalate_table = detect_privilege_escalation("compromised01",
table_events, time_window_minutes=10)
	
	print(f"escalate_table:\n{json.dumps(escalate_table,indent=4)}")

	'''

	parse_auth_log("test_data_complete/04_privilege_escalation/test_048_privilege_escalation/auth.log",table_events)

	parse_security_log("test_data_complete/04_privilege_escalation/test_048_privilege_escalation/security.log",table_events)

	danger_access_table = detect_anomalous_access("compromised00",table_events)	

	print(f"danger_table:\n{json.dumps(danger_access_table,indent=4)}")
	

if __name__=="__main__":

	main()
