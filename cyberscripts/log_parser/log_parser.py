from collections import Counter
import json
import sys

def parse_endpoint(tokens: list[str],quote_string: str):
	
	i = len(quote_string) - 1

# It is easier to parse the endpoint for METHOD PATH PROTOCOL

# in reverse!
	
	protocol = ""

	while i >= 0 and not quote_string[i].isspace():
		
		protocol = quote_string[i] + protocol
		
		i -= 1


	while i >=0 and quote_string[i].isspace():
	
		i -= 1

	path = ""

	while i >= 0 and not (quote_string[i-1].isspace() and quote_string[i] == '/'):
		
		path = quote_string[i] + path

		i -= 1

	path = quote_string[i] + path

	i -= 1
	
	while i >=0 and quote_string[i].isspace():
	
		i -= 1

	method = ""

	while i >= 0:

		method = quote_string[i] + method

		i -= 1

	tokens.append(method)

	tokens.append(path)

	tokens.append(protocol)
	
'''
0 - IP Address

1 - USERNAME

2 - TIMESTAMP

3 - METHOD

4 - PATH

5 - PROTOCOL

6 - STATUS_CODE

7 - BYTES

8 - REFERRER

9 - USER_AGENT
'''

def parse_tokens_list(tokens: list[str],

			summary_table,

			most_common_codes_table,

			top_ips,

			suspicious_user_agents,

			severity_list,

			failed_logins):

	summary_table["total_requests"] += 1

	if tokens[0] not in top_ips:
		
		summary_table["unique_ips"] += 1

		top_ips.update({tokens[0]: 1})
	
	elif tokens[0] in top_ips:

		top_ips[tokens[0]] += 1

	try:
		
		summary_table["total_bytes_transferred"] += int(tokens[7])	
	
	except ValueError:
		
		pass

	if tokens[6] not in summary_table["most_common_status_codes"]:

		summary_table["most_common_status_codes"].update({tokens[6]: 1})

	elif tokens[6] in summary_table["most_common_status_codes"]:

		summary_table["most_common_status_codes"][tokens[6]] += 1

	path = tokens[4]

	if int(tokens[6]) >= 400:
		
		summary_table["failed_requests"] += 1

		if path.find("login") >= 0 or path.find("LOGIN") >= 0:

			if tokens[0] not in failed_logins:
				failed_logins.update({tokens[0] : [1,path]})
			
			elif tokens[0] in failed_logins:
				failed_logins[tokens[0]][0] += 1
					
	suspicious_agents_list = ["sqlmap","nikto","nmap","curl","wget","python-requests"]	
	for agent in suspicious_agents_list:

		if tokens[9].find(agent) >= 0:
			
			if agent in suspicious_user_agents:
				suspicious_user_agents[agent] += 1

			elif agent not in suspicious_user_agents:
				suspicious_user_agents.update({agent: 1})		

	sql_payloads = ['UNION ','union ','SELECT ','select ','OR ','or ',

	'AND ','and ','--','/*','*/','DROP ','drop ','TABLE','table']

	path = tokens[4]

	for sql_payload in sql_payloads:

		if sql_payload in path:
			
			severity = {}

			severity.update({"severity": "HIGH"})

			severity.update({"finding_type": "SQL_INJECTION"})

			severity.update({"ip": tokens[0]})
			
			severity.update({"path": path})

			severity.update({"timestamp": tokens[2]})
			
			severity.update({"user_agent": tokens[9]})

			severity_list.append(severity)

			break

	if ".." in path or "2e" in path:
			
		severity = {}

		severity.update({"severity": "MEDIUM"})

		severity.update({"finding_type": "PATH_TRAVERSAL"})

		severity.update({"ip": tokens[0]})
		
		severity.update({"path": path})

		severity.update({"timestamp": tokens[2]})
		
		severity.update({"user_agent": tokens[9]})

		severity_list.append(severity)

	top_ips = dict(Counter(top_ips).most_common())
				
def parse_log():
	
	if len(sys.argv) != 2:
		
		print("Error: No argument for log file name. Aborting\n")
		
		exit(1)

	summary_table = {
			"total_requests": 0,
			"unique_ips": 0,
			"failed_requests": 0,
			"total_bytes_transferred": 0,
			"most_common_status_codes": {}
	}

	most_common_codes_table = {}

	top_ips = {}

	suspicious_user_agents = {}

	severity_list = []

	failed_logins = {}

	'''
	0 - IP Address

	1 - USERNAME

	2 - TIMESTAMP

	3 - METHOD

	4 - PATH

	5 - PROTOCOL

	6 - STATUS_CODE

	7 - BYTES

	8 - REFERRER

	9 - USER_AGENT
	'''

	lexeme = ""

	char = ' '

	tokens = []

	in_double_quote = 0

	seen_dash = 0

	file = open(sys.argv[1],'r')

	'''
	For now there is bug where PATH is parsed incorrectly

	when there is a SQL Injection Payload.

	To fix that when you hit the else conditional check if the

	number of lexemes in the tokens list is 4. If that's the case

	we are now parsing PATH.

	It is much easier to parse METHOD, PATH, and PROTOCOL backwards :)

	Same is true for USER_AGENT.

	PATH can be separated by whitespace thanks to SQL Injection (thanks

	a lot attacker)

	USER_AGENT can be seperated by whitespace

	That's why you can read both backwards.

	In fact only for METHOD PATH PROTOCOL should you read the entire

	in double-quote string backwards.

	For USER_AGENT just scan the whole double-quote string.
	'''

	while 1:

		if char == '\n':
			#print("tokens line: ")
			#print(tokens)
			parse_tokens_list(tokens,summary_table,most_common_codes_table,top_ips,suspicious_user_agents,severity_list,failed_logins)
			tokens.clear()
			seen_dash = 0
			char = file.read(1)

		elif char.isspace():
			while char != '\n' and char.isspace():
				char = file.read(1)

		elif not char:
			break

		elif char == '-' and seen_dash == 0:
			
			seen_dash = 1
		
			char = file.read(1)
		
			continue

		elif char == '-' and seen_dash == 1:

			tokens.append("-")

			char = file.read(1)

			continue
			

		elif char == '[':
			
			char = file.read(1)
			
			lexeme = ""

			while char != ']':

				lexeme += char
				
				char = file.read(1)

			tokens.append(lexeme)	

			char = file.read(1)

		elif char == '"':

			quote_string = ""
			
			char = file.read(1)

			while char != '"':

				quote_string += char

				char = file.read(1)

			if len(tokens) == 3:
				parse_endpoint(tokens,quote_string)

			elif len(tokens) == 8 or len(tokens) == 9:
				tokens.append(quote_string)

			else:
				print(f"Error for double quote string ; index = {len(tokens)}")		
				print(f"token_list: {tokens}")

			char = file.read(1)

					
		else:
			lexeme = ""

			while char != '"' and not char.isspace():

				lexeme += char
				
				char = file.read(1)
				
			tokens.append(lexeme)


	for ip, val in top_ips.items():

		if ip in failed_logins and failed_logins[ip][0] >= 3:
		
			severity = {}

			severity.update({"severity": "LOW"})

			severity.update({"finding_type": "BRUTE_FORCE"})

			severity.update({"ip": ip})
			
			severity.update({"description": f"{failed_logins[ip][0]} failed login attempts detected"})

			severity.update({"failed_request_count": failed_logins[ip][0]})
			
			severity.update({"target_path": failed_logins[ip][1]})

			severity_list.append(severity)

	final_raw_dict = {}

	final_raw_dict.update({"summary": summary_table})	

	top_ips_desc = dict(Counter(top_ips).most_common())

	top_ips_list = []

	suspicious_agents_list = []

	for ip, requests in top_ips_desc.items():
		top_ips_list.append({ "ip" : ip, "requests" : requests })
		
	final_raw_dict.update({"top_ips" : top_ips_list})

	final_raw_dict.update({"security_findings": severity_list})

	for agent, freq in suspicious_user_agents.items():
		suspicious_agents_list.append({"user_agent" : agent,"count" : freq})

	final_raw_dict.update({"suspicious_user_agents": suspicious_agents_list})

	final_json_resp = json.dumps(final_raw_dict,indent=4)

	file.close()

	return final_json_resp

def main():
	print(parse_log())


if __name__ == "__main__":
	main()
