import fnmatch
import json
import sys

from dateutil import parser

from datetime import datetime

from dateutil import tz

from pathlib import Path

def parse_version_number(version_num_line):

	version_line_split = version_num_line.split()

	return int(version_line_split[1])


def list_of_tlds() -> list[str]:

	tlds = []

	with open("tlds-alpha-by-domain.txt") as file:

		try:

			for line in file:

				if line[0] == '#':

					continue	

				else:

					tlds.append("*." + line.strip().lower())

		except FileNotFoundError:

			raise Exception("tlds-alpha-by-domain.txt not found")

		except Exception:

			raise Exception("Unexpected error in list_of_tlds()")
	return tlds

def dns_wildcard_match(hostname,san) -> bool:

	hostname_list = hostname.split(".")

	san_list = san.split(".")

	if len(hostname_list) != len(san_list):

		return False

	i = 0

	while i < len(hostname_list):

		if	(
				hostname_list[i] == "*"

				or

				san_list[i] == "*"
			):

			i += 1

			continue

		elif	(
				hostname_list[i] != san_list[i]
			):

			return False
		
		i += 1

	return True
			
def validate_tls_certificate(text_file,domain=""):
	"""
	Validate TLS certificate against 20-point checklist.

	Args:
	text_file: Path to TEXT certificate file (.txt)
	hostname: Expected hostname (e.g., "www.example.com")

	Returns:
	dict with:
	    - valid: bool (True if all 20 checks pass)
	    - score: int (0-20)
	    - failures: list of failed check descriptions
	"""

	table =	{
			# Check 1

			"Version" : 0, 		

			# Check 2

			"Validity" :	{		

						"Not Before" : "",

						"Not After" : ""
					}, 	

			# Check 3
			
			"Signature Algorithm" : "",

			# Check 4

			"Subject Public Key Info" :	

			{
				"Public Key Algorithm" : "",

				"Public-Key" : 0
			},

			# Check 5

			"Subject" : "",

			# Check 6

			"X509v3 Subject Alternative Name" : [],
		
			"X509v3 SAN critical" : 0,

			# Check 7

			## Check 7 is a logic test on what is in

			## Subject Alternative Names List
			
			# Check 8

			"X509v3 Basic Constraints" : "",
	
			"CA" : "",
			
			# Check 9

			"X509v3 Key Usage" :	{
							"critical" : 0,

							"Values" : []
						},
			
			# Check 10

			"X509v3 Extended Key Usage" :	{
								"Present": 0,

								"Values" : []
							},
			
			# Check 11

			"X509v3 CRL Distribution Points" :	{
									"Present" : 0,

									"Values" : []
								},
			
			# Check 12

			"Authority Information Access" : {

								"CA Issuers" : "",
								
								"OCSP" : ""								
							},

			# Check 13

			
			# Check 14

			"CT Precertificate SCTs" :	{
								"Present" : 0,

								"Log ID List" : []
							},

			# Check 15

			"Issuer" : {},

			"Subject" : {},

			# Check 16

			"Serial Number" : "",

			# Check 17

			"X509v3 Subject Key Identifier" : "",

			# Check 18

			"X509v3 Authority Key Identifier" : "",

			# Check 19: Only checks if
	
			# Subject Key Identifer

			# != Authority Key Identifier

			# Check 20: Validity

			"Duration" : 0 # in days
		}

	try:

		cert_text = ""

		with open(text_file,'r') as file:

			prev_line = ""

			for line in file:	

				# Check 1

				if "Version:" in line:

					table["Version"] = parse_version_number(line)

				# Check 2

				elif "Not Before:" in line:

					table["Validity"]["Not Before"] = line.split("Not Before:")[1].strip()
				elif "Not After :" in line:

					table["Validity"]["Not After"] = line.split("Not After :")[1].strip()

				# Check 3
	
				elif "Signature Algorithm:" in line:
			
					table["Signature Algorithm"] = line.split(":")[1].strip()
					
				# Check 4

				elif "Public Key Algorithm:" in line:
					
					table["Subject Public Key Info"]["Public Key Algorithm"] = line.split(":")[1].strip()
				
				elif "Public-Key:" in line:
				
					key_in_par = line.split(":")[1].strip()

					i = 0
	
					while	(
							i < len(key_in_par)

							and

							not key_in_par[i].isdigit()
						):

						i += 1

					key_size = ""

					while	(
							i < len(key_in_par)

							and

							key_in_par[i].isdigit()
						):

						key_size += key_in_par[i]

						i += 1
			
	
					table["Subject Public Key Info"]["Public-Key"] = int(key_size)
				# Check 5

				elif "Subject:" in line:

					field = {}
						
					field_vals = line.split(":")[1].strip()

					print(f"field_vals:{field_vals}")

					if field_vals == "":

						table["Subject"] = field

					elif "," in line:
					
						field_list = field_vals.split(",")

						i = 0

						while i < len(field_list):

							field_list[i] = field_list[i].strip()
							i += 1

						i = 0
	
						while i < len(field_list):

							key_val_list = field_list[i].split("=")
							if len(key_val_list) != 2:
							
								i += 1

								continue

							
							field[key_val_list[0].strip()] = key_val_list[1].strip()
							i += 1

						table["Subject"] = field 
					else:
							
						field_list = field_vals.split("=")

						i = 0

						field[field_list[0].strip()] = field_list[1].strip()
						table["Subject"] = field 

				# Check 6 checking for "critical" field

				elif	(

						"X509v3 Subject Alternative Name" in line
						and

						"critical" in line	
					):

					table["X509v3 SAN critical"] = 1
				
				# Check 6 appending hostname to list of
				# SANs
				
				elif "DNS:" in line:

					hostname_list = []

					if "," in line:

						hostname_list = line.split(",")

						j = 0

						while j < len(hostname_list):

							hostname_list[j] = hostname_list[j].split(":")[1].strip()	
							j += 1

					
						table["X509v3 Subject Alternative Name"] += hostname_list

					# Case where each DNS

					# query is in each

					# line

					else:

						hostname = line.split(":")[1].strip()

						hostname_list.append(hostname)
					
						table["X509v3 Subject Alternative Name"] += hostname_list
				# Check 8

				elif "X509v3 Basic Constraints:" in line:
					
					table["X509v3 Basic Constraints"] = line.split(":")[1].strip()

				elif "CA:FALSE" in line:

					table["CA"] = "FALSE"

				elif "CA:TRUE" in line:

					table["CA"] = "TRUE"

				# Check 9
				
				elif	(

						"X509v3 Key Usage"in line

						and

						"X509v3 Key Usage: critical" in line

					):
					
					table["X509v3 Key Usage"]["critical"] = 1
			
				elif "Digital Signature" in line:

					table["X509v3 Key Usage"]["Values"].append("Digital Signature")
				elif "Key Encipherment" in line:

					table["X509v3 Key Usage"]["Values"].append("Key Encipherment")
				elif "Certificate Sign" in line:

					table["X509v3 Key Usage"]["Values"].append("Certificate Sign")
				elif "CRL Sign" in line:

					table["X509v3 Key Usage"]["Values"].append("CRL Sign")
				# Check 10

				elif "X509v3 Extended Key Usage" in line:
					
					table["X509v3 Extended Key Usage"]["Present"] = 1

				elif "TLS Web Server Authentication" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("TLS Web Server Authentication")

				elif "Code Signing" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("Code Signing")
				elif "TLS Web Client Authentication" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("TLS Web Client Authentication")
				
				elif "E-mail Protection" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("E-mail Protection")

				elif "Time Stamping" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("Time Stamping")
				elif "OCSP Signing" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("OCSP Signing")
				elif "Document Signing" in line:
					
					table["X509v3 Extended Key Usage"]["Values"].append("Document Signing")
				# Check 11
					
				elif "X509v3 CRL Distribution Points:" in line:
	
					table["X509v3 CRL Distribution Points"]["Present"] = 1 

				elif ".crl" in line:

					url_line = line.split("URI:")[1].strip()
					
					table["X509v3 CRL Distribution Points"]["Values"].append(url_line) 
				# Check 12

				elif "OCSP" in line:

					ocsp_line = line.split("URI:")[1].strip()

					table["Authority Information Access"]["OCSP"] = ocsp_line

				elif "CA Issuers" in line:

					ca_issuers_line = line.split("URI:")[1].strip()

					table["Authority Information Access"]["CA Issuers"] = ca_issuers_line
				# Check 14

				elif "CT Precertificate SCTs" in line:
					
					table["CT Precertificate SCTs"]["Present"] = 1

				elif "Log ID" in line:

					log_id = line.split("Log ID    :")[1].strip()
					
					table["CT Precertificate SCTs"]["Log ID List"].append(log_id)
					
				# Check 15

				elif "Issuer:" in line:

					issue = line.split(":")[1].strip()	

					field_vals = issue.split(",")
					
					field = {}

					i = 0

					while i < len(field_vals):

						field_list = field_vals[i].split("=")

						field[field_list[0].strip()] = field_list[1].strip()				
						i += 1

					table["Issuer"] = field
				
				# Check 16

				elif "Serial Number:" in prev_line:

					serial = line.strip()	

					table["Serial Number"] = serial
				
				# Check 17

				elif "X509v3 Subject Key Identifier:" in prev_line:

					ski = line.strip()	

					table["X509v3 Subject Key Identifier"] = ski

				# Check 18

				elif "X509v3 Authority Key Identifier:" in prev_line:

					aki = line.strip()	

					table["X509v3 Authority Key Identifier"] = aki

				prev_line = line

		# Logic for all fields below

		if domain == "":

			domain = table["Subject"]["CN"]

		print("\nVALIDATION SUMMARY:\n")

		fail_list = []

		# Check 1

		if table["Version"] < 3:

			print(f'CHECK 1:  Version {table["Version"]} - FAIL')

			fail_list.append(1)

		else:	
			print(f'CHECK 1:  Version {table["Version"]} - PASS')

		'''

			# Check 2

			"Validity" :	{		

						"Not Before" : "",

						"Not After" : ""
					}, 	
		'''

		# Check 2

		now = datetime.now(tz.tzlocal())

		now_string = f"{now}"

		current = parser.parse(now_string)
		
		not_before = parser.parse(table["Validity"]["Not Before"])

		not_after = parser.parse(table["Validity"]["Not After"])

		'''
		We expect not_before <= current <= not_after
		'''

		if current < not_before or current > not_after:

			print("CHECK 2:  Not expired/not yet valid - FAIL")

			fail_list.append(2)

		else:
			print("CHECK 2:  Not expired/not yet valid - PASS")

		# Check 3

		allowed_algos =	[
					"sha256WithRSAEncryption",
			
					"sha384WithRSAEncryption",
					
					"sha512WithRSAEncryption",

					"ecdsa-with-SHA256",

					"ecdsa-with-SHA384",
	
					"ecdsa-with-SHA512"

				]

		if table["Signature Algorithm"] not in allowed_algos:

			print(f'CHECK 3: {table["Signature Algorithm"]} signature - FAIL')
			fail_list.append(3)
	
		else:
			print(f'CHECK 3: {table["Signature Algorithm"]} signature - PASS')
		# Check 4

		key_size = table["Subject Public Key Info"]["Public-Key"]			
		key_algo = table["Subject Public Key Info"]["Public Key Algorithm"]

		if	(

				"rsa" in key_algo

				and

				key_size < 2048

			):

			print(f'CHECK 4: RSA-{key_size} weak key - FAIL')

			fail_list.append(4)

		elif	(

				"rsa" in key_algo

				and

				key_size >= 2048

			):

			print(f'CHECK 4: RSA-{key_size} strong key - PASS')
		
		elif	(

				"ec" in key_algo

				and

				key_size < 256

			):

			print(f'CHECK 4: ECDSA P-{key_size} weak key - FAIL')

			fail_list.append(4)

		elif	(

				"ec" in key_algo

				and

				key_size >= 256

			):

			print(f'CHECK 4: ECDSA P-{key_size} strong key - PASS')

		else:
			print(f'CHECK 4: Weak key algorithm - FAIL')

			fail_list.append(4)
			
		# Check 5

		# First check if Subject is Empty but SANs has
		# "critical" and SANS is NOT empty

		if	(

				table["Subject"] == {}

				and
				
				table["X509v3 SAN critical"] == 1
			):

			print("CHECK 5: Subject DN present (minimal ok) - PASS")

		elif	(

				table["Subject"] == {}

				and
				
				table["X509v3 SAN critical"] == 0

			):

			print("CHECK 5: Subject DN NOT present - FAIL")
			
			fail_list.append(5)

		# Check 6

		if	(
				len(table["X509v3 Subject Alternative Name"]) > 0
			):

			print("CHECK 6:  SANs present - PASS")
		
		else:

			print("CHECK 6:  SANs present - FAIL")

			fail_list.append(6)

		# Check 7

		if len(table["X509v3 Subject Alternative Name"]) > 0:

			host_in_sans = 0

			tld_list = list_of_tlds()

			for san in table["X509v3 Subject Alternative Name"]:

				if domain == san:

					host_in_sans = 1

					break

				if san in tld_list:

					continue
				
				if dns_wildcard_match(domain,san):
				
					host_in_sans = 1

					break


			if host_in_sans == 1:

				print("CHECK 7:  Hostname matches a SAN - PASS (would need actual hostname)")
			else:
				print("CHECK 7:  Hostname matches a SAN - FAIL")

				fail_list.append(7)
		else: 	
			print("CHECK 7:  Hostname matches - FAIL (would need actual hostname)")
	
			fail_list.append(7)

		# Check 8

		if	(

				table["X509v3 Basic Constraints"] == "critical"

				and
				
				table["CA"] == "FALSE"	
			):

			print("CHECK 8:  Basic Constraints: CA:FALSE (critical) - PASS")

		else:	
			print("CHECK 8:  Basic Constraints: CA:FALSE (critical) - FAIL")

			fail_list.append(8)

		# Check 9

		ban_list = ["Certificate Sign","CRL Sign"]

		allow_list = ["Digital Signature","Key Encipherment"]
	
		if table["X509v3 Key Usage"]["critical"] == 0:

			print("CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - PASS")	

		elif table["X509v3 Key Usage"]["critical"] == 1:

			ban_found = 0

			allow_found = 0

			for ban in ban_list:

				if ban in table["X509v3 Key Usage"]["Values"]:

					print("CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - FAIL")	
			
					fail_list.append(9)

					ban_found = 1

					break

			for allow in allow_list:

				if allow in table["X509v3 Key Usage"]["Values"]:

					allow_found = 1
					
			if ban_found == 1:	
			
				print("CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - FAIL")	

				fail_list.append(9)

			elif allow_found == 1:

				print("CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - PASS")	

			else:
				print("CHECK 9:  Key Usage: Digital Signature, Key Encipherment (critical, optional) - FAIL")	
				
				fail_list.append(9)
		# Check 10

		if	(

				table["X509v3 Extended Key Usage"]["Present"] == 1

				and
	
				"TLS Web Server Authentication"

				in

				table["X509v3 Extended Key Usage"]["Values"]
				
			):

			print("CHECK 10: Extended Key Usage: TLS Web Server Authentication - PASS")
		else:	
			print("CHECK 10: Extended Key Usage: TLS Web Server Authentication - FAIL")
			fail_list.append(10)
		
		# Check 11

		if	(

				table["X509v3 CRL Distribution Points"]["Present"] == 1

				and

				len(table["X509v3 CRL Distribution Points"]["Values"]) > 0

			):

			print("CHECK 11: CRL Distribution Points present (>=1 URLs REQUIRED) - PASS")

		else:
			print("CHECK 11: CRL Distribution Points present (>=1 URLs REQUIRED) - FAIL")
			fail_list.append(11)

		# Check 12

		if	(
				table["Authority Information Access"]["CA Issuers"] != ""
				or
				
				table["Authority Information Access"]["OCSP"] != ""
			):

			print("CHECK 12: Authority Information Access present - PASS")	
		
		else:

			print("CHECK 12: Authority Information Access present - FAIL")	

			fail_list.append(12)

		# Check 13

		if table["Authority Information Access"]["OCSP"] != "":

			print("CHECK 13: OCSP URL present (optional) - PASS")	
		
		else:

			print("CHECK 13: OCSP URL present (optional) - FAIL")	
			
			fail_list.append(13)
	
		# Check 14

		if len(table["CT Precertificate SCTs"]["Log ID List"]) >= 2:

			print("CHECK 14: Certificate Transparency (>= 2 SCTs) - PASS")

		else:
			print("CHECK 14: Certificate Transparency (>= 2 SCTs) - FAIL")

			fail_list.append(14)

		# Check 15

		if table["Subject"] != table["Issuer"]:

			print("CHECK 15: Not self-signed (Issuer ≠ Subject) - PASS")

		else:
			print("CHECK 15: Not self-signed (Issuer ≠ Subject) - FAIL")

			fail_list.append(15)

		# Check 16

		serial_num = table["Serial Number"].strip().split(":")

		if len(serial_num) < 8:

			print(f"CHECK 16: Valid serial number ({len(serial_num * 8)} bits entropy) - FAIL")
			fail_list.append(16)

		else:
			print(f"CHECK 16: Valid serial number ({len(serial_num * 8)} bits entropy) - PASS")

		# Check 17

		if len(table["X509v3 Subject Key Identifier"]) != 0:

			print("CHECK 17: SKI present (RECOMMENDED, not required for end-entity) - PASS")
		else:
			print("CHECK 17: SKI present (RECOMMENDED, not required for end-entity) - FAIL")
			fail_list.append(17)

		if len(table["X509v3 Authority Key Identifier"]) != 0:

			print("CHECK 18: AKI present - PASS")

		else:
			print("CHECK 18: AKI present - FAIL")
			
			fail_list.append(18)

		# Check 19

		if	(

				table["X509v3 Subject Key Identifier"] != ""

				and

				table["X509v3 Subject Key Identifier"]

				!=

				table["X509v3 Authority Key Identifier"]	

			):
	
			print("CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - PASS")

		elif	(

				table["X509v3 Subject Key Identifier"] == ""
			):
	
			print("CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - PASS")

		else:
			print("CHECK 19: SKI ≠ AKI (CONDITIONAL, both present) - FAIL")
			
			fail_list.append(19)

		# Check 20

		diff = not_after - not_before

		diff_seconds = diff.total_seconds()

		diff_days = diff_seconds / (24 * 60 * 60)

		table["Duration"] = diff_seconds

		# 398 days (max duration in seconds below)

		max_duration_seconds = 398 * 24 * 60 * 60 

		if table["Duration"] > max_duration_seconds:

			print(f'CHECK 20: Validity {diff_days:.1f} > 398 days - FAIL')

			fail_list.append(20)
		else:
			print(f'CHECK 20: Validity {diff_days:.1f} <= 398 days - PASS')

		table["Duration"] = f"{diff_days:.2f}"

		optional_list = [9,13,17]

		final_fail_list = []

		final_optional_list = []

		for item in fail_list:

			if item in optional_list:

				final_optional_list.append(item)
			else:
		
				final_fail_list.append(item)

		if len(final_fail_list) > 0:

			print(f"\nThe following CHECKS FAILED and are REQUIRED:{final_fail_list}\n")

		if len(final_optional_list) > 0:

			print(f"\nThe following CHECKS FAILED and are OPTIONAL:{final_optional_list}\n")

		print("\nCertificate Structure:\n")

		print(json.dumps(table,indent=4))

	except FileNotFoundError:

		raise Exception("File Not Found")

	except PermissionError:

		raise Exception("Insufficient file permissions")

	except Exception as e:

		raise Exception("Unexpected error")	

		
def main():

	if len(sys.argv) > 3:

		raise Exception("Usage: python3 tls_cert_validator.py [hostname] [text version of TLS certificate]")

	domain = sys.argv[1]

	file = sys.argv[2]

	validate_tls_certificate(file,domain)
	
if __name__=="__main__":

	main()
