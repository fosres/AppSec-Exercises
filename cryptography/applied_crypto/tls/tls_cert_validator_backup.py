import json
import sys

def parse_version_number(version_num_line):

	version_line_split = version_num_line.split()

	return int(version_line_split[1])

	
def validate_tls_certificate(text_file, hostname):
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

			## Check 7 is a logic test on what is in

			## Subject Alternative Names List
			
			# Check 8

			"X509v3 Basic Constraints" : "",
			
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

			"X509v3 CRL Distribution Points" : [],
			
			# Check 12

			"Authority Information Access" : "",

			# Check 13

			"OCSP" : "",	
			
			# Check 14

			"CT Precertificate SCTs" : [],

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
					
					table["Subject"] = line.split(":")[1].strip()
				
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

					
						table["X509v3 Subject Alternative Name"] = hostname_list

					# Case where each DNS

					# query is in each

					# line

					else:

						hostname = line.split(":")[1].strip()

						hostname_list.append(hostname)
					
						table["X509v3 Subject Alternative Name"].append(hostname_list)
				# Check 8

				elif "X509v3 Basic Constraints:" in line:
					
					table["X509v3 Basic Constraints"] = line.split(":")[1].strip()
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

				elif "X509v3 Extended Key Usage" in line:
					
					table["X509v3 Extended Key Usage"]["Present"] = 1
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
				# Check 10
					
				elif "URI:" in line:
				
					uri_line = line.split("URI:")[1].strip()
	
					table["X509v3 CRL Distribution Points"].append(uri_line) 

		print(json.dumps(table,indent=4))
			

	except FileNotFoundError:

		raise Exception("File Not Found")

	except PermissionError:

		raise Exception("Insufficient file permissions")

	except Exception as e:

		raise Exception("Unexpected error")	

		
def main():

	if len(sys.argv) != 2:

		raise Exception("Usage: python3 tls_cert_validator.py [text version of TLS certificate]")

	validate_tls_certificate(sys.argv[1],"www.example.com")
	
if __name__=="__main__":

	main()
