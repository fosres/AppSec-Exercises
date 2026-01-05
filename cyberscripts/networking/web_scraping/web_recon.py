import requests
import sys
import validators
import os

from http.client import responses

def print_resp_codes(url):
	
	try:
	
		resp = requests.get(url)
		
		headers = resp.headers

		security_points = 0

		medium_vulns = 0

		medium_vulns_str = ""

		info_vulns = 0

		info_vulns_str = ""
		
		print(f"[*] Starting reconnaissance on: {url}\n") 	

		if 'Date' in headers:
			print(f"[*] Time: {headers['Date']}\n") 	

		else:
			print(f"[*] Time: (not present)\n") 	

		print("═══ RESPONSE STATUS ═══\n")
		
		if resp.status_code in {301,302}:

			print(f"Relocation for {url} detected:\n")

			print_resp_codes(headers['Location'])

		else:
			print(f"Status Code: {resp.status_code}\n")
			
		print(f"Status Message: {responses[resp.status_code]}\n")

		print(f"HTTP Version: HTTP/{resp.raw.version / 10}\n")
		
		print(f"Response Time: {resp.elapsed.total_seconds():.3f}s\n")

		print("═══ SERVER INFORMATION ═══\n")

		if 'Server' in headers:

			print(f"Server: {headers['Server']}\n")

			info_vulns += 1

			info_vulns_str += f"- Server: {headers['Server']}\n"

		else:
			print("Server: (not present)\n")
			
		if 'X-Powered-By' in headers:
			
			print(f"X-Powered-By: {headers['X-Powered-By']}\n")
			
			info_vulns += 1

			info_vulns_str += f"- X-Powered-By: {headers['X-Powered-By']}\n"

		else:
			print("X-Powered-By: (not present)\n")

		if 'X-AspNet-Version' in headers:
			
			print(f"X-AspNet-Version: {headers['X-AspNet-Version']}\n")
			
			info_vulns += 1

			info_vulns_str += f"- X-AspNet-Version: {headers['X-AspNet-Version']}\n"

		else:
			print("X-AspNet-Version: (not present)\n")

		if 'X-Generator' in headers:
			
			print(f"X-Generator: {headers['X-Generator']}\n")
			
			info_vulns += 1

			info_vulns_str += f"- X-Generator: {headers['X-Generator']}\n"
		
		else:
			print("X-Generator: (not present)\n")

		if 'X-Drupal-Cache' in headers:
			
			print(f"X-Drupal-Cache: {headers['X-Drupal-Cache']}\n")
			
			info_vulns += 1

			info_vulns_str += f"- X-Drupal-Cache: {headers['X-Drupal-Cache']}\n"

		else:
			print("X-Drupal-Cache: (not present)\n")
	
		if 'X-Varnish' in headers:
			
			print(f"X-Varnish: {headers['X-Varnish']}\n")
			
			info_vulns += 1

			info_vulns_str += f"- X-Varnish: {headers['X-Varnish']}\n"

		else:
			print("X-Varnish: (not present)\n")

		print("═══ SECURITY HEADERS ═══\n")

		if 'X-Frame-Options' in headers:
			
			print(f"X-Frame-Options: {headers['X-Frame-Options']}\n")

			security_points += 1

		else:
			print("X-Frame-Options: (not present)\n")
			
			medium_vulns += 1

			medium_vulns_str += "- Missing X-Frame-Options\n"

		if 'X-Content-Type-Options' in headers:
			
			print(f"X-Content-Type-Options: {headers['X-Content-Type-Options']}\n")
			security_points += 1
		else:
			print("X-Content-Type-Options: (not present)\n")
			
			medium_vulns += 1

			medium_vulns_str += "- Missing X-Content-Type-Options\n"

		if 'X-XSS-Protection' in headers:
			
			print(f"X-XSS-Protection: {headers['X-XSS-Protection']}\n")

			security_points += 1
		else:
			print("X-XSS-Protection: (not present)\n")

		if 'Strict-Transport-Security' in headers:
			
			print(f"Strict-Transport-Security: {headers['Strict-Transport-Security']}\n")
			security_points += 1
		else:
			print("Strict-Transport-Security: (not present)\n")
			
			medium_vulns += 1

			medium_vulns_str += "- Missing HSTS\n"

		if 'Content-Security-Policy' in headers:
			
			print(f"Content-Security-Policy: {headers['Content-Security-Policy']}\n")
			security_points += 1
		else:
			print("Content-Security-Policy: (not present)\n")

			medium_vulns += 1

			medium_vulns_str += "- Missing Content-Security-Policy\n"

			

		if 'Referrer-Policy' in headers:
			
			print(f"Referrer-Policy: {headers['Referrer-Policy']}\n")

			security_points += 1
		else:
			print("Referrer-Policy: (not present)\n")

		if 'Permissions-Policy' in headers:
			
			print(f"Permissions-Policy: {headers['Permissions-Policy']}\n")

			security_points += 1

		else:
			print("Permissions-Policy: (not present)\n")
			
			info_vulns += 1

			info_vulns_str += "- Permissions-Policy: (not present)\n"
	
		print("═══ COOKIES ═══\n")

		cookie_security_score = 0

		cookie_total_score = 0

		if 'Set-Cookie' in headers:

			i = 0

			for cookie in resp.cookies:

				cookie_total_score += 3

				print(f"Cookie {i+1}: {cookie.name}")				
				print(f"Value: {cookie.value}")				
				
				print(f"HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")				
				if cookie.has_nonstandard_attr('HttpOnly'):
			
					cookie_security_score += 1
				else:
				
					medium_vulns += 1

					medium_vulns_str += "- Cookie missing HttpOnly\n"
				
				print(f"Secure: {cookie.secure}")			
				
				if cookie.secure == True:
			
					cookie_security_score += 1

				else:
					medium_vulns += 1

					medium_vulns_str += "- Cookie missing Secure\n"
		
				# Remember each item in the list stores
				# complete info for a cookie
				# Bug: Fix indexing for the write cookie!
				
				cookie_list = resp.raw.headers.getlist('Set-Cookie')[i]

				if "SameSite=" in cookie_list: 

					index = cookie_list.find("SameSite=") + len("SameSite=")
					samesite_val = ""

					while index < len(cookie_list) and cookie_list[index].isalpha():
						samesite_val += cookie_list[index]

						index += 1

					if samesite_val != "None":

						cookie_security_score += 1
					
					print(f"SameSite: {samesite_val}")			
				else:
					print(f"SameSite: (not set)")		
					
					medium_vulns += 1

					medium_vulns_str += "- Cookie missing SameSite\n"
		
				print(f"Domain: {cookie.domain}")				
				print(f"Path: {cookie.path}")				

				print(f"Max-Age: {cookie.expires}\n")				
				i += 1

		else:
			print("No cookies set.\n")

		print("═══ CORS CONFIGURATION ═══\n")

		cors_count = 0

		critical_var = 0

		if 'Access-Control-Allow-Origin' in headers:
			
			print(f"Access-Control-Allow-Origin: {headers['Access-Control-Allow-Origin']}\n")

			cors_count += 1
	
		if 'Access-Control-Allow-Credentials' in headers:
			
			print(f"Access-Control-Allow-Credentials: {headers['Access-Control-Allow-Credentials']}\n")

			cors_count += 1

		if 'Access-Control-Allow-Origin' in headers and 'Access-Control-Allow-Credentials' in headers:
			if headers['Access-Control-Allow-Origin'] == "*" and headers['Access-Control-Allow-Credentials'] == "true":
			
				critical_var = 1
		
		if 'Access-Control-Allow-Methods' in headers:
			
			print(f"Access-Control-Allow-Methods: {headers['Access-Control-Allow-Methods']}\n")

			cors_count += 1
	
		if 'Access-Control-Allow-Headers' in headers:
			
			print(f"Access-Control-Allow-Headers: {headers['Access-Control-Allow-Headers']}\n")

			cors_count += 1

		if cors_count == 0:

			print("No CORS headers present.\n")
		
		print("═══ ADDITIONAL INFORMATION ═══\n")

		if 'Content-Type' in headers:
			
			print(f"Content-Type: {headers['Content-Type']}\n")

		else:
			print("Content-Type: (not present)\n")

		if 'Content-Length' in headers:
			
			print(f"Content-Length: {headers['Content-Length']}\n")

		else:
			print("Content-Length: (not present)\n")

		if 'Content-Encoding' in headers:
			
			print(f"Content-Encoding: {headers['Content-Encoding']}\n")

		else:
			print("Content-Encoding: (not present)\n")

		if 'Cache-Control' in headers:
			
			print(f"Cache-Control: {headers['Cache-Control']}\n")

		else:
			print("Cache-Control: (not present)\n")

		if 'ETag' in headers:
			
			print(f"ETag: {headers['ETag']}\n")

		else:
			print("ETag: (not present)\n")
	
		print("Interesting Headers Found:\n")
		
		if 'X-Request-ID' in headers:
			
			print(f"- X-Request-ID: {headers['X-Request-ID']}\n")

		if 'X-RateLimit-Remaining' in headers:
			
			print(f"- X-RateLimit-Remaining: {headers['X-RateLimit-Remaining']}\n")
			info_vulns += 1

			info_vulns_str += f"- X-RateLimit-Remaining: {headers['X-RateLimit-Remaining']}\n"

		if 'Via' in headers:
			
			print(f"- Via: {headers['Via']}\n")
		
			info_vulns += 1

			info_vulns_str += f"- Via: {headers['Via']}\n"

		print(f"CRITICAL ({critical_var})\n")

		if critical_var == 1:

			print("Wildcard origin (*) with Allow-Credentials is a security vulnerability!")
	
		print(f"MEDIUM ({medium_vulns}):\n")

		if medium_vulns > 0:

			print(medium_vulns_str)

		print(f"INFO ({info_vulns}):\n")

		if info_vulns > 0:

			print(info_vulns_str)

		print(f"Security Header Score: {security_points}/7\n")
	
		if cookie_total_score > 0:			
			
			print(f"Cookie Security Score: {cookie_security_score} / {cookie_total_score} ; {cookie_security_score / cookie_total_score * 100:.3f}%")

	except requests.exceptions.HTTPError as errh:

		print(f"HTTP Error: {errh.args[0]}")

def main():
	
	if len(sys.argv) != 2:

		print("Improper arguments. Aborting.")

		exit(1)

	arg = sys.argv[1]

	if arg in os.listdir('.'):

		with open(sys.argv[1],'r') as file:

			for line in file:

				url = line.strip()

				if len(url) > 0 and url[0] == '#':

					continue

				elif len(url) > 0 and validators.url(url):
					
					print_resp_codes(url)				
	elif validators.url(arg):
		print_resp_codes(arg)

	else:

		print("Neither file nor URL found. Aborting\n")

		exit(3)
	
if __name__ == "__main__":
	main()
