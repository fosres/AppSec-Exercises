# https://coderivers.org/blog/python-socket-timeout/

import sys
import socket

def scan_port(host: str, port: int, timeout: float) -> tuple:
	"""
	Scan a single port, return (port, status).
	
	Returns:
		tuple: (port_number, status_string)
		Example: (80, "OPEN") or (443, "CLOSED")
	"""

	if timeout < 1.0 or timeout > 2.0:

		print(f"{timeout} out of range ; 1.0 <= timeout <= 2.0")

		return "ERROR"

	if port < 1 or port > 65535:

		print(f"ERROR: Port {port} is invalid (must be 1-65535")

		return "ERROR"

	s = socket.socket()

	s.settimeout(timeout)

	try:
		s.connect((host,port))

		print(f"Port {port} on {host} is OPEN")

		return "OPEN"

	except socket.timeout:

		print(f"Port {port} on {host} is FILTERED")

		return "FILTERED"

	except ConnectionRefusedError:

		print(f"Port {port} on {host} is CLOSED")	

		return "CLOSED"

	except socket.gaierror:

		print(f"ERROR: Cannot resolve hostname '{host}'")

		return "ERROR"

	finally:
		s.close()	

scan_port("example.com",65,1.0)
