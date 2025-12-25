#/usr/bin/python3

import sys
import subprocess


cert_chain = subprocess.run(["openssl","s_client","-connect",sys.argv[1]+":443","-servername",sys.argv[1]],capture_output=True,text=True)


file_name = "/tmp/cert_chain.txt"

with open(file_name,"w") as file:
	file.write(cert_chain.stdout)

subprocess.run(["openssl","x509","-noout","-dates","-in",file_name])
