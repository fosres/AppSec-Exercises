import jwt

import time,datetime
from datetime import timezone

payload = 	{
			"user_id" : 0,

			"name" : "myname",

			"exp" : datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=3600)
		}

secret = "secret"

encode_jwt = jwt.encode(payload,secret,algorithm="HS256")

print(f"Encoded: {encode_jwt}")

decode_jwt = jwt.decode(encode_jwt,secret,algorithms=["HS256"])

print(f'Decoded: {decode_jwt}')

# Change expiration to -1 hours

payload = 	{
			"user_id" : 0,

			"name" : "myname",

			"exp" : datetime.datetime.now(tz=timezone.utc) - datetime.timedelta(seconds=3600)
		}

encode_jwt = jwt.encode(payload,secret,algorithm="HS256")

print(f"Encoded: {encode_jwt}")

decode_jwt = jwt.decode(encode_jwt,secret,algorithms=["HS256"])

print(f'Decoded: {decode_jwt}')
