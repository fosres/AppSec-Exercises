import jwt

payload = 	{
			"user_id" : 0,

			"name" : "myname"
		}

secret = "secret"

encode_jwt = jwt.encode(payload,secret,algorithm="HS256")

print(f"Encoded: {encode_jwt}")

decode_jwt = jwt.decode(encode_jwt,secret,algorithms=["HS256"])

print(f'Decoded: {decode_jwt}')
