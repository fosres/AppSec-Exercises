import jwt
from datetime import datetime, timedelta

# Not a good idea to hardcode the secret in code below:

SECRET = "my-secret-key"

payload = {
    "user_id": 123,
    "username": "alice",
    "exp": datetime.utcnow() + timedelta(hours=1)
}

#token = jwt.encode(payload, SECRET, algorithms=["HS256"])
token = jwt.encode(payload, SECRET, algorithm="HS256")
print(f"Token created: {token}")

decoded = jwt.decode(token, SECRET,algorithms=["HS256"])

print(f'User ID: {decoded["user_id"]}')
print(f'Username: {decoded["username"]}')
