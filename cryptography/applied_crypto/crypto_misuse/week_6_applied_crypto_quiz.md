Ans to Question 1:

Vulnerability:

Code Snippet:

```
import random
import string

def generate_session_token(username):
    random.seed(12345)  # Fixed seed for consistency
    token = ''.join(random.choice(string.ascii_letters) for _ in range(32))
    return token
```

Use of `random` module is insecure for cryptographic purposes!

The seed 1234 makes the tokens generated predictable!

An attacker can run the code on their own server and regenerate the

exact same token!

Use the `secrets` module instead.

Mitigation:

```
import secrets 
import string

def generate_session_token(username):
    alphabet = string.ascii_letters
    token = ''.join(secrets.choice(alphabet) for i in range(32)) 
    return token
```

Question 2:

Code Snippet:

```
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def create_token(user_id, role, permissions):
    token = {
        "user_id": user_id,
        "role": role,              # "admin" or "user"
        "permissions": permissions  # ["read", "write", "delete"]
    }
    
    # Sign only user_id and role for performance
    data = str(user_id) + role
    signature = secret_key.sign(data.encode())
    token["sig"] = signature
    
    return token

def verify_token(token):
    data = str(token["user_id"]) + token["role"]
    public_key.verify(token["sig"], data.encode())
    return token["user_id"], token["role"], token["permissions"]
```

Vulnerabilities:

Developer failed to sign all data prior to signing! An attacker

can get away with setting the token to have elevated privileges

since no attempt is made to sign the `permissions` field.

Below is the fix:

```
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

secret_key = Ed25519PrivateKey.generate()
public_key = secret_key.public_key()

def create_token(user_id, role, permissions):
    token = {
        "user_id": user_id,
        "role": role,              # "admin" or "user"
        "permissions": permissions  # ["read", "write", "delete"]
    }
    
    data = str(token["user_id"]) + token["role"] + ''.join(token["permissions"])
    signature = secret_key.sign(data.encode())
    token["sig"] = signature
    
    return token

def verify_token(token):
    data = str(token["user_id"]) + token["role"] + ''.join(token["permissions"])
    public_key.verify(token["sig"], data.encode())
    return token["user_id"], token["role"], token["permissions"]
```
