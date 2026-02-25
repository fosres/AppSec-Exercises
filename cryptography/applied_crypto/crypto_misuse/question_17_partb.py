## Part B: TLS Certificate Review

The Engineering Team is deploying this API with HTTPS. You inspect their certificate:
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4a:7f:92:3c:d1:8e:5b:22
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=US, ST=CA, O=Company, CN=api.company.com
        Validity
            Not Before: Jan  1 00:00:00 2023 GMT
            Not After : Jan  1 00:00:00 2024 GMT
        Subject: C=US, ST=CA, O=Company, CN=api.company.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus: [omitted]
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: [omitted]
            X509v3 Authority Key Identifier: [omitted]
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha1WithRSAEncryption
