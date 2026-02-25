server {
    listen 443 ssl;
    server_name medical-records.example.com;

    
    # SSL Certificate
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # SSL Protocol Configuration

    # Only allow TLSv1.2 and TLSv1.3
    ssl_protocols TLSv1.2 TLSv1.3;
   
    # Outdated ciphers used!
 
    # Cipher Suite Configuration
    ssl_ciphers 'AES128-GCM-SHA256:AES256-GCM-SHA384';

    ssl_prefer_server_ciphers on;
    
    # Session Cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Best practice to enable OCSP Stapling
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}
```

**Certificate Details:**
```
# TLS Certificate for medical-records.example.com is expired

Certificate Chain:
1. medical-records.example.com (leaf certificate)
   Issuer: IntermediateCA
   Valid: 2026-01-01 to 2026-03-01
   
2. IntermediateCA (intermediate certificate)
   Issuer: RootCA
   Valid: 2020-01-01 to 2030-01-01
   
3. RootCA (root certificate)
   Issuer: RootCA (self-signed)
   Valid: 2015-01-01 to 2035-01-01
