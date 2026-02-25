# The engineering team sends you this encryption code for review

import nacl.secret
from django.db import models
import os
from dotenv import load_dotenv

# Single encryption key for entire application
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")  

class EncryptedUserProfile(models.Model):
    """User profile with encrypted fields"""
    
    user_id = models.IntegerField()
    email_encrypted = models.BinaryField()
    ssn_encrypted = models.BinaryField()
    
    def encrypt_field(self, value):
        """Encrypt sensitive data"""
        box = nacl.secret.SecretBox(ENCRYPTION_KEY)
        return box.encrypt(value.encode())
    
    def decrypt_field(self, value):
        """Decrypt sensitive data"""
        box = nacl.secret.SecretBox(ENCRYPTION_KEY)
        return box.decrypt(value).decode()

# views.py
def export_backup(request):
    """Export user database backup"""
    # Export entire users table including encrypted fields
    users = EncryptedUserProfile.objects.all()
    backup_file = create_backup(users)
    
    # Store backup in S3 bucket
    s3_client.upload_file(backup_file, 'company-backups', 'users_backup.sql')
    
    return JsonResponse({'status': 'backup complete'})
