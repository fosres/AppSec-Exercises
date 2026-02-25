# models.py
from django.db import models
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import os

from dotenv import load_dotenv

import nacl.secret
import nacl.utils

load_dotenv()

class EncryptedField(models.BinaryField):
	"""Custom encrypted field"""
	
	# Use application-wide encryption key
	# The ENCRYPTION KEY can be generated using nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
	
	ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
	
	def get_prep_value(self, value):
		"""Encrypt value before saving to database"""
		if value is None:
			return value
		
		value = value.encode()

		box = nacl.secret.SecretBox(ENCRYPTION_KEY)

		# Encrypt automatically generates and packs nonce

		encrypted = box.encrypt(message)	
			
		return encrypted
	
	def to_python(self, value):
		"""Decrypt value when retrieving from database"""
		if value is None:
			return value
		
		box = nacl.secret.SecretBox(ENCRYPTION_KEY)

		plain = box.decrypt(value)
	
		return plain

class MedicalRecord(models.Model):
	patient_id = models.IntegerField()
	diagnosis = EncryptedField()
	treatment = EncryptedField()
	notes = EncryptedField()
	created_at = models.DateTimeField(auto_now_add=True)
