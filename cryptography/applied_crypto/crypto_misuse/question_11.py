from flask import Flask, request, jsonify
import datetime
import hmac
import hashlib
import time

from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from dotenv import load_dotenv
import os

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["5/minute"],
    storage_uri="memory://",
)

# Shared secret with webhook sender

# Do NOT hardcode API SECRET in codebase!

# No rate-limiting

load_dotenv()

API_SECRET = os.getenv("API_SECRET")

@app.route('/webhook', methods=['POST'])
@limiter.limit("5/minute")
def receive_webhook():
	"""Receive and verify signed webhook requests"""
	
	# Get signature from header
	received_signature = request.headers.get('X-Signature')

	if not received_signature:
		
		return jsonify({"error": "Invalid signature"}), 401

		
	
	# Get timestamp from header
	timestamp = request.headers.get('X-Timestamp')

	if not timestamp:

		return jsonify({"error": "No timestamp"}), 400

	
	# Get request body
	body = request.get_data().decode()

	# No check if HMAC Signature expired!

	# Check if HMAC signature expired here. The expiration

	# date must be set at the creation time of the HMAC

	# signature before being sent to the user, whose code

	# this question does not show.

	# So I leave a comment here about it.

	# Compute expected signature
	message = f"{timestamp}{body}"
	expected_signature = hmac.new(
		API_SECRET.encode(),
		message.encode(),
		hashlib.sha512
	).hexdigest()

	# Timing Vulnerability	
	# Verify signature
	if hmac.compare_digest(received_signature,expected_signature):
		print(f"✓ Valid signature from {request.remote_addr}")

		current_time = datetime.datetime.now()

		expiration_time = timestamp + datetime.timedelta(seconds=300)
	
		if current_time > expiration_time: 		
			
			return jsonify({"error": "Invalid Timestamp"}), 400

		# Process webhook
		data = request.get_json()
		process_payment(data['amount'], data['customer_id'])
		
		return jsonify({"status": "success"})
	else:
		return jsonify({"error": "Invalid signature"}), 401

