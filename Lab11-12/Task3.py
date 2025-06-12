import hmac
import hashlib

# Step 1: Input original message and secret key
message = input("Enter the original message: ")
secret_key = input("Enter the secret key: ")

# Convert to bytes
message_bytes = message.encode()
secret_key_bytes = secret_key.encode()

# Step 2: Generate HMAC using SHA-256
original_hmac = hmac.new(secret_key_bytes, message_bytes, hashlib.sha256).hexdigest()
print("\nOriginal HMAC:", original_hmac)

# Step 3: Modify the message (simulated tampering)
tampered_message = message + " (modified)"
tampered_bytes = tampered_message.encode()

# Step 4: Recalculate HMAC for modified message
new_hmac = hmac.new(secret_key_bytes, tampered_bytes, hashlib.sha256).hexdigest()
print("Modified Message:", tampered_message)
print("Modified HMAC:", new_hmac)

# Step 5: Compare and print warning if mismatch
if original_hmac == new_hmac:
    print("\n✅ HMAC matches: Message integrity verified.")
else:
    print("\n❌ WARNING: HMAC does not match! Message integrity compromised.")
