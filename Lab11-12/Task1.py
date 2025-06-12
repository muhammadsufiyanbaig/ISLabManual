import hmac
import hashlib

def generate_hmac(message: str, key: str) -> str:
    key_bytes = key.encode()
    message_bytes = message.encode()
    hmac_result = hmac.new(key_bytes, message_bytes, hashlib.sha256)
    return hmac_result.hexdigest()

# Input from user
message = input("Enter the original message: ")
key = input("Enter the secret key: ")

# Generate HMAC for original message
original_hmac = generate_hmac(message, key)
print("\nOriginal HMAC:", original_hmac)

# Modify the message
modified_message = message + " (tampered)"
modified_hmac = generate_hmac(modified_message, key)
print("\nModified Message:", modified_message)
print("Modified HMAC:", modified_hmac)

# Compare
if original_hmac == modified_hmac:
    print("\n✅ HMAC matches: Message integrity verified.")
else:
    print("\n❌ HMAC mismatch: Message has been tampered with!")
