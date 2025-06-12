from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import hashes, serialization # type: ignore
from cryptography.exceptions import InvalidSignature # type: ignore

# 1. Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

public_key = private_key.public_key()

# 2. Take message input from user
message = input("Enter the message to sign: ").encode()

# 3. Sign the message using the private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print("\n🔏 Message signed successfully.")
print("Signature:", signature.hex())

# 4. Verify the signature using the public key
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\n✅ Signature Verified.")
except InvalidSignature:
    print("\n❌ Signature Invalid.")
