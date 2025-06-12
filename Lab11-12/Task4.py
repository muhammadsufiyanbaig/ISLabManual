from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives import hashes 
from cryptography.exceptions import InvalidSignature 

# 1. Generate first RSA key pair (authorized user)
private_key_1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_1 = private_key_1.public_key()

# 2. Generate second RSA key pair (unauthorized user)
private_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_2 = private_key_2.public_key()

# 3. Message to sign
message = input("Enter a message to sign: ").encode()

# 4. Sign message with private_key_1
signature = private_key_1.sign(
    message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

print("\n🔏 Message signed successfully using authorized private key.")

# 5. Attempt verification with unauthorized public_key_2
print("\n🔐 Trying to verify using an unauthorized public key...")

try:
    public_key_2.verify(
        signature,
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("✅ Signature Verified. (Unexpected!)")
except InvalidSignature:
    print("❌ Signature Invalid. Unauthorized user cannot verify the signature.")
