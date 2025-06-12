# # 1. Program to Generate Hashes Using Different Algorithms

# import hashlib

# def generate_hash(data, algorithm):
#     hash_obj = hashlib.new(algorithm)
#     hash_obj.update(data.encode('utf-8'))
#     return hash_obj.hexdigest()

# # Example usage
# data = "Hello, Cybersecurity!"
# algorithms = ['sha256', 'sha512', 'blake2b', 'sha3_256']

# for algo in algorithms:
#     print(f"{algo.upper()} Hash: {generate_hash(data, algo)}")

# # 2. Program to Verify File Integrity Using Hashing

# import hashlib

# def calculate_file_hash(file_path, algorithm='sha256'):
#     hash_obj = hashlib.new(algorithm)
    
#     with open(file_path, 'rb') as file:
#         while chunk := file.read(4096):
#             hash_obj.update(chunk)

#     return hash_obj.hexdigest()

# # Example usage
# file_path = "sample.txt"
# print(f"SHA-256 Hash of file: {calculate_file_hash(file_path, 'sha256')}")
# print(f"SHA-512 Hash of file: {calculate_file_hash(file_path, 'sha512')}")

# # 3. Program to Hash Passwords Using Bcrypt

# import bcrypt

# def hash_password(password):
#     salt = bcrypt.gensalt()
#     hashed_password = bcrypt.hashpw(password.encode(), salt)
#     return hashed_password

# def verify_password(password, hashed_password):
#     return bcrypt.checkpw(password.encode(), hashed_password)

# # Example usage
# password = "$Uf!y@n3"
# hashed_pwd = hash_password(password)
# print(f"Hashed Password: {hashed_pwd}")

# # Verify Password
# print(f"Password Match: {verify_password(password, hashed_pwd)}")

# # 4. Program to Compare Hash Collisions (MD5 vs. SHA-256)

# import hashlib

# def check_hash_collision(data1, data2, algorithm):
#     hash1 = hashlib.new(algorithm)
#     hash1.update(data1.encode())

#     hash2 = hashlib.new(algorithm)
#     hash2.update(data2.encode())

#     return hash1.hexdigest(), hash2.hexdigest(), hash1.hexdigest() == hash2.hexdigest()

# # Example usage
# data1 = "hello123"
# data2 = "hello124"  # Slightly different input

# md5_hash1, md5_hash2, md5_match = check_hash_collision(data1, data2, 'md5')
# sha256_hash1, sha256_hash2, sha256_match = check_hash_collision(data1, data2, 'sha256')

# print(f"MD5 Hashes:\n {md5_hash1}\n {md5_hash2}\n Collision: {md5_match}")
# print(f"SHA-256 Hashes:\n {sha256_hash1}\n {sha256_hash2}\n Collision: {sha256_match}")

# # 5. How to Run These Programs
# #   a. Install necessary dependencies (for bcrypt):
# #   b. pip install bcrypt
# #   c. Save each script as a .py file.
# #   d. Run in a Python environment.

import bcrypt

# Sample password
password = "$Uf!y@n3"

# Generate salt and hash password
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)

print("Salt:", salt)
print("Hashed password:", hashed)
