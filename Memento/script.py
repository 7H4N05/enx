import requests
import json
import base64

BASE_URL = "http://127.0.0.1:5000/"

# Step 1 & 2: Log in and get the encrypted flag
login_data = {"username": "admin", "password": "admin"}
response = requests.post(f"{BASE_URL}/login", json=login_data)
if response.status_code == 200:
    data = response.json()
    encrypted_flag = data['encrypted_flag']
    print(f"Login successful. Encrypted flag: {encrypted_flag}")
else:
    print("Login failed.")
    exit()

# Step 3: Obtain the SECRET_KEY
secret_key = ""
for i in range(16):  # SECRET_KEY is 16 bytes long
    response = requests.get(f"{BASE_URL}/hint?part={i}")
    if response.status_code == 200:
        secret_key += response.json()['hint']
    else:
        print(f"Failed to get hint for part {i}")
        exit()

print(f"Obtained SECRET_KEY: {secret_key}")

# Step 4: Decrypt the flag
decrypt_data = {"key": secret_key, "encrypted_flag": encrypted_flag}
response = requests.post(f"{BASE_URL}/decrypt", json=decrypt_data)
if response.status_code == 200:
    data = response.json()
    decrypted_flag = data['decrypted_flag']
    print(f"Decryption successful. Flag: {decrypted_flag}")
else:
    print("Decryption failed.")