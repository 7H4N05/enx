from flask import Flask, request, jsonify, render_template
import hashlib
import base64

app = Flask(__name__)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" 
SECRET_KEY = b"Albus Dumbledore"  
ENCRYPTED_FLAG = base64.b64encode(bytes([b ^ SECRET_KEY[i % len(SECRET_KEY)] for i, b in enumerate(b"phxCTF{S3cur3_H4sh1ng_1s_1mp0rt4nt}")]))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    if username != ADMIN_USERNAME:
        return jsonify({"message": "Invalid credentials"}), 401

    if "debug" in request.args:
        return jsonify({"message": f"Debug: Comparing {hashlib.sha256(password.encode()).hexdigest()} with {ADMIN_PASSWORD_HASH}"}), 200

    if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        return jsonify({"message": "Login successful", "encrypted_flag": ENCRYPTED_FLAG.decode()}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/decrypt', methods=['POST'])
def decrypt_flag():
    data = request.json
    key = data.get('key')
    encrypted_flag = data.get('encrypted_flag')

    if not key or not encrypted_flag:
        return jsonify({"message": "Key and encrypted flag are required"}), 400

    try:
        key_bytes = bytes.fromhex(key)
        if len(key_bytes) != 16:
            return jsonify({"message": "Invalid key length"}), 400

        encrypted_bytes = base64.b64decode(encrypted_flag)
        decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes)])
        
        return jsonify({"decrypted_flag": decrypted.decode()}), 200
    except:
        return jsonify({"message": "Decryption failed"}), 400

@app.route('/hint', methods=['GET'])
def hint():
    part = request.args.get('part', default='0')
    try:
        index = int(part)
        if 0 <= index < len(SECRET_KEY):
            return jsonify({"hint": SECRET_KEY[index].to_bytes(1, 'big').hex()}), 200
        else:
            return jsonify({"message": "Invalid part number"}), 400
    except ValueError:
        return jsonify({"message": "Invalid part number"}), 400

if __name__ == '__main__':
    app.run(debug=True)