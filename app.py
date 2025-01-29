import sqlite3
import base64
from flask import Flask, redirect, render_template, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# XOR Encryption Function with Base64 encoding for safe printable output
def xor_encrypt(text, key):
    encrypted_bytes = bytes([ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(text)])
    # Convert the encrypted bytes to a Base64 string for safe transmission
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_base64

# XOR Decryption Function with Base64 decoding
def xor_decrypt(encrypted_text, key):
    try:
        # Decode the Base64 string back to bytes
        encrypted_bytes = base64.b64decode(encrypted_text)
        # Perform XOR decryption
        decrypted_text = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(encrypted_bytes))
        return decrypted_text
    except Exception as e:
        print(f"Decryption error: {e}")
        return f"Error during decryption: {e}"

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text = data.get('text')
    key = data.get('key')

    if text and key:
        encrypted_text = xor_encrypt(text, key)
        return jsonify({"encrypted_text": encrypted_text})

    return jsonify({"error": "Missing text or key"}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_text = data.get('encrypted_text')
    key = data.get('key')

    if encrypted_text and key:
        decrypted_text = xor_decrypt(encrypted_text, key)
        return jsonify({"decrypted_text": decrypted_text})

    return jsonify({"error": "Missing encrypted text or key"}), 400

# Database setup
DATABASE = "users.db"

def init_db():
    """Initialize the database and create the users table if it doesn't exist."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/registration", methods=["GET", "POST"])
def registration():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        verify_password = request.form.get("verify_password")

        if not username or not password or not verify_password:
            return jsonify({"status": "error", "message": "All fields are required."}), 400

        if password != verify_password:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            return jsonify({"status": "error", "message": "Username already exists. Please choose another one."}), 400

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "message": "Registration successful. Please log in."})
        except sqlite3.Error as e:
            return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500
    return render_template("registration.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password."}), 400


@app.route('/logout')
def logout():
    # Logic to log the user out, e.g., clear session or token
    return redirect('/')  # Redirect to the login page


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
