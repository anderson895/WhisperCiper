import sqlite3
from flask import Flask, render_template, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

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

@app.route("/login")
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

        # Debugging: Print data to verify it's received
        print("Received data:", username, password, verify_password)

        # Ensure all required fields are present
        if not username or not password or not verify_password:
            return jsonify({"status": "error", "message": "All fields are required."}), 400

        # Validate passwords match
        if password != verify_password:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        # Check if the username already exists
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        conn.close()

        if existing_user:
            return jsonify({"status": "error", "message": "Username already exists. Please choose another one."}), 400

        # Hash the password before saving
        hashed_password = generate_password_hash(password)

        # Save user to the database
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

    # Validate user credentials
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):  # Check if password matches the hash
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password."}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
