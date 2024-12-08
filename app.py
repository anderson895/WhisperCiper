import sqlite3
from flask import Flask, render_template, request, jsonify

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

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/registration", methods=["GET", "POST"])
def registration():
    if request.method == "GET":
        return render_template("registration.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        verify_password = request.form.get("verify_password")

        # Validate passwords match
        if password != verify_password:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        # Save user to the database
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "message": "Registration successful. Please log in."})
        except sqlite3.IntegrityError:
            return jsonify({"status": "error", "message": "Username already exists. Please choose another one."}), 400

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # Validate user credentials
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid username or password."}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
