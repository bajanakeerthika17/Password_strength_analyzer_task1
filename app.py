"""
app.py - Flask Web Application & REST API Server
================================================
Author: Password Security Internship Project
Description:
    Provides the backend REST API and serves the frontend for the Password
    Strength Analyzer. Connects with SQLite and performs salted PBKDF2-SHA256
    cryptographic verification.

Endpoints:
    - GET  /                  : Serves the web application user interface
    - POST /api/check-db      : Checks whether a candidate password was previously saved
    - POST /api/save-password : Saves a new password (rejects previously used passwords)
    - GET  /api/history       : Retrieves stored salts and hashes (NO plain text)
    - POST /api/clear-db      : Resets the SQLite database for testing/demos
    - GET  /api/generate      : Generates a cryptographically secure random password
"""

import os
import sys
import secrets
import string

# Safe Windows console encoding
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from flask import Flask, render_template, request, jsonify, send_from_directory
import database

# Initialize Flask application
app = Flask(__name__, static_folder="static", template_folder="templates")


@app.route("/")
def index():
    """
    Renders the main single-page application.
    """
    return render_template("index.html")


@app.route("/api/check-db", methods=["POST"])
def check_db():
    """
    API Endpoint: Checks if the submitted password has already been registered.
    
    Payload:
        { "password": "UserPassword123!" }
        
    Response:
        { "is_used": true/false }
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"is_used": False}), 200

    is_used = database.is_password_used_before(password)
    return jsonify({
        "is_used": is_used,
        "message": "This password was used before, choose a new one." if is_used else "Password not found in vault."
    }), 200


@app.route("/api/save-password", methods=["POST"])
def save_password_endpoint():
    """
    API Endpoint: Saves a new password with a unique salt into SQLite.
    
    Security Guarantee:
        - NEVER saves in plain text.
        - Generates 128-bit cryptographic salt.
        - Derives PBKDF2-HMAC-SHA256 hash (100,000 iterations).
        - Rejects candidate if already stored in database.
        
    Payload:
        { "password": "...", "label": "internship_demo" }
        
    Response:
        Success: { "success": true, "message": "...", "salt": "...", "hash": "..." }
        Failure: { "success": false, "message": "This password was used before, choose a new one." }
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    label = data.get("label", "Internship Demo User")

    if not password:
        return jsonify({"success": False, "message": "Password cannot be empty."}), 400

    result = database.save_password(password, label)
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@app.route("/api/history", methods=["GET"])
def history_endpoint():
    """
    API Endpoint: Returns stored cryptographic records for the Database Vault Inspector.
    
    Notice:
        Plain text passwords are NEVER returned or stored.
        Only the 128-bit salt preview and 256-bit hash digest are returned.
    """
    records = database.get_all_stored_passwords()
    return jsonify(records), 200


@app.route("/api/clear-db", methods=["POST"])
def clear_db_endpoint():
    """
    API Endpoint: Resets the SQLite database records for presentation / demo testing.
    """
    result = database.clear_database()
    return jsonify(result), 200


@app.route("/api/generate", methods=["GET"])
def generate_endpoint():
    """
    API Endpoint: Server-side cryptographically secure password generator.
    Uses Python's `secrets` module (CSPRNG backed by OS kernel entropy).
    """
    length = int(request.args.get("length", 16))
    length = max(8, min(64, length)) # Bound length safely

    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    all_chars = lower + upper + digits + symbols

    # Guarantee at least 2 characters from each class
    password_chars = [
        secrets.choice(upper), secrets.choice(upper),
        secrets.choice(lower), secrets.choice(lower),
        secrets.choice(digits), secrets.choice(digits),
        secrets.choice(symbols), secrets.choice(symbols)
    ]

    # Fill remainder using CSPRNG
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(all_chars))

    # Cryptographic shuffle
    system_random = secrets.SystemRandom()
    system_random.shuffle(password_chars)

    generated = "".join(password_chars)
    return jsonify({"password": generated, "length": len(generated)}), 200


if __name__ == "__main__":
    print("=" * 65)
    print(" [SAFE] Password Strength Analyzer & Cryptography Vault Server")
    print("=" * 65)
    print(" Server running locally at: http://127.0.0.1:5000")
    print(" SQLite Database File     : passwords.db")
    print(" Press Ctrl+C in terminal to stop server.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=True)
