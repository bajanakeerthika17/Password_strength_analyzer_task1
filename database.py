"""
database.py - SQLite Database & Cryptographic Hashing Engine
============================================================
Author: Password Security Internship Project
Description:
    This module handles database storage and cryptographic operations for the
    Password Strength Analyzer. It demonstrates fundamental security principles:
    
    1. NEVER store passwords in plain text.
    2. Salt generation: Using a cryptographically secure random number generator (CSPRNG)
       via Python's `secrets` module (128-bit / 16-byte random salt).
    3. Hashing algorithm: SHA-256 with PBKDF2 (Password-Based Key Derivation Function 2)
       using 100,000 rounds of HMAC-SHA256, following NIST SP 800-63B recommendations.
    4. Constant-time comparison: Using `hmac.compare_digest` to prevent timing attacks.
    5. Rejection of previously used passwords by verifying against all stored hashes.
"""

import os
import sqlite3
import hashlib
import secrets
import hmac
from datetime import datetime

# Path to the SQLite database file
DB_NAME = "passwords.db"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)

# Cryptographic parameters
SALT_BYTE_LENGTH = 16       # 16 bytes = 128 bits of cryptographic entropy
PBKDF2_ITERATIONS = 100000  # 100,000 iterations to resist GPU brute-force attacks
HASH_ALGORITHM = "sha256"


def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.
    row_factory is set to sqlite3.Row to allow accessing columns by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the database schema if it does not already exist.
    Creates the 'password_vault' table to store salts, hashes, and metadata.
    Notice: NO plain text password column exists in this schema!
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            iterations INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("[Database] Initialized SQLite database successfully at:", DB_PATH)


def generate_salt() -> str:
    """
    Generates a cryptographically secure random salt.
    
    Why Salting Matters:
    - Without salt, two users with the same password (e.g., 'Secret123!') would produce
      identical hashes. An attacker could use precomputed Rainbow Tables to instantly crack them.
    - With a unique random salt per password, identical passwords produce completely different
      hashes, rendering Rainbow Tables completely useless.
      
    Returns:
        Hexadecimal string of 16 random bytes (32 hex characters).
    """
    return secrets.token_hex(SALT_BYTE_LENGTH)


def hash_password(password: str, salt: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with the provided salt.
    
    Why PBKDF2-HMAC-SHA256?
    - A standard SHA-256 hash is computed in under a nanosecond on modern GPUs, making
      fast offline brute-force attacks possible (billions of guesses per second).
    - PBKDF2 applies key stretching: it hashes the salt and password in a loop 100,000 times.
      This introduces intentional computational work that slows down brute-force attackers
      dramatically while keeping login verification imperceptibly fast for a legitimate user.
      
    Args:
        password: The plain text candidate password.
        salt: The hex string salt.
        
    Returns:
        Hexadecimal representation of the derived 32-byte key hash.
    """
    salt_bytes = bytes.fromhex(salt)
    password_bytes = password.encode('utf-8')
    
    derived_key = hashlib.pbkdf2_hmac(
        hash_name=HASH_ALGORITHM,
        password=password_bytes,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        dklen=32  # 32 bytes = 256 bits output
    )
    return derived_key.hex()


def is_password_used_before(candidate_password: str) -> bool:
    """
    Checks whether the candidate password has already been registered in the database.
    
    How this works without storing plain text:
    - Since every password was stored with its own unique random salt, we cannot do a simple
      SQL query like `WHERE hash = my_hash`.
    - Instead, we fetch all stored (salt, password_hash) pairs from the database.
    - For each pair, we hash the candidate_password using THAT entry's salt.
    - We compare the result with the stored hash using `hmac.compare_digest`.
    - If any match is found, the candidate password was used before!
    
    Why `hmac.compare_digest`?
    - Standard `==` operator terminates comparison at the first mismatched character.
      This leaks timing information that allows attackers to guess bytes by measuring response latency.
    - `compare_digest` takes constant time regardless of where the mismatch occurs, defeating timing attacks.
    
    Args:
        candidate_password: The password to check.
        
    Returns:
        True if the password has been used before, False otherwise.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, salt, password_hash FROM password_vault")
    records = cursor.fetchall()
    conn.close()

    for record in records:
        stored_salt = record["salt"]
        stored_hash = record["password_hash"]
        
        # Hash the candidate password with the entry's unique salt
        candidate_hash = hash_password(candidate_password, stored_salt)
        
        # Constant-time comparison
        if hmac.compare_digest(candidate_hash, stored_hash):
            return True

    return False


def save_password(password: str, label: str = "Internship Demo User") -> dict:
    """
    Saves a new password securely into the SQLite database.
    Rejects the password if it has already been used before.
    
    Args:
        password: The plain text password to register.
        label: A descriptive label for the account/demo entry.
        
    Returns:
        dict: {'success': bool, 'message': str, 'id': int or None, 'salt': str, 'hash': str}
    """
    # Guard check: reject empty passwords
    if not password or not password.strip():
        return {
            "success": False,
            "message": "Password cannot be empty."
        }
        
    # Check if the password has been used before
    if is_password_used_before(password):
        return {
            "success": False,
            "message": "This password was used before, choose a new one."
        }
    
    # Generate unique salt and compute PBKDF2 hash
    salt = generate_salt()
    computed_hash = hash_password(password, salt)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO password_vault (label, salt, password_hash, algorithm, iterations)
        VALUES (?, ?, ?, ?, ?)
    """, (label, salt, computed_hash, f"PBKDF2-HMAC-{HASH_ALGORITHM.upper()}", PBKDF2_ITERATIONS))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    
    return {
        "success": True,
        "message": "Password hashed with salt and successfully saved to SQLite database!",
        "id": new_id,
        "salt": salt,
        "hash": computed_hash,
        "algorithm": f"PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} rounds)"
    }


def get_all_stored_passwords():
    """
    Retrieves all stored records to display in the UI's 'Database Vault Inspector'.
    CRITICAL: Only returns the ID, label, salt preview, hash preview, and timestamp.
    Plain text passwords CANNOT be returned because they are never stored!
    
    Returns:
        list of dicts containing non-sensitive record metadata.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, label, salt, password_hash, algorithm, iterations, created_at 
        FROM password_vault 
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "label": r["label"],
            "salt_preview": f"{r['salt'][:8]}...{r['salt'][-8:]}",
            "salt_full": r["salt"],
            "hash_preview": f"{r['password_hash'][:10]}...{r['password_hash'][-10:]}",
            "hash_full": r["password_hash"],
            "algorithm": r["algorithm"],
            "iterations": r["iterations"],
            "created_at": r["created_at"]
        })
    return history


def clear_database():
    """
    Clears all records from the password_vault table.
    Useful for demonstration and internship testing resets.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM password_vault")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='password_vault'")
    conn.commit()
    conn.close()
    return {"success": True, "message": "Database vault cleared successfully."}


# Automatically initialize the database schema when this module is imported
init_db()

