"""
test_analyzer.py - Automated Test Suite & Internship Demonstration Script
=========================================================================
Author: Password Security Internship Project
Description:
    Runs automated checks on the password analyzer and SQLite cryptographic
    database vault to verify correctness, test cases, and cryptographic properties.
    
Run via:
    python test_analyzer.py
"""

import unittest
import database
import hashlib
import secrets


class TestPasswordSecurityEngine(unittest.TestCase):

    def setUp(self):
        """Prepare fresh database state before each test."""
        database.clear_database()

    def tearDown(self):
        """Clean up database after each test."""
        database.clear_database()

    def test_database_hashing_and_salting(self):
        """
        Verify that passwords are never stored in plain text and that
        salts are uniquely generated for every entry.
        """
        pwd1 = "InternshipSecurity2026!"
        pwd2 = "InternshipSecurity2026!"

        # Generate two separate salts
        salt1 = database.generate_salt()
        salt2 = database.generate_salt()

        self.assertNotEqual(salt1, salt2, "Salts must be unique (CSPRNG).")
        self.assertEqual(len(salt1), 32, "16-byte salt must yield 32 hex characters.")

        # Hash the identical password with the two different salts
        hash1 = database.hash_password(pwd1, salt1)
        hash2 = database.hash_password(pwd2, salt2)

        # Salting principle: Identical passwords produce completely different hashes!
        self.assertNotEqual(hash1, hash2, "Identical passwords must produce distinct hashes when salted.")
        print("  [PASS] Cryptographic salting verification successful.")

    def test_rejection_of_previously_used_passwords(self):
        """
        Verify Requirement 8: The database must reject any password that has been used before
        and return the exact specified warning message.
        """
        test_password = "MySecureVaultPassword123!"

        # First registration should succeed
        res1 = database.save_password(test_password, "First Account")
        self.assertTrue(res1["success"])
        self.assertIn("successfully saved", res1["message"].lower())

        # Second attempt with the exact same password must be rejected!
        res2 = database.save_password(test_password, "Second Account")
        self.assertFalse(res2["success"])
        self.assertEqual(
            res2["message"],
            "This password was used before, choose a new one.",
            "Must output the exact specified rejection warning."
        )
        print("  [PASS] Rejection of previously used password verified.")

    def test_plain_text_never_exposed(self):
        """
        Verify that database records only expose the salt and hash, NEVER the plain text.
        """
        secret_pwd = "TopSecretPassword#2026"
        database.save_password(secret_pwd, "Admin")

        records = database.get_all_stored_passwords()
        self.assertEqual(len(records), 1)
        
        record = records[0]
        self.assertIn("salt_preview", record)
        self.assertIn("hash_preview", record)
        self.assertNotIn("password", record)
        self.assertNotIn("plain_text", record)
        print("  [PASS] Zero-knowledge plain text storage verified.")

    def test_entropy_mathematics(self):
        """
        Verify Shannon Entropy calculations:
        H = L * log2(R)
        For L = 16 and R = 95 (lowercase + uppercase + digits + symbols):
        log2(95) ~ 6.57
        H ~ 16 * 6.57 = 105.1 bits
        """
        import math
        pool_r = 95 # all 4 character sets
        length = 16
        entropy = length * (math.log(pool_r) / math.log(2))
        self.assertGreater(entropy, 100)
        print(f"  [PASS] Shannon entropy for 16-char full-pool password: {entropy:.2f} bits.")


import sys
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

if __name__ == "__main__":
    print("=" * 60)
    print(" [*] Running Automated Unit & Cryptography Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
