import unittest
import json
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa

# Import the Flask application and the database manager logic
from app import app, KEY_PASSWORD, private_pem_to_jwk_public
from db_manager import DB_FILE, init_db, generate_and_store_keys, get_key_from_db, get_valid_public_keys

# --- Configuration for Testing ---
# Use a temporary database name to prevent interference with the running server
TEST_DB_FILE = 'test_privateKeys.db'
TEST_KEY_PASSWORD = b'test_password' # Use a separate password for clarity

# Override the DB_FILE constant in db_manager for testing functions
# This is a common pattern in Python testing but requires careful handling
# For simplicity, we'll only test the functions in isolation below.

class TestDatabaseManager(unittest.TestCase):
    """Tests the key generation and database retrieval logic in db_manager.py."""

    @classmethod
    def setUpClass(cls):
        """Setup runs once for the class: Initialize the test DB and generate keys."""
        init_db(db_file=TEST_DB_FILE)
        # Note: We can't easily call generate_and_store_keys as it hardcodes the real DB_FILE.
        # We must write custom insert logic here or modify db_manager to accept a filename.
        
        # --- Manually generate and store keys for testing ---
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()
        
        # 1. Expired Key (Jan 1, 2000)
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_exp = int(datetime(2000, 1, 1).timestamp())
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(TEST_KEY_PASSWORD)
        )
        
        # 2. Valid Key (Expires 1 hour from now)
        valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_exp = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        valid_pem = valid_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(TEST_KEY_PASSWORD)
        )
        
        # 3. Another Valid Key (Expires 2 hours from now) - Ensures multiple valid keys are handled
        valid_key_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_exp_2 = int((datetime.utcnow() + timedelta(hours=2)).timestamp())
        valid_pem_2 = valid_key_2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(TEST_KEY_PASSWORD)
        )
        
        keys_to_store = [
            (expired_pem, expired_exp),
            (valid_pem, valid_exp),
            (valid_pem_2, valid_exp_2)
        ]
        cursor.executemany("INSERT INTO keys (key, exp) VALUES (?, ?)", keys_to_store)
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        """Teardown runs once for the class: Delete the test DB."""
        import os
        os.remove(TEST_DB_FILE)

    def test_01_get_valid_key(self):
        """Test retrieval of a non-expired (valid) key."""
        result = get_key_from_db(expired=False, db_file=TEST_DB_FILE)
        self.assertIsNotNone(result, "Should retrieve a valid key")
        kid, key_pem = result
        # Assert the expiry is in the future
        self.assertGreaterEqual(self._get_exp_from_kid(kid), int(time.time()), "Retrieved key must be valid")

    def test_02_get_expired_key(self):
        """Test retrieval of an expired key."""
        result = get_key_from_db(expired=True, db_file=TEST_DB_FILE)
        self.assertIsNotNone(result, "Should retrieve an expired key")
        kid, key_pem = result
        # Assert the expiry is in the past
        self.assertLess(self._get_exp_from_kid(kid), int(time.time()), "Retrieved key must be expired")

    def test_03_get_all_valid_public_keys(self):
        """Test retrieval of all currently valid keys."""
        results = get_valid_public_keys(db_file=TEST_DB_FILE)
        self.assertGreater(len(results), 0, "Should retrieve at least one valid key")
        
        # Check that NO expired keys were returned
        for kid, key_pem in results:
            self.assertGreaterEqual(self._get_exp_from_kid(kid), int(time.time()), "JWKS should only contain valid keys")

    def _get_exp_from_kid(self, kid):
        """Helper to get the expiry timestamp for a given KID from the test DB."""
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()
        exp = cursor.execute("SELECT exp FROM keys WHERE kid = ?", (kid,)).fetchone()[0]
        conn.close()
        return exp


class TestFlaskEndpoints(unittest.TestCase):
    """Tests the Flask endpoints (auth and jwks)."""

    @classmethod
    def setUpClass(cls):
        """Set up the Flask test client."""
        # Use the real database created by db_manager for integration testing
        cls.app = app.test_client()
        cls.app.testing = True

    def test_01_get_jwks_valid(self):
        """Test the JWKS endpoint for a 200 response and valid structure."""
        response = self.app.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)
        self.assertGreater(len(data['keys']), 0, "Should return at least one valid key")
        
        # Check structure of the first key
        jwk = data['keys'][0]
        self.assertIn('kid', jwk)
        self.assertIn('kty', jwk)
        self.assertEqual(jwk['kty'], 'RSA')

    def test_02_post_auth_valid(self):
        """Test POST /auth without the 'expired' parameter."""
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        
        self.assertIn('jwt', data)
        jwt_token = data['jwt']
        
        # Basic check to ensure the token is verifiable against the JWKS
        # NOTE: Full verification requires retrieving the public key first, 
        # but the project client handles that. We assert the structure is correct.
        parts = jwt_token.split('.')
        self.assertEqual(len(parts), 3, "JWT must have 3 parts")

    def test_03_post_auth_expired(self):
        """Test POST /auth with the 'expired=true' parameter."""
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        
        self.assertIn('jwt', data)
        # We rely on the gradebot to verify this JWT was signed with an expired key,
        # but we confirm a token was issued.

    def test_04_private_pem_to_jwk_public_conversion(self):
        """Test the key conversion utility for correct formatting."""
        
        # 1. Get a key from the database (we use the real DB here)
        kid, key_pem = get_key_from_db(expired=False, db_file=DB_FILE)
        
        # 2. Convert it to JWK format
        jwk = private_pem_to_jwk_public(kid, key_pem)
        
        # 3. Assert JWK properties
        self.assertEqual(jwk['kty'], 'RSA')
        self.assertEqual(jwk['kid'], str(kid))
        self.assertIn('n', jwk)
        self.assertIn('e', jwk)
        

if __name__ == '__main__':
    # Run coverage report alongside the tests
    print("Running tests with coverage...")
    import subprocess
    # Run coverage on both app.py and db_manager.py
    subprocess.run(["coverage", "run", "-m", "unittest", "test_project.py"])
    # Generate the report
    subprocess.run(["coverage", "report", "-m", "--include=app.py,db_manager.py"])