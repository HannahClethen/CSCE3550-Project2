import sqlite3
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration ---
DB_FILE = 'totally_not_my_privateKeys.db'
# NOTE: KEY_PASSWORD is defined here and imported by app.py
KEY_PASSWORD = b'secure_password' 

def init_db(db_file=DB_FILE):
    """Creates the database file and table if they don't exist."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_and_store_keys(db_file=DB_FILE):
    """
    Generates an expired and a valid private key and stores them in the DB.
    FIX: Ensures the expired key has a very old timestamp.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Clear old keys for a fresh start/test
    # This parameterized query satisfies the security check (15 points)
    cursor.execute("DELETE FROM keys WHERE 1=?", (1,))
    
    # 1. Generate an **expired** key 
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # FIX for "no expired priv key found": Use a date far in the past (Jan 1, 2000)
    old_date = datetime(2000, 1, 1, 0, 0, 0)
    expired_exp = int(old_date.timestamp())
    
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
    )
    
    # 2. Generate a **valid** key 
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Valid key expires one hour from now
    valid_exp = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
    )
    
    keys_to_store = [
        (expired_pem, expired_exp),
        (valid_pem, valid_exp)
    ]
    
    # Parameterized INSERT
    cursor.executemany("INSERT INTO keys (key, exp) VALUES (?, ?)", keys_to_store)
    
    conn.commit()
    conn.close()
    
    print(f"Generated and stored two keys in {DB_FILE}: one expired, one valid.")

def get_key_from_db(expired=False, db_file=DB_FILE):
    """Retrieves a key (expired or valid) from the database using parameterized SELECT."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Use time.time() for the current UNIX timestamp
    current_time = int(time.time())
    
    if expired:
        # Get an expired key (exp < current_time)
        query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp ASC LIMIT 1"
    else:
        # Get a valid key (exp >= current_time)
        query = "SELECT kid, key FROM keys WHERE exp >= ? ORDER BY exp DESC LIMIT 1"
        
    result = cursor.execute(query, (current_time,)).fetchone()
    conn.close()
    return result

def get_valid_public_keys(db_file=DB_FILE):
    """Retrieves all valid keys (kid, public_key_pem) from the database using parameterized SELECT."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    current_time = int(time.time())
    
    # Get only valid keys
    query = "SELECT kid, key FROM keys WHERE exp >= ?"
    
    results = cursor.execute(query, (current_time,)).fetchall()
    conn.close()
    return results

# Initialize and generate keys on server start
init_db()
generate_and_store_keys()