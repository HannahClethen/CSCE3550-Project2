# Google Gemini was used to assist in this file implementation.
#  Import appropriate libraries
import sqlite3
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Configuration setup for databse files to store keys
DB_FILE = 'totally_not_my_privateKeys.db'
# need a password to encryp/decrypt the private keys (BLOBs)
KEY_PASSWORD = b'secure_password' 


# Functions to manage the database and keys (setup using connect function, commit, and close)
def init_db(db_file=DB_FILE):
    """Creates the database file and table if they don't exist."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Scheme definition with kid, key, and exp columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# Function for key generation and storage
def generate_and_store_keys(db_file=DB_FILE):
    """
    Generates an expired and a valid private key, then stores them in the DB.
    """
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    # Remove old keys, need this for the secuirty check
    cursor.execute("DELETE FROM keys WHERE 1=?", (1,))
    
    # Generate an expired key 
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # if a key not found generate a timestamp in the past
    old_date = datetime(2000, 1, 1, 0, 0, 0)
    expired_exp = int(old_date.timestamp())
    
    # Used to store the key in PEM format with encryption
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
    )
    
    # 2. Generate valid key 
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Give valid key an expiration (~1 hour)
    valid_exp = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
    )
    
    # Store both keys in the database
    keys_to_store = [
        (expired_pem, expired_exp),
        (valid_pem, valid_exp)
    ]
    
    # store keys with parametrized INSERT to prevent SQL injection
    cursor.executemany("INSERT INTO keys (key, exp) VALUES (?, ?)", keys_to_store)
    
    conn.commit()
    conn.close()
    
    # Inform user about key generation
    print(f"Generated and stored two keys in {DB_FILE}: one expired, one valid.")

# Use SELECT to retrieve keys
def get_key_from_db(expired=False, db_file=DB_FILE):
    """Retrieves a key (expired or valid) from the database using parameterized SELECT."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    # Use time.time() for the current UNIX timestamp
    current_time = int(time.time())
    
    # Use conditional to check whether to get expired or valid key
    if expired:
        # Get an expired key 
        query = "SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp ASC LIMIT 1"
    else:
        # Get a valid key 
        query = "SELECT kid, key FROM keys WHERE exp >= ? ORDER BY exp DESC LIMIT 1"
    
    # HAVE TO use parameterized query to prevent SQL injection
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

# Initialize and generate the keys when the server start
init_db()
generate_and_store_keys()