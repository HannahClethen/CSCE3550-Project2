# Google Gemini was used to assist in this file implementation.
import jwt
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa 
import base64

# Import database utilities and the shared password
from db_manager import get_key_from_db, get_valid_public_keys
from db_manager import KEY_PASSWORD 

app = Flask(__name__)

# Convert encrupted PEM private key to JWK public key
def private_pem_to_jwk_public(kid, key_pem):
    """
    Converts a PEM-formatted private key to a JWK public key.
    FIX: Uses rsa.RSAPublicKey check to resolve "Unsupported key type" error.
    """
    private_key = serialization.load_pem_private_key(
        key_pem,
        password=KEY_PASSWORD,
        backend=None
    )
    
    public_key = private_key.public_key()
    
    # Check for the correct type -  rsa.RSAPublicKey
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        
        # Helper function for integer conversion to base64url
        def to_b64(n):
            return base64.urlsafe_b64encode( # <--- USE base64.urlsafe_b64encode
    n.to_bytes((n.bit_length() + 7) // 8, 'big')
).decode('utf-8').rstrip('=')

        # Modulus and exponent in base64url format
        n = to_b64(numbers.n)
        e = to_b64(numbers.e)
        
        return {
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid), # Convert integer kid (from the database) to string
            "n": n,
            "e": e
        }
    else:
        # Handle unsupported key types
        raise ValueError("Unsupported key type.")

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Reads all valid private keys from the DB and returns their public JWKS format."""
    try:
        # Retrieve unexpired keys from the database
        keys_from_db = get_valid_public_keys()
        
        jwks_list = []

        # Convert each private key to JWK public key format
        for kid, key_pem in keys_from_db:
            try:
                jwk = private_pem_to_jwk_public(kid, key_pem)
                jwks_list.append(jwk)
            except Exception as e:
                # Note any conversion errors
                print(f"Error converting key {kid}: {e}")
                
        return jsonify({"keys": jwks_list})
        
    except Exception as e:
        print(f"Error fetching keys from DB: {e}")
        return jsonify({"error": "Server error fetching keys"}), 500

@app.route("/auth", methods=["POST"])
def auth():
    """Mocks authentication and issues a JWT signed with a key from the DB."""
    
    # user authentication for key selection - used for grading
    
    # Check for key expiry parameter
    expired_param = request.args.get('expired')
    use_expired_key = expired_param is not None and expired_param.lower() in ('true', '1')

    # Get correct key from db
    key_data = get_key_from_db(expired=use_expired_key)
    
    if not key_data:
        return jsonify({"error": "No signing key available"}), 500
        
    kid, key_pem = key_data
    

    # Load the private key for signing
    try:
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=KEY_PASSWORD,
            backend=None
        )
    except Exception as e:
        print(f"Error loading private key {kid}: {e}")
        return jsonify({"error": "Server error loading key"}), 500

    # Create JWT claims
    now = datetime.utcnow()
    exp_time = now + timedelta(minutes=10) 
    
    payload = {
        "iss": "jwks-server",
        "sub": "userABC", 
        "aud": "client",
        "iat": now,
        "exp": exp_time,
    }
    
    # Ensure kid is a string for the JWT header, must be linked in the JWKS endpoint
    headers = {"kid": str(kid)} 
    
    # Sign the JWT with RS256 algorithm
    encoded_jwt = jwt.encode(
        payload, 
        private_key, 
        algorithm="RS256", 
        headers=headers
    )
    
    return jsonify({"jwt": encoded_jwt}), 200

if __name__ == "__main__":
    # initialize the Flask app on port 8080
    app.run(port=8080)