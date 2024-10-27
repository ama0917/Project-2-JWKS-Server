from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
from typing import Tuple

# Server configuration
HOST_NAME = "localhost"
SERVER_PORT = 8080
DB_NAME = "totally_not_my_privateKeys.db"

def init_database():
    """Initialize the SQLite database and create the keys table"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def generate_and_store_keys():
    """Generate and store both valid and expired keys in the database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Generate RSA keys
    valid_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Convert RSA keys to PEM format
    valid_pem = valid_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiration times using timezone-aware datetime
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    future = int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp())
    past = int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).timestamp())
    
    # Store keys in database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (valid_pem, future))
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, past))
    
    conn.commit()
    conn.close()

def get_key_from_db(expired: bool = False) -> Tuple[int, bytes]:
    """Retrieve key from database based on expiration status"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    # Retrieve expired key if status is expired. If not, retrieve valid key
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1", (now,))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ? LIMIT 1", (now,))
    
    result = cursor.fetchone()
    conn.close()
    
    # Raise error if suitable key is not found
    if result is None:
        raise ValueError("No suitable key found in database")
    
    # Return a tuple containing a key ID and key in PEM format
    return result

def get_valid_keys():
    """Retrieve all valid (non-expired) keys from the database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
    results = cursor.fetchall()
    conn.close()
    
    # Return a list of tuples containg key IDs and keys
    return results

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    """Implement HTTP to handle JWKS and JWT authentication endpoints"""

    # Reject PUT requests
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    # Reject PATCH requests
    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    # Reject DELETE requests
    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    # Reject HEAD requests
    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    # Handle POST requests
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        if parsed_path.path == "/auth":
            try:
                # Get appropriate key based on expired parameter
                kid, key_pem = get_key_from_db('expired' in params)
                
                # Load the private key from PEM format
                private_key = serialization.load_pem_private_key(
                    key_pem,
                    password=None
                )
                
                headers = {
                    "kid": str(kid)
                }
                
                # Create token payload with expiration
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
                }
                
                # Set expiration to past time if expired
                if 'expired' in params:
                    token_payload["exp"] = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
                
                encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
                return

        self.send_response(405)
        self.end_headers()

    # Handle GET requests
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            try:
                keys = {"keys": []}
                valid_keys = get_valid_keys()
                
                # Add and process valid keys to JWKS
                for kid, key_pem in valid_keys:
                    private_key = serialization.load_pem_private_key(
                        key_pem,
                        password=None
                    )
                    numbers = private_key.private_numbers()
                    
                    # Create JWKS entry
                    keys["keys"].append({
                        "alg": "RS256", # Algorithm
                        "kty": "RSA", # Key
                        "use": "sig", # Key use
                        "kid": str(kid), # Key ID
                        "n": int_to_base64(numbers.public_numbers.n), # Modulus
                        "e": int_to_base64(numbers.public_numbers.e), # Exponent
                    })
                
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(keys), "utf-8"))
                return
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
                return

        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    # Initialize database and store initial keys
    init_database()
    generate_and_store_keys()
    
    # Start the server
    webServer = HTTPServer((HOST_NAME, SERVER_PORT), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    
    webServer.server_close()