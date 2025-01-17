from jwt.exceptions import ExpiredSignatureError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from unittest.mock import patch, MagicMock
from http.client import HTTPConnection
from threading import Thread
import unittest
import requests
import jwt
import json
import base64
import sqlite3
import os
import datetime
import base64
from main1 import (
    init_database, generate_and_store_keys, get_key_from_db,
    get_valid_keys, int_to_base64, MyServer, HTTPServer,
    HOST_NAME, SERVER_PORT, DB_NAME
)


class TestJWTServer(unittest.TestCase):
    BASE_URL = "http://localhost:8080"

    def setUp(self):
        # This setup assumes the server is already running
        pass

    def test_initialization(self):
        # Test server initialization, database setup, and key generation."""

        # Check if the database file is created
        self.assertTrue(os.path.exists("totally_not_my_privateKeys.db"), "Database file was not created.")

        # Test that at least one key is stored in the database
        with sqlite3.connect("totally_not_my_privateKeys.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM keys")
            key_count = cursor.fetchone()[0]
            self.assertGreater(key_count, 0, "No keys were found in the database.")

        # Test that the JWKS endpoint is accessible and returns expected data
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200, "JWKS endpoint is not accessible.")
        
        # Parse the JSON response and check its contents
        data = response.json()
        self.assertIn("keys", data, "JWKS response does not contain 'keys'.")
        self.assertGreater(len(data["keys"]), 0, "No keys found in JWKS response.")

    def test_int_to_base64(self):
        # Test integer to Base64 URL-safe conversion.
        
        # Define test cases with known integer inputs and their expected Base64 outputs
        test_cases = [
            (0, "AA"),                          # Edge case: smallest integer
            (1, "AQ"),                          # Small integer
            (255, "_w"),                        # Max single-byte integer
            (65535, "__8"),                     # Max two-byte integer
            (123456789, "Bz0vDQ"),              # Random integer
            (2**256 - 1, "_" * 43 + "w"),       # Large integer close to 256 bits
        ]

        for integer, expected_base64 in test_cases:
            with self.subTest(integer=integer):
                # Call the int_to_base64 function from main
                result = int_to_base64(integer)
                self.assertEqual(result, expected_base64, f"Failed for integer {integer}")

    def test_unsupported_methods(self):
        # Test unsupported HTTP methods to ensure they return a 405 Method Not Allowed
        unsupported_methods = [requests.put, requests.patch, requests.delete, requests.head]
        for method in unsupported_methods:
            with self.subTest(method=method):
                response = method(f"{self.BASE_URL}/some_endpoint")
                self.assertEqual(response.status_code, 405)
        

    def test_jwks_endpoint(self):
        # Test the JWKS endpoint to ensure it returns the correct JSON Web Key Set
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        
        # Check that the response status code is 200 OK
        self.assertEqual(response.status_code, 200)

        # Parse the JSON response
        data = response.json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0) # Check for valid key

        key = data["keys"][0]
        self.assertEqual(key["alg"], "RS256") # Check algorithm
        self.assertEqual(key["kty"], "RSA") # Check key type
        self.assertEqual(key["use"], "sig") # Check key usage
        self.assertEqual("kid", key) # Check key ID
        self.assertIn("n", key) # Ensure existing modulus
        self.assertIn("e", key) # Ensure existing exponent

    def construct_public_key(self, jwk):
    # Construct a public key from a JWK dictionary

        # Add padding for base64 decoding
        def add_padding(b64str):
            return b64str + '=' * (-len(b64str) % 4)
    
        e = int.from_bytes(base64.urlsafe_b64decode(add_padding(jwk['e'])), 'big')
        n = int.from_bytes(base64.urlsafe_b64decode(add_padding(jwk['n'])), 'big')
       
        # Create a public key from the modulus and exponent
        public_numbers = rsa.RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key()

        return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def test_auth_endpoint(self):
        response = requests.post(f"{self.BASE_URL}/auth")
        self.assertEqual(response.status_code, 200)
        token = response.text
        
        # Get the JWKS
        jwks_response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        jwks = jwks_response.json()
        
        # Decode token header to get kid
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        
        # Find matching key in JWKS
        matching_key = next((k for k in jwks['keys'] if k['kid'] == kid), None)
        self.assertIsNotNone(matching_key, "No matching key found in JWKS")
        
        public_key = self.construct_public_key(matching_key)
        decoded = jwt.decode(token, public_key, algorithms=["RS256"])
        
        self.assertIn("user", decoded)
        self.assertEqual(decoded["user"], "username")

    def test_token_expiration(self):
        # Test token expiration based on exp claim
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = response.text
        
        # Decode token with a valid public key
        jwks_response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        jwks = jwks_response.json()

        header = jwt.get_unverified_header(token)
        matching_key = next((k for k in jwks['keys'] if k['kid'] == header['kid']), None)
        self.assertIsNotNone(matching_key)
        
        public_key = self.construct_public_key(matching_key)
    
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(token, public_key, algorithms=["RS256"])

    def test_expired_token(self):
        # Test token generation and identification
        response = requests.post(f"{self.BASE_URL}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = response.text
    
        # Manually construct the public key for testing
        public_key = self.construct_public_key({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": "goodKID",
            "n": "some_n_value",
            "e": "AQAB"
        })
    
        # Check for expired JWT
        with self.assertRaises(ExpiredSignatureError):
            jwt.decode(token, public_key, algorithms=["RS256"])
        
if __name__ == "__main__":
    unittest.main()