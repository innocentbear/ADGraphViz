# VULNERABILITY: File with multiple security issues for learning GitHub Advanced Security

import os
import re
from typing import Any

# VULNERABILITY: Hardcoded credentials in config
API_KEYS = {
    "github": "ghp_1234567890abcdefghijklmnopqrstuv",
    "slack": "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUv",
    "stripe": "sk_test_51234567890abcdefghijklmnopqrstuv"
}

# VULNERABILITY: SQL Injection - No input validation
def build_user_query(username: str) -> str:
    """Build a user query - VULNERABLE to SQL injection"""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

# VULNERABILITY: Path Traversal
def read_file(filename: str) -> str:
    """Read a file - VULNERABLE to path traversal attacks"""
    path = f"/uploads/{filename}"
    with open(path, "r") as f:
        return f.read()

# VULNERABILITY: Hardcoded passwords
CREDENTIALS = {
    "admin_user": "admin123",
    "db_password": "Password@123!",
    "api_token": "secret_token_xyz_123_abc"
}

# VULNERABILITY: Weak regex for email validation
def validate_email(email: str) -> bool:
    """Email validation - uses weak regex"""
    pattern = r"^.+@.+\..+$"
    return bool(re.match(pattern, email))

# VULNERABILITY: Use of eval() with user input
def execute_expression(expr: str) -> Any:
    """Execute arbitrary Python code - EXTREMELY DANGEROUS"""
    result = eval(expr)
    return result

# VULNERABILITY: Missing input validation
def process_payment(amount: str, card_number: str) -> dict:
    """Process payment without proper validation"""
    # No validation on amount or card number format
    processed_amount = float(amount)
    return {
        "amount": processed_amount,
        "card": card_number[-4:],
        "status": "processed"
    }

# VULNERABILITY: Insecure randomness
import random
def generate_token() -> str:
    """Generate a token using weak randomness"""
    token = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(32))
    return token

# VULNERABILITY: Missing authentication check
def admin_endpoint(user_id: str) -> dict:
    """Admin endpoint - no role/permission check"""
    return {
        "admin_data": "sensitive information",
        "user_id": user_id
    }

# VULNERABILITY: XXE (XML External Entity) - if XML is processed
import xml.etree.ElementTree as ET
def parse_xml(xml_data: str) -> dict:
    """Parse XML without disabling entity expansion"""
    root = ET.fromstring(xml_data)
    return {"data": root.tag}

# VULNERABILITY: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key-12345"

# VULNERABILITY: Use of insecure hash algorithm
import hashlib
def hash_password(password: str) -> str:
    """Hash password using MD5 - INSECURE"""
    return hashlib.md5(password.encode()).hexdigest()
