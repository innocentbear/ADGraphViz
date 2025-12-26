"""
Bandit Security Vulnerabilities for Learning GitHub Advanced Security
Reference: https://bandit.readthedocs.io/en/latest/

This file intentionally contains security vulnerabilities for testing
GitHub's security scanning capabilities.
"""

import pickle
import hashlib
import ssl
import subprocess
import requests
import tempfile
import random
from typing import Any

# ============================================
# B102: exec_used
# ============================================
def vulnerable_exec_code(user_code: str) -> Any:
    """
    VULNERABILITY B102: Use of exec - Allows arbitrary code execution
    Never execute user-supplied code directly!
    """
    # DANGEROUS: Direct execution of user input
    exec(user_code)  # B102: exec_used
    return None

# ============================================
# B110: try_except_pass
# ============================================
def vulnerable_bare_except():
    """
    VULNERABILITY B110: Bare except clause catching all exceptions
    This silently swallows all exceptions, including system exits
    """
    try:
        result = 1 / 0
    except:  # B110: try_except_pass - catches ALL exceptions
        pass

# ============================================
# B112: try_except_pass with specific exception
# ============================================
def vulnerable_except_pass(user_input: str) -> bool:
    """
    VULNERABILITY B112: Exception handler that just passes
    Silently ignores errors without logging or proper handling
    """
    try:
        if len(user_input) < 4:
            raise ValueError("Input too short")
        process_data(user_input)
        return True
    except ValueError:  # B112: try_except_pass
        pass  # Silently ignores the error
    return False

def process_data(data: str):
    pass

# ============================================
# B303: use_of_insecure_MD2_MD4_MD5_SHA1
# ============================================
def vulnerable_md5_hash(password: str) -> str:
    """
    VULNERABILITY B303: Use of MD5 hash - Cryptographically broken
    MD5 is vulnerable to collision attacks and should never be used for passwords
    """
    # DANGEROUS: MD5 is insecure and should be replaced with bcrypt, scrypt, or argon2
    hashed = hashlib.md5(password.encode()).hexdigest()  # B303
    return hashed

# ============================================
# B304: use_of_insecure_hash_functions (SHA1)
# ============================================
def vulnerable_sha1_hash(data: str) -> str:
    """
    VULNERABILITY B304: Use of SHA1 hash - Cryptographically weak
    SHA1 has known collision vulnerabilities
    """
    # DANGEROUS: SHA1 should not be used for security
    hashed = hashlib.sha1(data.encode()).hexdigest()  # B304
    return hashed

# ============================================
# B312: telnetlib
# ============================================
def vulnerable_telnet_connection(host: str, port: int = 23):
    """
    VULNERABILITY B312: Use of telnetlib - Unencrypted protocol
    Telnet transmits data in plaintext including credentials
    """
    try:
        import telnetlib
        # DANGEROUS: Unencrypted communication
        tn = telnetlib.Telnet(host, port)  # B312: telnetlib
        tn.write(b"username\n")
        tn.write(b"password\n")
        tn.close()
    except Exception:
        pass

# ============================================
# B321: ftplib FTP (unencrypted)
# ============================================
def vulnerable_ftp_connection(host: str, username: str, password: str):
    """
    VULNERABILITY B321: Use of FTP - Unencrypted file transfer
    FTP sends credentials and data in plaintext
    """
    try:
        import ftplib
        # DANGEROUS: Unencrypted FTP protocol
        ftp = ftplib.FTP(host)  # B321: ftp_use
        ftp.login(username, password)  # Credentials in plaintext!
        ftp.quit()
    except Exception:
        pass

# ============================================
# B324: probable_use_of_insecure_hash_functions
# ============================================
def vulnerable_weak_jwt_secret(payload: str) -> str:
    """
    VULNERABILITY B324: Use of insecure hash in JWT
    Weak secrets and hardcoded values compromise JWT security
    """
    try:
        import jwt
        # DANGEROUS: Weak hardcoded secret
        token = jwt.encode(
            {"data": payload},
            "weak-secret-key-12345",  # B324: Hardcoded weak secret
            algorithm="HS256"
        )
        return token
    except:
        return ""

# ============================================
# B413: pickle deserialization
# ============================================
def vulnerable_pickle_load(data: bytes) -> Any:
    """
    VULNERABILITY B413: Unsafe deserialization with pickle
    Pickle can execute arbitrary code when deserializing untrusted data
    """
    # DANGEROUS: Never use pickle with untrusted data
    result = pickle.loads(data)  # B413: pickle_use
    return result

# ============================================
# B501: requests verify=False
# ============================================
def vulnerable_insecure_request(url: str) -> str:
    """
    VULNERABILITY B501: Disabled SSL certificate verification
    This allows man-in-the-middle attacks
    """
    # DANGEROUS: Disables SSL certificate verification
    response = requests.get(url, verify=False)  # B501: request_verify_false
    return response.text

# ============================================
# B502: ssl_with_bad_version (SSLv2/SSLv3)
# ============================================
def vulnerable_ssl_bad_version():
    """
    VULNERABILITY B502: Use of insecure SSL version
    SSLv2 and SSLv3 have critical security flaws
    """
    # DANGEROUS: SSLv2 is completely broken
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)  # B502: ssl_with_bad_version
        return context
    except Exception:
        return None

# ============================================
# B503: ssl_with_bad_defaults
# ============================================
def vulnerable_ssl_bad_defaults():
    """
    VULNERABILITY B503: SSL context with insecure defaults
    Disables critical security checks
    """
    # DANGEROUS: Disables hostname and certificate verification
    context = ssl.create_default_context()
    context.check_hostname = False  # B503: Disables hostname check
    context.verify_mode = ssl.CERT_NONE  # B503: Disables certificate verification
    return context

# ============================================
# B504: ssl_with_no_version
# ============================================
def vulnerable_ssl_no_version():
    """
    VULNERABILITY B504: SSL context without explicit version
    Could use deprecated protocols by default
    """
    # DANGEROUS: No explicit protocol version specified
    try:
        context = ssl.SSLContext()  # B504: ssl_with_no_version
        return context
    except Exception:
        return None

# ============================================
# B505: weak_cryptographic_key (RSA < 2048)
# ============================================
def vulnerable_weak_rsa_key():
    """
    VULNERABILITY B505: Use of weak RSA key size
    RSA keys less than 2048 bits are vulnerable to factorization
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # DANGEROUS: 512-bit RSA is trivially broken
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=512,  # B505: weak_key_size - Should be at least 2048
            backend=default_backend()
        )
        return key
    except Exception:
        return None

# ============================================
# Additional common vulnerabilities
# ============================================

def vulnerable_command_injection(user_command: str):
    """
    VULNERABILITY: Command injection via subprocess with shell=True
    """
    # DANGEROUS: User input in shell command
    subprocess.run(f"echo {user_command}", shell=True)  # B602

def vulnerable_temp_file():
    """
    VULNERABILITY: Insecure temporary file creation
    """
    # DANGEROUS: Predictable temp file name
    temp_file = f"/tmp/data_{random.randint(1, 100)}.txt"  # B108
    return temp_file

def vulnerable_random_for_security(num_bytes: int = 16):
    """
    VULNERABILITY: Use of random for security-sensitive operations
    random module is not cryptographically secure
    """
    # DANGEROUS: random is not suitable for security
    token = ''.join(str(random.randint(0, 9)) for _ in range(num_bytes))  # B311
    return token


# ============================================
# CRITICAL: B201 - Flask debug mode in production
# ============================================
def vulnerable_flask_debug():
    """
    CRITICAL VULNERABILITY: Running Flask with debug=True in production
    Exposes sensitive information and allows remote code execution
    """
    from flask import Flask
    app = Flask(__name__)
    
    # CRITICAL: Debug mode enabled - allows code execution
    app.run(debug=True, host='0.0.0.0', port=5000)  # B201: flask_debug_true


# ============================================
# CRITICAL: SQL Injection via string concatenation
# ============================================
def vulnerable_sql_injection(user_email: str, user_id: int):
    """
    CRITICAL VULNERABILITY: SQL Injection
    Direct string concatenation in SQL queries
    """
    import sqlite3
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # CRITICAL: SQL injection vulnerability
    # Attacker can use: email = "'; DROP TABLE users; --"
    query = f"SELECT * FROM users WHERE email = '{user_email}' AND id = {user_id}"
    cursor.execute(query)  # B608: sql_injection
    
    return cursor.fetchall()


# ============================================
# CRITICAL: Command Injection
# ============================================
def vulnerable_command_injection(filename: str):
    """
    CRITICAL VULNERABILITY: Command Injection
    User input directly passed to shell commands
    """
    import os
    
    # CRITICAL: Command injection via os.system
    # Attacker can use: filename = "test.txt; rm -rf /"
    result = os.system(f'cat {filename}')  # B605: start_process_with_no_shell
    
    # Also vulnerable: using shell=True with subprocess
    import subprocess
    subprocess.run(f'ls -la {filename}', shell=True)  # B602: shell_injection


# ============================================
# CRITICAL: Hard-coded passwords and secrets
# ============================================
def vulnerable_hardcoded_secrets():
    """
    CRITICAL VULNERABILITY: Hardcoded credentials in code
    Exposed in version control history and compiled code
    """
    # Database credentials
    db_host = 'prod-db.company.com'
    db_user = 'admin'
    db_password = 'SuperSecure@123!'  # B105: hardcoded_password
    db_port = 5432
    
    # API Keys
    api_key = 'sk_live_4eC39HqLyjWDarhtT657tHtF'  # Stripe key
    github_token = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'
    
    # AWS credentials
    aws_access_key = 'AKIAIOSFODNN7EXAMPLE'
    aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    
    # OAuth tokens
    oauth_token = 'ya29.a0AWY7CkliYhZcUBl...'
    refresh_token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjExIn0...'
    
    # JWT Secret
    jwt_secret = 'my_super_secret_jwt_key_never_share_this'
    
    return {
        'db_password': db_password,
        'api_key': api_key,
        'github_token': github_token,
        'aws_secret': aws_secret_key
    }


# ============================================
# CRITICAL: Unsafe YAML deserialization
# ============================================
def vulnerable_yaml_load(user_config: str):
    """
    CRITICAL VULNERABILITY: YAML deserialization with arbitrary code execution
    yaml.load() allows arbitrary Python code execution
    """
    import yaml
    
    # CRITICAL: yaml.load allows code execution
    # Attacker YAML: !!python/object/apply:os.system ["rm -rf /"]
    config = yaml.load(user_config, Loader=yaml.Loader)  # B506: yaml_load
    
    return config


# ============================================
# CRITICAL: Insecure cryptographic algorithms
# ============================================
def vulnerable_insecure_crypto():
    """
    CRITICAL VULNERABILITY: Using weak or insecure cryptographic algorithms
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # CRITICAL: DES is deprecated and insecure
    cipher = Cipher(
        algorithms.TripleDES(b'0123456789abcdef0123456'),  # Weak key size
        modes.ECB(),  # ECB mode - doesn't hide patterns
        backend=default_backend()
    )
    
    return cipher


# ============================================
# CRITICAL: Path traversal attack
# ============================================
def vulnerable_path_traversal(user_file: str):
    """
    CRITICAL VULNERABILITY: Path traversal attack
    No validation on file paths allows reading arbitrary files
    """
    import os
    
    # CRITICAL: User can use '../../../etc/passwd'
    file_path = f'/uploads/{user_file}'
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()  # B101: assert_used
        return content
    except:
        pass  # B110: Bare except


# ============================================
# CRITICAL: Insecure temporary file creation
# ============================================
def vulnerable_temp_file_creation():
    """
    CRITICAL VULNERABILITY: Insecure temporary file creation
    predictable filenames can lead to race conditions
    """
    import tempfile
    
    # CRITICAL: mktemp is predictable (DEPRECATED)
    temp_file = tempfile.mktemp()  # B108: hardcoded_temp_filename
    
    # Write sensitive data to predictable location
    with open(temp_file, 'w') as f:
        f.write('API_KEY=secret_key_12345')
    
    return temp_file


# ============================================
# CRITICAL: Logging sensitive information
# ============================================
def vulnerable_logging_secrets():
    """
    CRITICAL VULNERABILITY: Logging sensitive information
    Secrets exposed in application logs
    """
    import logging
    
    logger = logging.getLogger(__name__)
    
    user_data = {
        'username': 'john',
        'password': 'SecurePassword123!',
        'credit_card': '4532-1234-5678-9010',
        'ssn': '123-45-6789',
        'api_token': 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'
    }
    
    # CRITICAL: Logging sensitive data
    logger.info(f'User login: {user_data}')  # Logs everything including secrets
    logger.debug(f'Password: {user_data["password"]}')
    logger.warning(f'Credit card: {user_data["credit_card"]}')
    
    return user_data


# ============================================
# CRITICAL: Insecure random number generation
# ============================================
def vulnerable_weak_random_generation():
    """
    CRITICAL VULNERABILITY: Using weak random for security operations
    random module is not cryptographically secure
    """
    import random
    
    # CRITICAL: Not suitable for security operations
    session_token = ''.join(
        random.choice('0123456789abcdef') for _ in range(32)
    )  # B311: random
    
    # CRITICAL: Predictable reset token
    reset_token = str(random.randint(100000, 999999))  # 6 digits only!
    
    return session_token, reset_token


# ============================================
# CRITICAL: Insecure deserialization
# ============================================
def vulnerable_insecure_deserialization(pickled_data: bytes):
    """
    CRITICAL VULNERABILITY: Unsafe pickle deserialization
    Can lead to arbitrary code execution
    """
    import pickle
    
    # CRITICAL: Pickle deserialization is dangerous
    # Attacker can create malicious pickled objects
    data = pickle.loads(pickled_data)  # B301: pickle
    
    return data


# ============================================
# CRITICAL: Insecure SSL/TLS configuration
# ============================================
def vulnerable_insecure_ssl_requests():
    """
    CRITICAL VULNERABILITY: Insecure SSL/TLS configuration
    Disabling certificate verification allows man-in-the-middle attacks
    """
    import requests
    
    # CRITICAL: Disabling SSL verification
    response = requests.get(
        'https://api.example.com/data',
        verify=False  # B501: verify=False disables SSL cert verification
    )
    
    # CRITICAL: Ignoring SSL errors
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    return response


# ============================================
# Comment examples of what to look for
# ============================================
"""
Bandit will detect:
- B102: exec_used - Direct code execution
- B105: hardcoded_password - Hardcoded credentials
- B108: hardcoded_temp_filename - Predictable temp files
- B110: try_except_pass - Bare except clauses
- B112: try_except_pass - Exception swallowing
- B201: flask_debug_true - Debug mode enabled
- B301: pickle_use - Unsafe pickle deserialization
- B303: use_of_insecure_MD2_MD4_MD5_SHA1 - Weak hash MD5
- B304: use_of_insecure_hash_functions - Weak hash SHA1
- B312: telnetlib - Unencrypted protocol
- B321: ftplib - Unencrypted file transfer
- B324: probable_use_of_insecure_hash_functions - Weak JWT secret
- B413: pickle_use - Unsafe deserialization
- B501: request_verify_false - SSL verification disabled
- B502: ssl_with_bad_version - Deprecated SSL versions
- B503: ssl_with_no_version - No SSL version specified
- B504: ssl_with_bad_defaults - Insecure SSL defaults
- B505: weak_key_size - Weak cryptographic keys
- B506: yaml_load - YAML code execution
- B602: shell_injection - Command injection
- B605: start_process_with_no_shell - Unsafe shell commands
- B608: sql_injection - SQL injection vulnerability
"""

