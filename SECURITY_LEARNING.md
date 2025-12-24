# GitHub Advanced Security Learning Guide

This repository contains intentional vulnerabilities for learning purposes. These are used to demonstrate GitHub's Advanced Security features.

## Injected Vulnerabilities

### 1. **Secret Scanning Issues**
- **Location**: `backend/main.py` (line ~44)
- **Issue**: Hardcoded credentials in debug code
  - `AZURE_CLIENT_SECRET_BACKUP=abc123xyz789@backup_secret_key`
  - `AZURE_STORAGE_KEY` with connection string
  - `DEBUG_API_KEY` with API key format

- **Location**: `backend/utils.py`
- **Issues**: Multiple hardcoded secrets
  - GitHub token: `ghp_1234567890abcdefghijklmnopqrstuv`
  - Slack token: `xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUv`
  - Stripe key: `sk_test_51234567890abcdefghijklmnopqrstuv`
  - Database passwords and API tokens

### 2. **Code Scanning Issues (SAST)**

#### Injection Vulnerabilities
- **Location**: `backend/main.py` (line ~53)
- **Issue**: SQL Injection in graph search query
  ```python
  url = f"{GRAPH_ENDPOINT}/groups?$filter=startswith(displayName, '{query}')"
  ```

- **Location**: `backend/main.py` (line ~130)
- **Issue**: Command Injection using subprocess with shell=True
  ```python
  subprocess.run(f"echo Group search: {q}", shell=True)
  ```

- **Location**: `backend/utils.py`
- **Issue**: SQL Injection in user query
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}'"
  ```

- **Issue**: eval() with untrusted input (arbitrary code execution)
  ```python
  result = eval(expr)
  ```

#### Path Traversal
- **Location**: `backend/utils.py`
- **Issue**: Unsanitized file path from user input
  ```python
  path = f"/uploads/{filename}"
  ```

#### Cryptography Issues
- **Location**: `backend/main.py` (line ~140)
- **Issue**: Weak hashing algorithm (MD5)
  ```python
  weak_hash_val = hashlib.md5(password.encode()).hexdigest()
  ```

- **Location**: `backend/utils.py`
- **Issue**: MD5 for password hashing (deprecated and insecure)
- **Issue**: Weak JWT secret (hardcoded)
- **Issue**: Insecure randomness for token generation

#### Deserialization Issues
- **Location**: `backend/main.py` (line ~135)
- **Issue**: Unsafe pickle deserialization with untrusted data
  ```python
  result = pickle.loads(data.encode())
  ```

#### XXE (XML External Entity)
- **Location**: `backend/utils.py`
- **Issue**: XML parsing without entity expansion disabled
  ```python
  root = ET.fromstring(xml_data)
  ```

#### Missing Authentication/Authorization
- **Location**: `backend/utils.py`
- **Issue**: Admin endpoint with no permission checks

### 3. **Dependency Vulnerabilities**

- **Location**: `backend/requirements.txt`
- **Issues**:
  - `PyYAML==5.3.1` - Has known CVE (unsafe.yaml() code execution)
  - `Django==3.0.0` - Outdated version with multiple CVEs

## How to Test with GitHub Advanced Security

### Enable Features
1. **Code Scanning (CodeQL)**
   - Go to Settings → Code security and analysis → Code scanning → Enable CodeQL
   - This will run automated SAST analysis

2. **Secret Scanning**
   - Go to Settings → Code security and analysis → Secret scanning → Enable
   - Will detect hardcoded credentials

3. **Dependency Scanning**
   - Go to Settings → Code security and analysis → Dependabot → Enable
   - Will identify vulnerable package versions

### View Results
- **Security** tab on repository main page
- Check "Code scanning alerts" for SAST issues
- Check "Secret scanning" for exposed credentials
- Check "Dependabot alerts" for vulnerable dependencies

### Create a PR
```bash
git checkout -b fix/security-issues
# Make fixes
git add .
git commit -m "Fix: Security vulnerabilities"
git push origin fix/security-issues
```

Then create a pull request to see:
- CodeQL analysis on PR
- Pre-commit scanning alerts
- Suggested fixes

## Learning Objectives

This setup allows you to learn:
1. ✅ How GitHub detects hardcoded secrets
2. ✅ How CodeQL identifies code injection vulnerabilities
3. ✅ How Dependabot finds vulnerable packages
4. ✅ How to review and fix security alerts
5. ✅ How to create secure code patterns
6. ✅ Understanding OWASP Top 10 vulnerabilities
7. ✅ Best practices for secure coding

## Next Steps: Fix the Issues

Once you've explored the security findings, you should:
1. Use parameterized queries instead of string interpolation
2. Remove hardcoded credentials, use environment variables
3. Replace weak hashing with bcrypt/scrypt
4. Remove subprocess shell=True usage
5. Use proper input validation and sanitization
6. Update vulnerable dependencies
7. Add proper authentication checks
8. Use secure random generators (secrets module)
