/**
 * JavaScript Security Vulnerabilities for Learning GitHub Advanced Security
 * 
 * This file intentionally contains security vulnerabilities for testing
 * GitHub's security scanning capabilities with ESLint and MSDO.
 * 
 * DO NOT USE IN PRODUCTION
 */

// ============================================================
// CRITICAL VULNERABILITY 1: SQL Injection via direct query construction
// Severity: CRITICAL (CWE-89)
// ============================================================
export function critical_sql_injection(userInput, userId) {
  // CRITICAL: Direct SQL query construction with user input
  // Attacker can drop tables, steal data, or modify database
  const query = `SELECT * FROM users WHERE username = '${userInput}' AND id = ${userId}`;
  
  // Example attack: userInput = "' OR '1'='1'; DROP TABLE users; --"
  // Resulting query: SELECT * FROM users WHERE username = '' OR '1'='1'; DROP TABLE users; --' AND id = 123
  
  return executeQuery(query); // CRITICAL: Unsanitized query execution
}

// ============================================================
// CRITICAL VULNERABILITY 2: Command Injection
// Severity: CRITICAL (CWE-78)
// ============================================================
export function critical_command_injection(filename) {
  // CRITICAL: Shell command with unsanitized user input
  const child_process = require('child_process');
  
  // Attacker can execute arbitrary system commands
  // Example: filename = "test.txt; rm -rf /"
  const result = child_process.execSync(`cat ${filename}`); // CRITICAL: No input sanitization
  
  return result;
}

// ============================================================
// CRITICAL VULNERABILITY 3: NoSQL Injection
// Severity: CRITICAL (CWE-943)
// ============================================================
export function critical_nosql_injection(userEmail) {
  // CRITICAL: NoSQL query with unsanitized user input
  const db = require('mongodb');
  
  // Attacker can bypass authentication or access unauthorized data
  // Example: userEmail = { $ne: null } would return all users
  const query = { email: userEmail }; // CRITICAL: No validation
  
  return db.collection('users').findOne(query);
}

// ============================================================
// CRITICAL VULNERABILITY 4: Hardcoded Database Credentials
// Severity: CRITICAL (CWE-798)
// ============================================================
export const critical_db_credentials = {
  // CRITICAL: Exposed database credentials in source code
  // Commit history, decompiled code, or source leaks expose all data
  dbHost: 'prod-database.company.com',
  dbPort: 5432,
  dbName: 'production_db',
  dbUsername: 'admin',
  dbPassword: 'P@ssw0rd123!SuperSecret', // CRITICAL: Plain text password
  rootPassword: 'RootAccessPassword2024'
};

// ============================================================
// CRITICAL VULNERABILITY 5: Hardcoded API Keys and Auth Tokens
// Severity: CRITICAL (CWE-798)
// ============================================================
export const critical_api_keys = {
  // CRITICAL: Production API keys in source code
  // Attackers can impersonate the application and access all data
  
  // AWS Credentials
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  awsSessionToken: 'AQoDYXdzEJr...',
  
  // GitHub PAT Token (full access)
  githubToken: 'ghp_16C7e42F292c6912E7710c838347Ae178B4a',
  
  // Stripe API Key (production)
  stripeSecretKey: 'sk_live_4eC39HqLyjWDarhtT657tHtF',
  
  // Twilio Credentials
  twilioAccountSid: 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  twilioAuthToken: 'your_auth_token_12345',
  
  // Google API Key
  googleApiKey: 'AIzaSyDYwzlHQ5_vscejTS4qsU0OiJlxVeCB97A',
  
  // Firebase Config
  firebaseApiKey: 'AIzaSyDYwzlHQ5_vscejTS4qsU0OiJlxVeCB97A',
  firebaseDatabaseUrl: 'https://myproject.firebaseio.com',
  
  // JWT Secret (production)
  jwtSecret: 'super_secret_key_that_should_never_be_exposed_in_code',
  
  // OAuth tokens
  oauthAccessToken: 'ya29.a0AWY7CkliYhZcUBl...',
  
  // Private key for SSL/TLS
  privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Z3qX2...'
};

// ============================================================
// CRITICAL VULNERABILITY 6: Authentication Bypass
// Severity: CRITICAL (CWE-287)
// ============================================================
export function critical_auth_bypass(userId) {
  // CRITICAL: No authentication check before sensitive operation
  // Attacker can directly call this function without being logged in
  
  return getUserData(userId); // NO AUTH CHECK - CRITICAL!
}

// ============================================================
// CRITICAL VULNERABILITY 7: Insecure Deserialization
// Severity: CRITICAL (CWE-502)
// ============================================================
export function critical_insecure_deserialization(serializedData) {
  // CRITICAL: Deserializing untrusted data can execute arbitrary code
  const pickle = require('pickle');
  
  // Attacker can inject malicious objects that execute on deserialization
  const data = pickle.loads(serializedData); // CRITICAL: No validation
  
  return data;
}

// ============================================================
// CRITICAL VULNERABILITY 8: Path Traversal / Directory Traversal
// Severity: CRITICAL (CWE-22)
// ============================================================
export function critical_path_traversal(userProvidedPath) {
  // CRITICAL: No path validation allows reading/writing arbitrary files
  const fs = require('fs');
  
  // Attacker can use: "../../../../etc/passwd" to read sensitive files
  // Or: "../../../../var/www/html/config.php" to access configs
  const fullPath = `/uploads/${userProvidedPath}`; // CRITICAL: No sanitization
  
  return fs.readFileSync(fullPath, 'utf8'); // CRITICAL: Unrestricted file read
}

// ============================================================
// CRITICAL VULNERABILITY 9: Remote Code Execution via Eval
// Severity: CRITICAL (CWE-95)
// ============================================================
export function critical_rce_eval(userCode) {
  // CRITICAL: eval() with user input = arbitrary code execution
  // Attacker can steal data, modify database, install backdoors, etc.
  
  const result = eval(userCode); // CRITICAL: Direct eval of user input
  
  return result;
}

// ============================================================
// VULNERABILITY 2: innerHTML with untrusted data - XSS
// ESLint Rule: no-inner-html (security rule)
// ============================================================
export function vulnerable_innerhtml_xss(htmlString) {
  const container = document.getElementById('app');
  // VULNERABLE: innerHTML with untrusted content = XSS
  container.innerHTML = htmlString; // Could contain malicious scripts
  return container;
}

// ============================================================
// VULNERABILITY 3: dangerouslySetInnerHTML in React
// ESLint Rule: react/no-danger
// ============================================================
export function VulnerableDangerousHTMLComponent({ content }) {
  // VULNERABLE: dangerouslySetInnerHTML with user input
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// ============================================================
// VULNERABILITY 4: Hardcoded Credentials/Secrets
// ESLint Rule: no-secrets (with MSDO)
// ============================================================
export const vulnerableCredentials = {
  // VULNERABLE: Hardcoded API keys and tokens
  apiKey: 'sk_live_abc123def456ghi789jkl',
  githubToken: 'ghp_1234567890abcdefghijklmnopqrst',
  databasePassword: 'admin@123#SecurePassword',
  jwtSecret: 'my-super-secret-jwt-key-12345',
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  slackWebhook: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
};

// ============================================================
// VULNERABILITY 5: Unsafe use of Function() constructor
// ESLint Rule: no-function-constructor-with-string-args
// ============================================================
export function vulnerable_function_constructor(code) {
  // VULNERABLE: Function constructor with string argument
  const dynamicFunc = new Function('a', 'b', code); // User code as function body
  return dynamicFunc(1, 2);
}

// ============================================================
// VULNERABILITY 6: Unsafe comparison operators
// ESLint Rule: eqeqeq
// ============================================================
export function vulnerable_loose_equality(userInput) {
  // VULNERABLE: Using == instead of ===
  if (userInput == '0') { // Should use ===
    return 'Zero string';
  }
  
  // VULNERABLE: Loose comparison can cause unexpected behavior
  if (userInput == false) { // Should use ===
    return 'Falsy value';
  }
  
  if (null == undefined) { // VULNERABLE: This is true with ==
    return 'null equals undefined';
  }
  
  return 'Other value';
}

// ============================================================
// VULNERABILITY 7: console.log with sensitive data
// ESLint Rule: no-console (when configured)
// ============================================================
export function vulnerable_console_logging(user) {
  // VULNERABLE: Logging sensitive information
  console.log('User password:', user.password);
  console.warn('API token:', localStorage.getItem('authToken'));
  console.info('Credit card:', user.creditCard);
  console.error('User SSN:', user.ssn);
  
  return user;
}

// ============================================================
// VULNERABILITY 8: Direct DOM manipulation with eval-like behavior
// ESLint Rule: no-implied-eval
// ============================================================
export function vulnerable_settimeout_string(delay) {
  // VULNERABLE: setTimeout with string is like eval
  setTimeout('alert("Dangerous code")', delay); // Should use arrow function
  
  // VULNERABLE: setInterval with string
  setInterval('processUserData()', 5000); // Should be proper function
  
  return true;
}

// ============================================================
// VULNERABILITY 9: Missing input validation
// ESLint Rule: no-eval + custom rules
// ============================================================
export function vulnerable_no_input_validation(userEmail, userId) {
  // VULNERABLE: No validation before using in query
  const query = `SELECT * FROM users WHERE email = '${userEmail}' AND id = ${userId}`;
  
  // VULNERABLE: String concatenation in SQL = SQL Injection
  return query;
}

// ============================================================
// VULNERABILITY 10: Unsafe regular expressions
// ESLint Rule: no-regex-spaces
// ============================================================
export function vulnerable_regex_patterns() {
  // VULNERABLE: Multiple spaces in regex (inefficient)
  const pattern1 = /hello   world/; // Multiple spaces
  
  // VULNERABLE: Unescaped special characters
  const pattern2 = /user@example.com/; // @ should be escaped
  
  // VULNERABLE: Complex regex that could cause ReDoS
  const pattern3 = /(a+)+b/; // Catastrophic backtracking
  
  return {
    pattern1: pattern1.test('hello   world'),
    pattern2: pattern2.test('user@example.com'),
    pattern3: pattern3.test('aaaaaaaaaaaaaaaaaaab')
  };
}

// ============================================================
// VULNERABILITY 11: Implicit global variables
// ESLint Rule: no-implicit-globals
// ============================================================
function vulnerable_implicit_global() {
  // VULNERABLE: Creates global variable without declaration
  implicitGlobalVar = 'This pollutes the global scope'; // Missing var/let/const
  
  return implicitGlobalVar;
}

// ============================================================
// VULNERABILITY 12: Array mutation in state-like scenarios
// ESLint Rule: no-array-mutation (custom)
// ============================================================
export function vulnerable_array_mutation(items) {
  // VULNERABLE: Direct mutation instead of creating new array
  items.push('new item'); // Mutates original array
  items[0] = 'modified'; // Direct modification
  items.splice(1, 1); // Modifying in place
  
  return items; // Returns mutated original
}

// ============================================================
// VULNERABILITY 13: Missing error handling
// ESLint Rule: no-implicit-error-handling
// ============================================================
export async function vulnerable_missing_error_handling(url) {
  try {
    // VULNERABLE: No error handling in async operation
    const response = await fetch(url);
    const data = await response.json();
    
    // VULNERABLE: Assuming data structure without validation
    return data.user.profile.email;
  } catch (e) {
    // VULNERABLE: Swallowing error
    // pass - no error handling
  }
}

// ============================================================
// VULNERABILITY 14: Unvalidated object/array access
// ESLint Rule: no-optional-chaining-enforcement
// ============================================================
export function vulnerable_unsafe_property_access(userData) {
  // VULNERABLE: No validation before property access
  return userData.address.country.code; // Any null/undefined breaks this
}

// ============================================================
// VULNERABILITY 15: localStorage with sensitive data
// ESLint Rule: no-storage-of-sensitive-data
// ============================================================
export function vulnerable_localstorage_secrets(user) {
  // VULNERABLE: Storing secrets in localStorage (accessible to XSS)
  localStorage.setItem('userPassword', user.password);
  localStorage.setItem('apiToken', user.apiToken);
  localStorage.setItem('creditCard', user.creditCard);
  localStorage.setItem('ssn', user.ssn);
  
  // VULNERABLE: Retrieving and logging
  console.log('Token from storage:', localStorage.getItem('apiToken'));
  
  return localStorage.getItem('userPassword');
}

// ============================================================
// VULNERABILITY 16: Unsafe fetch without CORS validation
// ESLint Rule: no-cors-bypass
// ============================================================
export function vulnerable_unsafe_cors() {
  // VULNERABLE: No CORS validation, accepts credentials
  return fetch('https://api.example.com/data', {
    method: 'GET',
    credentials: 'include', // Sends cookies to cross-origin
    mode: 'no-cors' // Bypasses CORS checking
  });
}

// ============================================================
// VULNERABILITY 17: Missing Content Security Policy
// ESLint Rule: no-csp-bypass
// ============================================================
export function vulnerable_csp_bypass() {
  // VULNERABLE: Dynamic script injection bypasses CSP
  const script = document.createElement('script');
  script.src = 'https://untrusted-cdn.example.com/malware.js';
  document.head.appendChild(script); // Could execute malicious code
  
  return script;
}

// ============================================================
// VULNERABILITY 18: Unsafe JSON parsing
// ESLint Rule: no-unsafe-json
// ============================================================
export function vulnerable_unsafe_json_parse(jsonString) {
  try {
    // VULNERABLE: Using eval-like JSON parsing (if extended)
    // Note: JSON.parse is safe, but showing alternative methods
    const result = eval('(' + jsonString + ')'); // VULNERABLE: eval with JSON
    
    return result;
  } catch (e) {
    return null;
  }
}

// ============================================================
// VULNERABILITY 19: Using Math.random for security
// ESLint Rule: no-random-for-security
// ============================================================
export function vulnerable_weak_random_generation() {
  // VULNERABLE: Math.random() is not cryptographically secure
  const randomToken = Math.random().toString(36).substring(2);
  const randomId = Math.random().toString(16).slice(2);
  const randomSecret = Math.floor(Math.random() * 100000);
  
  return {
    token: randomToken,
    id: randomId,
    secret: randomSecret
  };
}

// ============================================================
// VULNERABILITY 20: Prototype pollution
// ESLint Rule: no-prototype-pollution
// ============================================================
export function vulnerable_prototype_pollution(obj, key, value) {
  // VULNERABLE: Assigning to object without validation
  // If key is '__proto__' or 'constructor', pollutes prototype chain
  obj[key] = value; // No validation
  
  return obj;
}

// ============================================================
// VULNERABILITY 21: Open redirect
// ESLint Rule: no-open-redirect
// ============================================================
export function vulnerable_open_redirect(redirectUrl) {
  // VULNERABLE: Redirecting to user-controlled URL without validation
  window.location.href = redirectUrl; // Could redirect to malicious site
  
  return redirectUrl;
}

// ============================================================
// VULNERABILITY 22: Missing rate limiting
// ESLint Rule: no-rate-limit-bypass
// ============================================================
export async function vulnerable_no_rate_limiting(userId, attempts = 0) {
  // VULNERABLE: No rate limiting on login attempts
  // Attacker can brute force passwords
  const maxAttempts = 999999; // No real limit
  
  if (attempts > maxAttempts) {
    return false; // This limit is essentially non-existent
  }
  
  return true;
}

// ============================================================
// VULNERABILITY 23: Unsafe file operations
// ESLint Rule: no-unsafe-file-operations
// ============================================================
export function vulnerable_unsafe_file_path(userInput) {
  // VULNERABLE: Path traversal attack
  // If userInput = '../../etc/passwd', could read sensitive files
  const filePath = `/uploads/${userInput}`;
  
  return filePath;
}

// ============================================================
// VULNERABILITY 24: Missing HTTPS enforcement
// ESLint Rule: no-mixed-content
// ============================================================
export function vulnerable_mixed_content() {
  // VULNERABLE: Loading resources over HTTP in HTTPS page
  const scripts = [
    'http://cdn.example.com/script.js', // Should be https
    'http://api.example.com/data.js'    // Should be https
  ];
  
  scripts.forEach(src => {
    const script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
  });
  
  return scripts;
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 10: Session Fixation
// Severity: CRITICAL (CWE-384)
// ============================================================
export function critical_session_fixation(sessionId) {
  // CRITICAL: Not regenerating session after login
  // Attacker can hijack user session
  
  // VULNERABLE: Setting session without regeneration
  sessionStorage.setItem('sessionId', sessionId); // No session regeneration after auth
  
  return sessionId;
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 11: Broken Authentication
// Severity: CRITICAL (CWE-287)
// ============================================================
export async function critical_broken_authentication(username, password) {
  // CRITICAL: Multiple authentication weaknesses
  
  // 1. No rate limiting on login attempts - brute force possible
  // 2. Plain text password comparison
  // 3. No password requirements validation
  // 4. Credentials sent over HTTP (not HTTPS)
  
  const response = await fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({
      username: username,
      password: password  // CRITICAL: Plain text password over HTTP
    })
  });
  
  const data = await response.json();
  
  // CRITICAL: No token expiration check
  localStorage.setItem('token', data.token); // Token stored indefinitely
  localStorage.setItem('password', password); // CRITICAL: Storing password!
  
  return data;
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 12: Sensitive Data Exposure
// Severity: CRITICAL (CWE-200)
// ============================================================
export function critical_sensitive_data_exposure() {
  // CRITICAL: Exposing sensitive information in multiple ways
  
  // 1. In error messages
  try {
    throw new Error('Database connection failed: user=admin@prod-db.com pass=SecurePass123');
  } catch (e) {
    console.error(e.message); // CRITICAL: Exposing DB credentials
  }
  
  // 2. In client-side code
  const apiKey = 'sk_live_4eC39HqLyjWDarhtT657tHtF'; // CRITICAL: Hardcoded key
  const database = {
    host: 'prod-database.company.com',
    user: 'admin',
    password: 'SuperSecure@123!' // CRITICAL: Plaintext password
  };
  
  // 3. In HTML comments (visible to users)
  const html = `
    <!-- CRITICAL: Exposed credentials in HTML
    Admin login: admin:AdminPass123
    Database: mongodb://admin:password@prod-db.com:27017/main
    API Key: ghp_16C7e42F292c6912E7710c838347Ae178B4a
    -->
  `;
  
  return { apiKey, database, html };
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 13: Race Condition
// Severity: CRITICAL (CWE-362)
// ============================================================
export async function critical_race_condition(userId) {
  // CRITICAL: Check-then-act race condition
  
  // Step 1: Check if user exists (vulnerable to race condition)
  const user = await fetchUser(userId);
  
  if (!user) {
    // Step 2: Create user (Time gap - race condition possible!)
    // Another request could create same user in between
    await createUser(userId, { balance: 1000 });
  }
  
  // CRITICAL: Two requests could both create the user
  // Or transfer funds twice on same account
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 14: LDAP Injection
// Severity: CRITICAL (CWE-90)
// ============================================================
export function critical_ldap_injection(username) {
  // CRITICAL: LDAP query with unsanitized input
  
  // Attacker can use: username = "*)(cn=*" to bypass authentication
  const ldapQuery = `(&(uid=${username})(userPassword=*))`;
  
  // Execute LDAP query without escaping
  return executeLdapQuery(ldapQuery); // CRITICAL
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 15: XXE Injection
// Severity: CRITICAL (CWE-611)
// ============================================================
export function critical_xxe_injection(xmlContent) {
  // CRITICAL: XML External Entity (XXE) attack
  
  const xml = `<?xml version="1.0"?>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <data>&xxe;</data>
    ${xmlContent}`;
  
  // Parse without XXE protection
  const parser = new DOMParser();
  const doc = parser.parseFromString(xml, 'application/xml'); // CRITICAL: No XXE protection
  
  return doc;
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 16: Unvalidated Redirects
// Severity: CRITICAL (CWE-601)
// ============================================================
export function critical_unvalidated_redirect(redirectUrl) {
  // CRITICAL: Redirecting to user-controlled URL
  
  // Attacker can redirect to phishing site
  // Example: redirectUrl = "https://evil.com"
  
  const whitelist = []; // CRITICAL: Empty whitelist!
  
  if (whitelist.includes(redirectUrl)) {
    window.location.href = redirectUrl;
  }
  
  // CRITICAL: If whitelist is empty, any URL is allowed
  window.location.href = redirectUrl; // CRITICAL: No validation
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 17: Insecure Cryptography
// Severity: CRITICAL (CWE-327)
// ============================================================
export function critical_insecure_cryptography(data) {
  // CRITICAL: Using insecure cryptographic algorithms
  
  const crypto = require('crypto');
  
  // CRITICAL: MD5 is broken and insecure
  const hash = crypto.createHash('md5');
  hash.update(data);
  const md5 = hash.digest('hex'); // CRITICAL: Never use MD5 for anything
  
  // CRITICAL: DES is deprecated
  const cipher = crypto.createCipher('des', 'secret');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return { md5, encrypted };
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 18: Type Confusion
// Severity: HIGH (CWE-843)
// ============================================================
export function critical_type_confusion(userInput) {
  // CRITICAL: Type confusion via loose equality
  
  // 0 == "0" is true with loose equality
  // null == undefined is true with loose equality
  // [] == false is true with loose equality
  
  if (userInput == 0) { // CRITICAL: Should use ===
    return 'zero';
  }
  
  if (userInput == false) { // CRITICAL: Unintended matches
    return 'falsy';
  }
  
  if (userInput == []) { // CRITICAL: Type confusion
    return 'empty array';
  }
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 19: Insecure Direct Object Reference (IDOR)
// Severity: CRITICAL (CWE-639)
// ============================================================
export async function critical_idor(userId) {
  // CRITICAL: No authorization check on direct object reference
  
  // Attacker can change userId in URL and access other users' data
  // Example: GET /api/user/123 -> attacker uses /api/user/456
  
  // No authorization check - just fetch whatever is requested
  const userData = await fetch(`/api/user/${userId}`).then(r => r.json()); // CRITICAL: No auth
  
  return userData; // Returns other users' data!
}

// ============================================================
// ADDITIONAL CRITICAL VULNERABILITY 20: Weak JWT Implementation
// Severity: CRITICAL (CWE-347)
// ============================================================
export function critical_weak_jwt(payload) {
  // CRITICAL: Weak JWT secret and no algorithm checking
  
  const jwt = require('jsonwebtoken');
  
  // CRITICAL: Very weak secret - easily bruteforced
  const secret = '123456'; // 6 digits only!
  
  const token = jwt.sign(payload, secret); // CRITICAL: Weak secret
  
  // CRITICAL: Not checking algorithm - vulnerable to algorithm confusion
  // Attacker can change "alg" to "none" to bypass verification
  const decoded = jwt.decode(token); // No verification!
  
  return token;
}

export default {
  vulnerable_eval_execution,
  vulnerable_innerhtml_xss,
  vulnerable_function_constructor,
  vulnerable_loose_equality,
  vulnerable_console_logging,
  vulnerable_settimeout_string,
  vulnerable_no_input_validation,
  vulnerable_regex_patterns,
  vulnerable_array_mutation,
  vulnerable_missing_error_handling,
  vulnerable_unsafe_property_access,
  vulnerable_localstorage_secrets,
  vulnerable_unsafe_cors,
  vulnerable_csp_bypass,
  vulnerable_unsafe_json_parse,
  vulnerable_weak_random_generation,
  vulnerable_prototype_pollution,
  vulnerable_open_redirect,
  vulnerable_no_rate_limiting,
  vulnerable_unsafe_file_path,
  vulnerable_mixed_content,
  // CRITICAL vulnerabilities
  critical_sql_injection,
  critical_command_injection,
  critical_nosql_injection,
  critical_auth_bypass,
  critical_insecure_deserialization,
  critical_path_traversal,
  critical_rce_eval,
  critical_db_credentials,
  critical_api_keys,
  // ADDITIONAL CRITICAL vulnerabilities
  critical_session_fixation,
  critical_broken_authentication,
  critical_sensitive_data_exposure,
  critical_race_condition,
  critical_ldap_injection,
  critical_xxe_injection,
  critical_unvalidated_redirect,
  critical_insecure_cryptography,
  critical_type_confusion,
  critical_idor,
  critical_weak_jwt
};
