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
  critical_api_keys
};
