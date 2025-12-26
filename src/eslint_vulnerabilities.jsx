/**
 * ESLint Vulnerabilities Reference File
 * 
 * This file contains intentional ESLint violations for learning purposes.
 * Each section demonstrates a vulnerability that ESLint/MSDO will catch.
 * 
 * DO NOT USE IN PRODUCTION
 */

import React from 'react';

// ============================================================
// VULNERABILITY 1: Unsafe use of dangerouslySetInnerHTML
// ESLint Rule: react/no-danger
// Security Impact: XSS (Cross-Site Scripting)
// ============================================================
export function VulnerableDangerousHTML() {
  const userInput = '<img src=x onerror="alert(\'XSS\')" />';
  
  return (
    <div>
      {/* This is vulnerable to XSS attacks */}
      <div dangerouslySetInnerHTML={{ __html: userInput }} />
    </div>
  );
}

// ============================================================
// VULNERABILITY 2: Missing dependencies in useEffect
// ESLint Rule: react-hooks/exhaustive-deps
// Security Impact: Logic bugs, state inconsistencies
// ============================================================
export function VulnerableUseEffect() {
  const [data, setData] = React.useState(null);
  const userId = 'user123';
  
  React.useEffect(() => {
    // Missing 'userId' in dependency array
    // This effect will not re-run when userId changes
    fetch(`/api/users/${userId}`)
      .then(res => res.json())
      .then(data => setData(data));
  }, []); // VULNERABLE: Missing userId dependency
  
  return <div>{data?.name}</div>;
}

// ============================================================
// VULNERABILITY 3: eval() usage
// ESLint Rule: no-eval
// Security Impact: Arbitrary code execution
// ============================================================
export function VulnerableEval() {
  const formula = 'Math.pow(2, 10)'; // Could be user input
  
  // VULNERABLE: eval() can execute arbitrary code
  const result = eval(formula);
  
  return <div>Result: {result}</div>;
}

// ============================================================
// VULNERABILITY 4: Implicit global variables
// ESLint Rule: no-implicit-globals
// Security Impact: Variable pollution, unintended modifications
// ============================================================
function vulnerableGlobalFunction() {
  // VULNERABLE: Creates implicit global variable
  implicitGlobal = 'This is now a global variable'; // Should use 'let', 'const', 'var'
  return implicitGlobal;
}

// ============================================================
// VULNERABILITY 5: with statement (deprecated)
// ESLint Rule: no-with
// Security Impact: Scope confusion, performance issues
// ============================================================
export function VulnerableWithStatement() {
  const obj = { name: 'John', age: 30 };
  
  // VULNERABLE: with statement is deprecated and dangerous
  // This is intentionally vulnerable
  // with (obj) {
  //   return name + age; // Scope is ambiguous
  // }
  
  return null;
}

// ============================================================
// VULNERABILITY 6: Regular expression ReDoS
// ESLint Rule: no-regex-spaces
// Security Impact: Regular Expression Denial of Service
// ============================================================
export function VulnerableRegex() {
  // VULNERABLE: Multiple spaces can cause inefficient matching
  const pattern = /hello   world/; // Multiple spaces
  
  return pattern.test('hello   world');
}

// ============================================================
// VULNERABILITY 7: Unsafe comparison operators
// ESLint Rule: eqeqeq
// Security Impact: Type coercion vulnerabilities
// ============================================================
export function VulnerableComparison() {
  const userInput = '0';
  
  // VULNERABLE: Using == instead of === can cause unexpected behavior
  // null == undefined is true, but null === undefined is false
  if (userInput == 0) { // VULNERABLE: Should use ===
    return 'Input is falsy';
  }
  
  return 'Input is truthy';
}

// ============================================================
// VULNERABILITY 8: Unsafe direct DOM manipulation
// ESLint Rule: no-inner-html (security rule)
// Security Impact: XSS attacks
// ============================================================
export function VulnerableDirectDOM() {
  const handleClick = () => {
    // VULNERABLE: Direct DOM manipulation with innerHTML
    const container = document.getElementById('app');
    const userContent = '<script>alert("XSS")</script>';
    
    if (container) {
      container.innerHTML = userContent; // VULNERABLE
    }
  };
  
  return <button onClick={handleClick}>Load Content</button>;
}

// ============================================================
// VULNERABILITY 9: Missing propTypes validation
// ESLint Rule: react/prop-types
// Security Impact: Type confusion, runtime errors
// ============================================================
export function VulnerableComponent({ user, isAdmin }) {
  // VULNERABLE: No PropTypes defined
  // user.id could be anything, leading to logic errors
  
  return (
    <div>
      <h1>{user.name}</h1>
      {isAdmin && <button>Delete User</button>}
    </div>
  );
}

// ============================================================
// VULNERABILITY 10: innerHTML assignment from untrusted source
// ESLint Rule: security/detect-non-literal-regexp (with MSDO)
// Security Impact: XSS injection
// ============================================================
export function VulnerableTemplateInjection() {
  const [htmlContent, setHtmlContent] = React.useState('');
  
  const handleLoadTemplate = async () => {
    // Simulating fetch from untrusted source
    const apiResponse = '<img src=x onerror="steal()" />';
    
    // VULNERABLE: Setting HTML without sanitization
    setHtmlContent(apiResponse);
  };
  
  return (
    <div>
      <button onClick={handleLoadTemplate}>Load Template</button>
      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />
    </div>
  );
}

// ============================================================
// VULNERABILITY 11: console.log left in production code
// ESLint Rule: no-console (when configured)
// Security Impact: Information disclosure
// ============================================================
export function VulnerableLogging() {
  const apiKey = 'sk-12345-secret-key-67890'; // VULNERABLE: Hardcoded secret
  
  // VULNERABLE: console.log with sensitive data
  console.log('API Key:', apiKey);
  console.warn('User token:', localStorage.getItem('token'));
  
  return <div>Check console for secrets...</div>;
}

// ============================================================
// VULNERABILITY 12: Hardcoded credentials
// ESLint Rule: no-process-env (with MSDO)
// Security Impact: Credential exposure
// ============================================================
export function VulnerableCredentials() {
  // VULNERABLE: Hardcoded credentials
  const dbPassword = 'admin123';
  const apiToken = 'ghp_abcdef123456789';
  const jwtSecret = 'my-super-secret-key-12345';
  
  const connectDB = async () => {
    // These should come from environment variables
    const connection = {
      password: dbPassword,
      token: apiToken,
      secret: jwtSecret
    };
    
    return connection;
  };
  
  return <button onClick={connectDB}>Connect</button>;
}

// ============================================================
// VULNERABILITY 13: Array mutation
// ESLint Rule: no-array-mutation (if configured)
// Security Impact: State inconsistencies, bugs
// ============================================================
export function VulnerableArrayMutation() {
  const [items, setItems] = React.useState(['a', 'b', 'c']);
  
  const handleAdd = (newItem) => {
    // VULNERABLE: Direct array mutation instead of creating new array
    items.push(newItem); // WRONG: Mutates state directly
    setItems(items); // Won't trigger re-render because array reference is same
    
    // CORRECT: items.push(newItem); setItems([...items, newItem]);
  };
  
  return (
    <div>
      <button onClick={() => handleAdd('d')}>Add Item</button>
      {items.map((item, i) => <div key={i}>{item}</div>)}
    </div>
  );
}

// ============================================================
// VULNERABILITY 14: Missing key prop in lists
// ESLint Rule: react/jsx-key
// Security Impact: Item loss, state corruption
// ============================================================
export function VulnerableListRendering() {
  const users = [
    { id: 1, name: 'Alice' },
    { id: 2, name: 'Bob' },
    { id: 3, name: 'Charlie' }
  ];
  
  return (
    <div>
      {/* VULNERABLE: Using index as key or no key at all */}
      {users.map((user, index) => (
        <div key={index}>{user.name}</div> // VULNERABLE: Index as key
        // CORRECT: <div key={user.id}>{user.name}</div>
      ))}
    </div>
  );
}

// ============================================================
// VULNERABILITY 15: Conditional rendering with &&
// ESLint Rule: jsx-a11y/no-static-element-interactions
// Security Impact: Unexpected rendering, logic errors
// ============================================================
export function VulnerableConditionalRender() {
  const count = 0;
  
  // VULNERABLE: count && <div> will render 0 (falsy but rendered)
  // When count is 0, this renders "0" as text
  return (
    <div>
      {count && <div>Count: {count}</div>}
      {/* CORRECT: {count > 0 && <div>Count: {count}</div>} */}
    </div>
  );
}

export default VulnerableDangerousHTML;
