/**
 * DEMO FILE: Security Vulnerabilities for Screenshot Examples
 * This file intentionally contains security issues to demonstrate
 * the OWASP/CISA Security Scanner's detection capabilities.
 *
 * DO NOT use this code in production!
 */

// ❌ A03: Code Injection - eval() with user input
function processUserCode(userInput) {
    eval(userInput);  // Critical: Arbitrary code execution
}

// ❌ A01: XSS - innerHTML assignment
function displayUserContent(content) {
    document.getElementById('output').innerHTML = content;  // High: XSS vulnerability
}

// ❌ A02: Weak Cryptography
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');  // Critical: MD5 is broken
}

// ❌ A07: Hardcoded Credentials
const dbConfig = {
    host: 'localhost',
    password: 'admin123',  // Critical: Hardcoded password
    apiKey: 'sk-1234567890abcdef'  // Critical: Exposed API key
};

// ❌ A03: SQL Injection
async function getUser(userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // Critical: SQL injection
    return db.query(query);
}

// ❌ A09: Sensitive Data Logging
function authenticateUser(username, password) {
    console.log('Login attempt:', username, password);  // High: Password in logs
    // ... authentication logic
}

// ❌ A02: Insecure Random
function generateToken() {
    return Math.random().toString(36);  // High: Not cryptographically secure
}

// ❌ LLM01: Prompt Injection Risk
async function askAI(userQuestion) {
    const prompt = `You are a helpful assistant. User says: ${userQuestion}`;
    return await openai.chat.completions.create({
        messages: [{ role: 'user', content: prompt }]
    });
}

// ❌ LLM02: Executing LLM Output
async function runAICode(response) {
    const code = response.choices[0].message.content;
    eval(code);  // Critical: Executing untrusted LLM output
}

// ❌ CISA: Command Injection
const { exec } = require('child_process');
function runCommand(userCommand) {
    exec(userCommand);  // Critical: Command injection
}
