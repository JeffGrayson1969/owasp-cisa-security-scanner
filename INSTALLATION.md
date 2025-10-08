# OWASP CISA Security Scanner - Installation Guide

## Quick Installation (From VSIX)

The extension has been built and packaged. To install:

```bash
cd /Users/jeffgrayson/owasp-cisa-security-scanner
code --install-extension owasp-cisa-security-scanner-0.1.0.vsix
```

## Building from Source

### Prerequisites
- Node.js 16+
- npm
- VS Code 1.74+

### Steps

1. **Clone the repository**
```bash
git clone https://github.com/JeffGrayson1969/owasp-cisa-security-scanner.git
cd owasp-cisa-security-scanner
```

2. **Install dependencies**
```bash
npm install
```

3. **Build the extension**
```bash
npm run compile
```

4. **Package the extension**
```bash
npm install -g @vscode/vsce
vsce package
```

5. **Install in VS Code**
```bash
code --install-extension owasp-cisa-security-scanner-0.1.0.vsix
```

## Usage

### Automatic Scanning
- The scanner automatically runs when you open or save files
- Security issues appear as diagnostics in your code

### Manual Scanning
**Option 1: Right-click menu**
- Right-click in any file
- Select "Scan for Security Issues"

**Option 2: Command Palette**
- Press `Cmd+Shift+P` (Mac) or `Ctrl+Shift+P` (Windows/Linux)
- Type "OWASP/CISA: Scan for Security Issues"
- Press Enter

### Viewing Results
- Security issues appear with squiggly underlines
- Hover over highlighted code to see details
- Check the "Problems" panel (`Cmd+Shift+M` / `Ctrl+Shift+M`)

## Configuration

Access settings via VS Code Preferences:

```json
{
    // Enable automatic scanning on file save
    "owaspCisaScanner.enableAutoScan": true,

    // Maximum file size to scan (bytes)
    "owaspCisaScanner.maxFileSize": 5242880,

    // Only show high severity vulnerabilities
    "owaspCisaScanner.enableHighSeverityOnly": false,

    // Additional patterns to exclude
    "owaspCisaScanner.excludePatterns": [
        "**/test/**",
        "**/*.test.ts"
    ]
}
```

## What It Detects

### OWASP Top 10
- SQL Injection
- Cross-Site Scripting (XSS)
- Insecure Deserialization
- XML External Entities (XXE)
- Broken Access Control
- Security Misconfiguration
- And more...

### OWASP LLM Top 10
- Prompt Injection
- Insecure Output Handling
- Training Data Poisoning
- Model Denial of Service
- Supply Chain Vulnerabilities
- Sensitive Information Disclosure
- And more...

### CISA Secure by Design
- Default secure configurations
- Input validation
- Cryptographic best practices
- Secure authentication patterns

## Supported Languages

- JavaScript (.js)
- TypeScript (.ts)
- Python (.py)
- Java (.java)
- C# (.cs)
- PHP (.php)
- Ruby (.rb)
- Go (.go)
- C/C++ (.c, .cpp)

## Testing the Scanner

Try opening a file with potential security issues:

```javascript
// test.js
const username = req.query.username;
eval(username); // Should detect: Dangerous use of eval()

const password = "hardcoded123"; // Should detect: Hardcoded credentials

const query = "SELECT * FROM users WHERE id = " + userId; // Should detect: SQL Injection risk
```

## Troubleshooting

### Extension not appearing
1. Restart VS Code
2. Check Extensions panel for "OWASP CISA Security Scanner"
3. Verify installation: `code --list-extensions | grep owasp`

### No diagnostics showing
1. Check file type is supported
2. Verify auto-scan is enabled in settings
3. Try manual scan (right-click → "Scan for Security Issues")
4. Check file size is under maxFileSize limit

### Build errors
- Ensure Node.js 16+ is installed
- Delete `node_modules` and `package-lock.json`
- Run `npm install` again
- Run `npm run compile`

## Development

### Run in debug mode
1. Open the scanner project in VS Code
2. Press F5 to launch Extension Development Host
3. Open a file in the new window to test

### Run tests
```bash
npm test
```

### Lint code
```bash
npm run lint
```

## Uninstalling

```bash
code --uninstall-extension JeffGrayson1969.owasp-cisa-security-scanner
```

Or via VS Code Extensions panel: Right-click extension → Uninstall

## Support

- **Issues:** https://github.com/JeffGrayson1969/owasp-cisa-security-scanner/issues
- **Repository:** https://github.com/JeffGrayson1969/owasp-cisa-security-scanner

## License

MIT
