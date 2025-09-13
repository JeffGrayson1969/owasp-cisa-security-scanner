# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a VS Code extension that scans code for security vulnerabilities based on OWASP Top 10, OWASP LLM Top 10, and CISA Secure by Design principles. The extension provides real-time security analysis across multiple programming languages, including specialized GenAI/LLM security detection.

## Common Development Commands

### Build and Development
- `npm run compile` - Build the extension using webpack
- `npm run watch` - Watch for file changes and rebuild automatically
- `npm run vscode:prepublish` - Prepare for publishing (runs compile)

### Code Quality and Security
- `npm run lint` - Run ESLint with automatic fixes
- `npm run lint:check` - Run ESLint in check-only mode (no fixes)
- `npm run security-audit` - Run npm audit for dependency vulnerabilities
- `npm run security-check` - Run both security audit and lint check
- `npm run pretest` - Run compile and lint before testing

### Testing
- `npm test` - Run the extension test suite
- `npm run pretest` - Prepare for testing (compile + lint)

## Architecture

### Core Components

**Main Extension (`src/extension.ts`)**
- `SecureCodeScanner` class: Core scanning engine with security-first design
- File validation with path traversal protection and size limits
- Automatic scanning on file save (500ms debounce) and open
- Diagnostic integration with VS Code Problems panel
- Command registration for manual scanning

**Security Rules Engine (`src/securityRules.ts`)**
- `SecurityRule` interface defining rule structure
- `SECURITY_RULES` array containing 70+ vulnerability detection patterns
- Organized by OWASP Top 10 categories (A01-A10), OWASP LLM Top 10 (LLM01-LLM10), and CISA principles
- Each rule includes severity, remediation advice, CWE IDs, and references
- Specialized GenAI/LLM security rules for JavaScript, TypeScript, and Python

### Extension Architecture

**Activation Events**
- Activates for 10 programming languages: JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++
- Enhanced support for AI/ML codebases with GenAI security rules
- Provides context menu and command palette integration

**Configuration Options**
- `owaspCisaScanner.enableAutoScan`: Auto-scan on file save (default: true)
- `owaspCisaScanner.maxFileSize`: Maximum file size to scan in bytes (default: 5MB)
- `owaspCisaScanner.enableHighSeverityOnly`: Filter to show only high-severity issues (default: false)

**Security Features**
- File extension allowlist prevents scanning of unsupported files
- Workspace boundary validation prevents scanning files outside project
- File size limits prevent DoS attacks
- Regex safety measures prevent infinite loops

### Build System

**Webpack Configuration (`webpack.config.js`)**
- Bundles TypeScript into single `dist/extension.js` file
- Excludes VS Code API from bundle (external dependency)
- Source maps enabled for debugging
- Target: Node.js environment

**TypeScript Configuration (`tsconfig.json`)**
- ES2022 target with Node16 modules
- Strict type checking enabled
- Source maps for debugging support

## Development Patterns

### Adding New Security Rules
1. Add rule to `SECURITY_RULES` array in `src/securityRules.ts`
2. Include OWASP/CISA/LLM category mapping
3. Provide clear remediation guidance
4. Test regex patterns for accuracy and performance
5. Add CWE ID and reference links where applicable
6. For GenAI rules, specify target languages (JavaScript, TypeScript, Python)
7. Update `FILE_TYPE_RULES` mapping to include new rule IDs

### Security Rule Structure
```typescript
{
    id: 'LLM01-001',                      // Unique identifier (A01-A10, LLM01-LLM10, CISA-XXX)
    pattern: /regex_pattern/gi,           // Detection regex
    severity: 'critical',                 // critical|high|medium|low
    category: 'GenAI Prompt Injection',   // Human-readable category
    owaspCategory: 'LLM01: Prompt Injection', // OWASP LLM Top 10 mapping
    cisaCategory: 'Input Validation',     // CISA principle mapping (optional)
    message: 'Description',               // Issue description
    remediation: 'Fix guidance',          // How to resolve
    cweId: 'CWE-74',                     // Common Weakness Enumeration
    references: ['https://...'],          // Additional resources
    languages: ['javascript', 'typescript', 'python'] // Target languages
}
```

### Extension Development Best Practices
- Use `vscode.DiagnosticCollection` for integrating with Problems panel
- Implement proper error handling and user feedback
- Follow security-first coding practices (input validation, size limits)
- Use debouncing for performance-sensitive operations
- Dispose of resources properly in `deactivate()`

## Development Workflow

### Setting Up Development Environment
1. Clone the repository and run `npm install`
2. Open project in VS Code
3. Run `npm run compile` to build initially
4. Use `npm run watch` for continuous compilation during development

### Development Cycle
1. **Make changes** to source files (`src/extension.ts` or `src/securityRules.ts`)
2. **Watch mode** automatically recompiles (or run `npm run compile` manually)
3. **Press F5** to launch Extension Development Host with your changes
4. **Test changes** by opening files in supported languages
5. **Check Problems panel** for security issues detected by your rules
6. **Run linting** with `npm run lint` before committing

### Testing Changes
- **Manual testing**: Use Command Palette → "OWASP/CISA: Scan for Security Issues"
- **Automated tests**: Run `npm test` to execute test suite
- **Security validation**: Run `npm run security-check` before publishing
- **Create test files** with known vulnerabilities to validate new rules

### Debugging Techniques
- **Console logs**: Extension logs appear in Extension Development Host's Debug Console
- **Breakpoints**: Set breakpoints in TypeScript source files (source maps enabled)
- **VS Code DevTools**: Use "Developer: Toggle Developer Tools" in Extension Host
- **Diagnostic inspection**: Check diagnostic objects in Problems panel
- **Regex testing**: Test patterns at regex101.com before adding to rules

### Common Development Tasks

**Adding a New Security Rule:**
1. Research the vulnerability pattern and OWASP/CISA/LLM classification
2. Write and test the regex pattern thoroughly
3. Add rule to appropriate category section in `src/securityRules.ts` (OWASP A01-A10, LLM01-LLM10, or CISA)
4. Update `FILE_TYPE_RULES` mapping to include the new rule ID for target languages
5. Create test files demonstrating both vulnerable and secure code
6. Verify rule triggers correctly and provides helpful remediation
7. Run full test suite and security checks

**Adding GenAI/LLM Security Rules:**
1. Focus on LLM-specific vulnerabilities (prompt injection, output handling, etc.)
2. Target JavaScript/TypeScript (OpenAI, Anthropic APIs) and Python (ML frameworks)
3. Include patterns for popular LLM libraries and frameworks
4. Consider both direct API usage and higher-level abstractions
5. Test with real-world AI/ML code examples

**Modifying Scanner Behavior:**
1. Update logic in `SecureCodeScanner` class in `src/extension.ts`
2. Consider security implications of any file system or user input changes
3. Test with various file sizes and types
4. Verify error handling and user feedback
5. Check performance impact with large files

**Updating Configuration:**
1. Modify `contributes.configuration` in `package.json`
2. Update configuration reading in extension code
3. Test default values and edge cases
4. Update documentation if user-facing

### Performance Considerations
- **Regex optimization**: Avoid catastrophic backtracking patterns
- **File size limits**: Respect `maxFileSize` configuration
- **Debouncing**: Auto-scan uses 500ms debounce to prevent excessive scanning
- **Memory usage**: Large files are validated before processing
- **Rule efficiency**: Order rules by likelihood of match for better performance

### Publishing Workflow
1. Run `npm run security-check` to ensure code quality
2. Update version in `package.json`
3. Run `npm run vscode:prepublish` to create production build
4. Test extension package thoroughly
5. Publish to VS Code Marketplace

## Testing and Debugging

### Running the Extension
1. Open project in VS Code
2. Press F5 to launch Extension Development Host
3. Open files in supported languages to trigger scanning
4. Use "OWASP/CISA: Scan for Security Issues" command

### Test Files Location
- Tests: `src/test/extension.test.ts`
- Test configuration: `.vscode-test.mjs`

## File Structure

```
src/
├── extension.ts        # Main extension logic and VS Code integration
├── securityRules.ts    # Security rule definitions and patterns
└── test/              # Test files
    └── extension.test.ts

dist/                  # Compiled output
├── extension.js       # Bundled extension

package.json          # Extension manifest and dependencies
tsconfig.json         # TypeScript configuration
webpack.config.js     # Build configuration
eslint.config.mjs     # Linting rules
```

## Security Considerations

This extension implements several security measures:
- Input validation and sanitization
- File system access restrictions
- Resource consumption limits
- Protection against regex DoS attacks
- Workspace boundary enforcement

The extension now includes comprehensive GenAI/LLM security detection covering:
- Prompt injection vulnerabilities
- Insecure LLM output handling
- Training data poisoning risks
- Model denial of service attacks
- Sensitive information disclosure
- Insecure plugin/tool designs
- Excessive AI agency concerns
- AI overreliance patterns
- Model theft and exposure risks

When modifying the code, maintain these security principles and avoid introducing new attack vectors. For GenAI rules, ensure patterns are tested against real AI/ML codebases.