# Contributing to OWASP/CISA Security Scanner

Thank you for your interest in contributing to the OWASP/CISA Security Scanner! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## How to Contribute

### Reporting Bugs

1. Check existing [GitHub Issues](https://github.com/JeffGrayson1969/owasp-cisa-security-scanner/issues) to avoid duplicates
2. Use the bug report template if available
3. Include:
   - VS Code version
   - Extension version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant code snippets (if applicable)

### Suggesting Features

1. Open a [GitHub Issue](https://github.com/JeffGrayson1969/owasp-cisa-security-scanner/issues) with the "enhancement" label
2. Describe the use case and expected behavior
3. Explain why this would benefit users

### Adding Security Rules

Security rules are the core of this extension. To add a new rule:

1. **Research the vulnerability**
   - Identify the OWASP Top 10, OWASP LLM Top 10, or CISA category
   - Find the relevant CWE ID
   - Gather reference documentation

2. **Add the rule to `src/securityRules.ts`**
   ```typescript
   {
       id: 'A03-XXX',                    // Unique ID following category pattern
       pattern: /your_regex_pattern/gi,  // Detection regex
       severity: 'high',                 // critical|high|medium|low
       category: 'Category Name',
       owaspCategory: 'A03: Injection',  // OWASP mapping
       cisaCategory: 'Input Validation', // CISA mapping (optional)
       message: 'Clear description of the vulnerability',
       remediation: 'Specific fix guidance',
       cweId: 'CWE-XXX',
       references: ['https://...'],
       languages: ['javascript', 'typescript'] // Target languages
   }
   ```

3. **Test your regex pattern**
   - Use [regex101.com](https://regex101.com) to test patterns
   - Ensure minimal false positives
   - Test against both vulnerable and safe code

4. **Add test cases to `src/test/securityRules.test.ts`**
   ```typescript
   test('Detects your vulnerability', () => {
       const rule = SECURITY_RULES.find(r => r.id === 'A03-XXX');
       assert.ok(rule, 'Rule not found');
       
       // Test positive cases
       assert.ok(rule!.pattern.test('vulnerable_code'));
       
       // Test negative cases (false positives)
       assert.ok(!rule!.pattern.test('safe_code'));
   });
   ```

5. **Update FILE_TYPE_RULES mapping** if adding language-specific rules

### Code Contributions

1. **Fork and clone** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Install dependencies**: `npm install`
4. **Make your changes**
5. **Run quality checks**:
   ```bash
   npm run lint          # Fix linting issues
   npm run compile       # Ensure it builds
   npm run security-check # Run security audit
   npm test              # Run tests
   ```
6. **Commit with clear messages**: Follow conventional commits
7. **Push and create a Pull Request**

## Development Setup

### Prerequisites
- Node.js 16+
- VS Code 1.74+
- Git

### Getting Started
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/owasp-cisa-security-scanner.git
cd owasp-cisa-security-scanner

# Install dependencies
npm install

# Compile
npm run compile

# Open in VS Code
code .

# Press F5 to launch Extension Development Host
```

### Project Structure
```
src/
├── extension.ts        # Main extension logic
├── securityRules.ts    # Security rule definitions
└── test/              # Test files

dist/                  # Compiled output
package.json          # Extension manifest
```

## Pull Request Guidelines

- **One feature/fix per PR** - Keep changes focused
- **Update tests** - Add or modify tests as needed
- **Update documentation** - Update README if adding user-facing features
- **Follow existing code style** - ESLint will help enforce this
- **Write clear commit messages** - Describe what and why

### PR Checklist
- [ ] Code compiles without errors (`npm run compile`)
- [ ] Linting passes (`npm run lint:check`)
- [ ] Tests pass (`npm test`)
- [ ] Security audit passes (`npm run security-audit`)
- [ ] Documentation updated (if applicable)

## Security Rule Quality Standards

When adding or modifying security rules:

1. **Minimize false positives** - Rules should be precise
2. **Provide actionable remediation** - Tell users how to fix issues
3. **Include references** - Link to documentation
4. **Test thoroughly** - Cover edge cases
5. **Consider performance** - Avoid expensive regex patterns

## Questions?

- Open a [GitHub Issue](https://github.com/JeffGrayson1969/owasp-cisa-security-scanner/issues)
- Check existing documentation in CLAUDE.md

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
