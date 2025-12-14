# Change Log

All notable changes to the "owasp-cisa-security-scanner" extension will be documented in this file.

## [0.2.0] - 2025-12-13

### Added
- **SQL Injection Detection**: 4 new rules for comprehensive SQL injection detection
  - `A03-SQL-001`: Template literal SQL injection (JavaScript/TypeScript)
  - `A03-SQL-002`: String concatenation SQL injection (all languages)
  - `A03-SQL-003`: Python f-string SQL injection
  - `A03-SQL-004`: Python .format() SQL injection
- **React/JSX Support**: Added `javascriptreact` and `typescriptreact` language mappings
- **Configuration Rescanning**: Open documents now automatically rescan when settings change
- **CONTRIBUTING.md**: Comprehensive contribution guidelines for new contributors

### Fixed
- **25+ Rules Now Active**: Fixed FILE_TYPE_RULES mapping - many rules were defined but never applied
  - React dangerouslySetInnerHTML (A01-002)
  - Weak crypto methods (A02-003, A02-004)
  - setTimeout/setInterval injection (A03-003, A03-004)
  - CORS misconfiguration (A05-001)
  - API keys and secrets detection (A07-002, A07-003, A07-004)
  - SSRF detection (A10-001)
  - All SEC-001 through SEC-008 rules
  - And more...
- **Glob Pattern Security**: Fixed regex injection vulnerability in exclude pattern matching
- **npm Vulnerability**: Updated js-yaml to fix prototype pollution (CWE-1321)
- **ESLint Configuration**: Fixed invalid naming-convention rule

### Changed
- **Improved Hash Function**: Replaced weak 32-bit hash with SHA-256 for reliable content caching
- **Reduced False Positives**:
  - Removed overly-broad `require()`/`import` detection rules
  - Removed generic template literal rule that flagged all `${}` usage
  - Made LLM prompt injection rule context-specific
- **Cleaner Codebase**: Removed unused imports and dead code

### Documentation
- Updated README with VS Code Marketplace badges
- Fixed repository links and marketplace URLs
- Corrected rule count from "70+" to "60+" to match actual count
- Added proper GitHub repository links throughout

## [0.1.0] - 2025-10-20

### Added
- **Configuration System**: Full support for VS Code settings
  - `enableAutoScan`: Toggle automatic scanning on file save
  - `maxFileSize`: Configurable file size limits (default 5MB)
  - `enableHighSeverityOnly`: Filter to show only critical/high severity issues
  - `excludePatterns`: Custom file/folder exclusion patterns
- **Enhanced Diagnostics**: 
  - Improved diagnostic ranges with accurate code highlighting
  - Related information with remediation guidance and CWE links
  - Reference links to OWASP/CISA documentation
- **Language-Specific Rules**: Smart rule filtering for optimal performance
  - JavaScript/TypeScript: innerHTML, crypto methods, eval()
  - Python: exec(), eval() with Python-specific remediation  
  - 50-80% performance improvement through targeted scanning
- **Workspace Integration**:
  - Automatic exclusion of common build/dependency folders
  - Custom exclude patterns support
  - Proper workspace boundary validation
- **Performance Optimizations**:
  - Result caching with content hashing
  - Rule caching per language
  - Memory management with automatic cache cleanup
- **Comprehensive Test Suite**: 40+ test cases covering:
  - Security rule validation and detection
  - Configuration system functionality
  - Language-specific filtering
  - Performance benchmarks

### Fixed
- Configuration settings now properly read and applied
- File size limits enforced based on user settings
- Auto-scan can be disabled via configuration
- Severity filtering works correctly
- Memory leaks prevented through proper cache management

### Changed
- Diagnostic messages now separated from remediation advice
- Better error ranges highlighting actual problematic code
- Improved security rule organization with language targeting

### Technical Improvements
- Added TypeScript strict mode compliance
- Enhanced error handling throughout codebase
- Security-first development practices maintained
- ESLint compliance with automated formatting

## [0.0.1] - 2025-10-01

### Added
- Initial release with basic security scanning
- OWASP Top 10 and CISA Secure by Design rule coverage
- Multi-language support (JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++)
- VS Code Problems panel integration
- Manual and automatic scanning capabilities