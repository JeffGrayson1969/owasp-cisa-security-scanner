# Change Log

All notable changes to the "owasp-cisa-security-scanner" extension will be documented in this file.

## [0.1.0] - 2024-09-11

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

## [0.0.1] - 2024-08-24

### Added
- Initial release with basic security scanning
- OWASP Top 10 and CISA Secure by Design rule coverage
- Multi-language support (JavaScript, TypeScript, Python, Java, C#, PHP, Ruby, Go, C/C++)
- VS Code Problems panel integration
- Manual and automatic scanning capabilities