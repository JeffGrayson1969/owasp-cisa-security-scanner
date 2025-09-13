export interface SecurityRule {
    readonly id: string;
    readonly pattern: RegExp;
    readonly severity: 'critical' | 'high' | 'medium' | 'low';
    readonly category: string;
    readonly message: string;
    readonly owaspCategory?: string;
    readonly cisaCategory?: string;
    readonly remediation: string;
    readonly cweId?: string;
    readonly references?: readonly string[];
    readonly languages?: readonly string[]; // Language targeting
}

/**
 * Comprehensive security rules covering OWASP Top 10 and CISA Secure by Design principles
 * Rules are organized by security category and severity
 */
export const SECURITY_RULES: readonly SecurityRule[] = [
    // ===============================
    // OWASP A01: Broken Access Control
    // ===============================
    {
        id: 'A01-001',
        pattern: /\.(?:innerHTML|outerHTML)\s*=\s*(?!['"`]\s*$)/gi,
        severity: 'high',
        category: 'XSS Prevention',
        owaspCategory: 'A01: Broken Access Control',
        message: 'Potential XSS vulnerability: Unsafe HTML assignment without sanitization',
        remediation: 'Use textContent, createElement, or DOMPurify.sanitize() for HTML content',
        cweId: 'CWE-79',
        references: ['https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)'],
        languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact']
    },
    {
        id: 'A01-002',
        pattern: /dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:/gi,
        severity: 'high',
        category: 'XSS Prevention',
        owaspCategory: 'A01: Broken Access Control',
        message: 'React dangerouslySetInnerHTML detected - ensure content is sanitized',
        remediation: 'Sanitize HTML content with DOMPurify before using dangerouslySetInnerHTML',
        cweId: 'CWE-79',
        languages: ['javascript', 'typescript', 'javascriptreact', 'typescriptreact']
    },

    // ===============================
    // OWASP A02: Cryptographic Failures
    // ===============================
    {
        id: 'A02-001',
        pattern: /crypto\.createHash\(['"`]md5['"`]\)/gi,
        severity: 'critical',
        category: 'Weak Cryptography',
        owaspCategory: 'A02: Cryptographic Failures',
        message: 'MD5 is cryptographically broken and vulnerable to collision attacks',
        remediation: 'Use SHA-256, SHA-3, or bcrypt for hashing',
        cweId: 'CWE-327',
        references: ['https://tools.ietf.org/html/rfc6151'],
        languages: ['javascript', 'typescript']
    },
    {
        id: 'A02-002',
        pattern: /crypto\.createHash\(['"`]sha1['"`]\)/gi,
        severity: 'high',
        category: 'Weak Cryptography',
        owaspCategory: 'A02: Cryptographic Failures',
        message: 'SHA-1 is deprecated and vulnerable to collision attacks',
        remediation: 'Use SHA-256, SHA-3, or stronger algorithms',
        cweId: 'CWE-327'
    },
    {
        id: 'A02-003',
        pattern: /crypto\.createCipher\(/gi,
        severity: 'high',
        category: 'Weak Cryptography',
        owaspCategory: 'A02: Cryptographic Failures',
        message: 'crypto.createCipher is deprecated and insecure',
        remediation: 'Use crypto.createCipherGCM() or crypto.createCipherCCM() with proper key derivation',
        cweId: 'CWE-327'
    },
    {
        id: 'A02-004',
        pattern: /Math\.random\(\)/gi,
        severity: 'medium',
        category: 'Weak Random Number Generation',
        owaspCategory: 'A02: Cryptographic Failures',
        message: 'Math.random() is not cryptographically secure',
        remediation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive operations',
        cweId: 'CWE-338'
    },

    // ===============================
    // OWASP A03: Injection
    // ===============================
    {
        id: 'A03-001',
        pattern: /eval\s*\(/gi,
        severity: 'critical',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'eval() enables arbitrary code execution and is extremely dangerous',
        remediation: 'Use JSON.parse() for data or refactor to eliminate dynamic code execution',
        cweId: 'CWE-95',
        references: ['https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#Never_use_eval!'],
        languages: ['javascript', 'typescript']
    },
    {
        id: 'A03-001-PY',
        pattern: /exec\s*\(/gi,
        severity: 'critical',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'exec() enables arbitrary code execution and is extremely dangerous',
        remediation: 'Use ast.literal_eval() for data or refactor to eliminate dynamic code execution',
        cweId: 'CWE-95',
        languages: ['python']
    },
    {
        id: 'A03-002-PY',
        pattern: /eval\s*\(/gi,
        severity: 'critical',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'eval() enables arbitrary code execution and is extremely dangerous',
        remediation: 'Use ast.literal_eval() for safe evaluation of literals',
        cweId: 'CWE-95',
        languages: ['python']
    },
    {
        id: 'A03-002',
        pattern: /new\s+Function\s*\(/gi,
        severity: 'critical',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'Function constructor can execute arbitrary code',
        remediation: 'Refactor to use predefined functions or safer alternatives',
        cweId: 'CWE-95',
        languages: ['javascript', 'typescript']
    },
    {
        id: 'A03-003',
        pattern: /setTimeout\s*\(\s*['"`][^'"`]+['"`]/gi,
        severity: 'high',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'setTimeout with string parameter can execute arbitrary code',
        remediation: 'Use setTimeout with function reference instead of string',
        cweId: 'CWE-95'
    },
    {
        id: 'A03-004',
        pattern: /setInterval\s*\(\s*['"`][^'"`]+['"`]/gi,
        severity: 'high',
        category: 'Code Injection',
        owaspCategory: 'A03: Injection',
        message: 'setInterval with string parameter can execute arbitrary code',
        remediation: 'Use setInterval with function reference instead of string',
        cweId: 'CWE-95'
    },
    {
        id: 'A03-005',
        pattern: /document\.write\s*\(/gi,
        severity: 'medium',
        category: 'XSS Prevention',
        owaspCategory: 'A03: Injection',
        message: 'document.write() can lead to XSS vulnerabilities',
        remediation: 'Use DOM manipulation methods like createElement() and appendChild()',
        cweId: 'CWE-79'
    },
    {
        id: 'A03-006',
        pattern: /\$\{\s*[^}]*\s*\}/g,
        severity: 'medium',
        category: 'Template Injection',
        owaspCategory: 'A03: Injection',
        message: 'Template literal with potential user input - ensure proper escaping',
        remediation: 'Validate and sanitize all user input in template literals',
        cweId: 'CWE-94'
    },

    // ===============================
    // OWASP A04: Insecure Design
    // ===============================
    {
        id: 'A04-001',
        pattern: /if\s*\(\s*(?:password|token|key)\s*==\s*['"`][^'"`]*['"`]\s*\)/gi,
        severity: 'high',
        category: 'Insecure Comparison',
        owaspCategory: 'A04: Insecure Design',
        message: 'Direct string comparison of secrets vulnerable to timing attacks',
        remediation: 'Use crypto.timingSafeEqual() for comparing sensitive values',
        cweId: 'CWE-208'
    },

    // ===============================
    // OWASP A05: Security Misconfiguration
    // ===============================
    {
        id: 'A05-001',
        pattern: /app\.use\(\s*cors\(\s*\)\s*\)/gi,
        severity: 'medium',
        category: 'CORS Misconfiguration',
        owaspCategory: 'A05: Security Misconfiguration',
        message: 'CORS enabled for all origins - potential security risk',
        remediation: 'Configure CORS with specific origins: cors({origin: "https://trusted-domain.com"})',
        cweId: 'CWE-346'
    },

    // ===============================
    // OWASP A06: Vulnerable Components
    // ===============================
    {
        id: 'A06-001',
        pattern: /require\s*\(\s*['"`][^'"`]*['"`]\s*\)/gi,
        severity: 'low',
        category: 'Dependency Management',
        owaspCategory: 'A06: Vulnerable Components',
        message: 'Static require() detected - ensure dependencies are regularly updated',
        remediation: 'Regularly audit dependencies with npm audit and keep them updated',
        cweId: 'CWE-1104'
    },
    {
        id: 'A06-002',
        pattern: /import\s+.*\s+from\s+['"`][^'"`]*['"`]/gi,
        severity: 'low',
        category: 'Dependency Management',
        owaspCategory: 'A06: Vulnerable Components',
        message: 'External dependency import - verify package integrity',
        remediation: 'Use package-lock.json, verify checksums, and audit dependencies regularly',
        cweId: 'CWE-1104'
    },

    // ===============================
    // OWASP A07: Identity and Authentication Failures
    // ===============================
    {
        id: 'A07-001',
        pattern: /(?:password|pwd|pass)\s*[:=]\s*['"`][^'"`]*['"`]/gi,
        severity: 'critical',
        category: 'Hardcoded Credentials',
        owaspCategory: 'A07: Identity and Authentication Failures',
        message: 'Potential hardcoded password detected in source code',
        remediation: 'Use environment variables, secure vaults, or configuration files outside version control',
        cweId: 'CWE-798'
    },
    {
        id: 'A07-002',
        pattern: /(?:api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['"`][^'"`]*['"`]/gi,
        severity: 'critical',
        category: 'Hardcoded Credentials',
        owaspCategory: 'A07: Identity and Authentication Failures',
        message: 'Potential hardcoded API key or access token detected',
        remediation: 'Store API keys in environment variables or secure credential management systems',
        cweId: 'CWE-798'
    },
    {
        id: 'A07-003',
        pattern: /(?:secret|private[_-]?key)\s*[:=]\s*['"`][^'"`]*['"`]/gi,
        severity: 'critical',
        category: 'Hardcoded Credentials',
        owaspCategory: 'A07: Identity and Authentication Failures',
        message: 'Potential hardcoded secret or private key detected',
        remediation: 'Use secure key management services and never commit secrets to version control',
        cweId: 'CWE-798'
    },
    {
        id: 'A07-004',
        pattern: /jwt\.sign\([^,)]*,\s*['"`][^'"`]*['"`]\s*\)/gi,
        severity: 'medium',
        category: 'JWT Security',
        owaspCategory: 'A07: Identity and Authentication Failures',
        message: 'JWT signed with hardcoded secret',
        remediation: 'Use environment variables for JWT secrets and consider key rotation',
        cweId: 'CWE-798'
    },

    // ===============================
    // OWASP A08: Software and Data Integrity Failures
    // ===============================
    {
        id: 'A08-001',
        pattern: /JSON\.parse\([^)]*\)/gi,
        severity: 'medium',
        category: 'Data Integrity',
        owaspCategory: 'A08: Software and Data Integrity Failures',
        message: 'JSON.parse() without error handling can cause application crashes',
        remediation: 'Wrap JSON.parse() in try-catch blocks and validate parsed data',
        cweId: 'CWE-20'
    },
    {
        id: 'A08-002',
        pattern: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*[^)]*\)/gi,
        severity: 'low',
        category: 'Prototype Pollution',
        owaspCategory: 'A08: Software and Data Integrity Failures',
        message: 'Object.assign may be vulnerable to prototype pollution',
        remediation: 'Validate object properties or use Object.create(null) as target',
        cweId: 'CWE-1321'
    },

    // ===============================
    // OWASP A09: Security Logging Failures
    // ===============================
    {
        id: 'A09-001',
        pattern: /console\.log\s*\([^)]*(?:password|token|key|secret|auth)[^)]*\)/gi,
        severity: 'high',
        category: 'Information Disclosure',
        owaspCategory: 'A09: Security Logging Failures',
        message: 'Potential logging of sensitive information detected',
        remediation: 'Remove or sanitize sensitive data from logs, use structured logging',
        cweId: 'CWE-532'
    },
    {
        id: 'A09-002',
        pattern: /console\.(?:error|warn|info)\s*\([^)]*(?:password|token|key|secret)[^)]*\)/gi,
        severity: 'high',
        category: 'Information Disclosure',
        owaspCategory: 'A09: Security Logging Failures',
        message: 'Potential logging of sensitive information in error/warning messages',
        remediation: 'Sanitize error messages and avoid exposing sensitive data in logs',
        cweId: 'CWE-532'
    },

    // ===============================
    // OWASP A10: Server-Side Request Forgery (SSRF)
    // ===============================
    {
        id: 'A10-001',
        pattern: /(?:fetch|axios|http\.get|https\.get)\s*\(\s*[^'"`][^)]*\)/gi,
        severity: 'medium',
        category: 'SSRF Prevention',
        owaspCategory: 'A10: Server-Side Request Forgery',
        message: 'HTTP request with potentially user-controlled URL',
        remediation: 'Validate and allowlist URLs, avoid direct user input in HTTP requests',
        cweId: 'CWE-918'
    },

    // ===============================
    // CISA Secure by Design Principles
    // ===============================
    {
        id: 'CISA-001',
        pattern: /parseInt\s*\([^,)]+\s*\)/gi,
        severity: 'medium',
        category: 'Input Validation',
        cisaCategory: 'Secure by Design: Input Validation',
        message: 'parseInt() without radix parameter can cause unexpected behavior',
        remediation: 'Always specify radix parameter: parseInt(value, 10) or parseInt(value, 16)',
        cweId: 'CWE-20'
    },
    {
        id: 'CISA-002',
        pattern: /Buffer\.alloc\s*\(\s*[^,)]+\s*\)/gi,
        severity: 'low',
        category: 'Memory Safety',
        cisaCategory: 'Secure by Design: Memory Safety',
        message: 'Buffer allocation - ensure proper size validation',
        remediation: 'Validate buffer size and consider using Buffer.allocUnsafe() only when necessary',
        cweId: 'CWE-119'
    },
    {
        id: 'CISA-003',
        pattern: /new\s+Buffer\s*\(/gi,
        severity: 'high',
        category: 'Memory Safety',
        cisaCategory: 'Secure by Design: Memory Safety',
        message: 'new Buffer() constructor is deprecated and potentially unsafe',
        remediation: 'Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe() instead',
        cweId: 'CWE-119'
    },
    {
        id: 'CISA-004',
        pattern: /process\.env\.[A-Z_]+/gi,
        severity: 'low',
        category: 'Environment Security',
        cisaCategory: 'Secure by Design: Default Security',
        message: 'Environment variable access detected',
        remediation: 'Validate environment variables and provide secure defaults',
        cweId: 'CWE-20'
    },
    {
        id: 'CISA-005',
        pattern: /(?:fs\.readFile|fs\.writeFile|fs\.appendFile)\s*\([^,)]*[^'"`][^,)]*,/gi,
        severity: 'medium',
        category: 'Path Traversal',
        cisaCategory: 'Secure by Design: Input Validation',
        message: 'File system operation with potentially unsafe path',
        remediation: 'Validate file paths, use path.resolve() and ensure paths are within allowed directories',
        cweId: 'CWE-22'
    },
    {
        id: 'CISA-006',
        pattern: /child_process\.(?:exec|spawn|execSync|spawnSync)\s*\(/gi,
        severity: 'high',
        category: 'Command Injection',
        cisaCategory: 'Secure by Design: Input Validation',
        message: 'Child process execution detected - potential command injection risk',
        remediation: 'Validate all inputs, use parameterized commands, avoid shell=true',
        cweId: 'CWE-78'
    },

    // ===============================
    // Additional Security Patterns
    // ===============================
    {
        id: 'SEC-001',
        pattern: /<!--[\s\S]*?-->/gi,
        severity: 'low',
        category: 'Information Disclosure',
        message: 'HTML comment detected - may contain sensitive information',
        remediation: 'Review comments for sensitive data before production deployment',
        cweId: 'CWE-200'
    },
    {
        id: 'SEC-002',
        pattern: /debugger\s*;/gi,
        severity: 'medium',
        category: 'Debug Information',
        message: 'Debugger statement found in code',
        remediation: 'Remove debugger statements before production deployment',
        cweId: 'CWE-489'
    },
    {
        id: 'SEC-003',
        pattern: /alert\s*\(/gi,
        severity: 'low',
        category: 'User Experience Security',
        message: 'Alert dialog detected - can be used for social engineering',
        remediation: 'Use proper UI notifications instead of alert() dialogs',
        cweId: 'CWE-1021'
    },
    {
        id: 'SEC-004',
        pattern: /confirm\s*\(/gi,
        severity: 'low',
        category: 'User Experience Security',
        message: 'Confirm dialog detected - can be used for social engineering',
        remediation: 'Use proper UI confirmation dialogs instead of confirm()',
        cweId: 'CWE-1021'
    },
    {
        id: 'SEC-005',
        pattern: /window\.open\s*\(/gi,
        severity: 'medium',
        category: 'Window Security',
        message: 'window.open() can be used for popup-based attacks',
        remediation: 'Validate URLs and use noopener, noreferrer attributes for external links',
        cweId: 'CWE-601'
    },
    {
        id: 'SEC-006',
        pattern: /(?:btoa|atob)\s*\(/gi,
        severity: 'low',
        category: 'Encoding Security',
        message: 'Base64 encoding/decoding detected - not suitable for security',
        remediation: 'Base64 is encoding, not encryption. Use proper encryption for sensitive data',
        cweId: 'CWE-327'
    },
    {
        id: 'SEC-007',
        pattern: /RegExp\s*\(\s*[^,)]*,\s*['"`].*i.*['"`]\s*\)/gi,
        severity: 'low',
        category: 'Regular Expression Security',
        message: 'Case-insensitive regex - ensure this is intentional for security contexts',
        remediation: 'Review regex flags for security-sensitive pattern matching',
        cweId: 'CWE-1333'
    },
    {
        id: 'SEC-008',
        pattern: /(?:localStorage|sessionStorage)\.setItem\s*\([^,)]*(?:password|token|key|secret)[^,)]*,/gi,
        severity: 'high',
        category: 'Client-Side Storage Security',
        message: 'Storing sensitive data in browser storage is insecure',
        remediation: 'Use secure, httpOnly cookies or server-side sessions for sensitive data',
        cweId: 'CWE-922'
    },

    // ===============================
    // OWASP GenAI Security - LLM01: Prompt Injection
    // ===============================
    {
        id: 'LLM01-001',
        pattern: /(?:openai|anthropic|azure\.openai|cohere|huggingface)\.(?:chat\.)?completions?\.create\s*\(\s*\{[^}]*(?:prompt|messages?)\s*:\s*[^'"`][^}]*\}/gi,
        severity: 'critical',
        category: 'GenAI Prompt Injection',
        owaspCategory: 'LLM01: Prompt Injection',
        message: 'Potential prompt injection vulnerability - user input directly used in LLM prompt',
        remediation: 'Sanitize user input, use input validation, implement prompt templates with parameter binding',
        cweId: 'CWE-74',
        references: ['https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM01-002',
        pattern: /f["'].*\{[^}]*\}.*["']\.format\s*\(/gi,
        severity: 'high',
        category: 'GenAI Prompt Injection',
        owaspCategory: 'LLM01: Prompt Injection',
        message: 'Python f-string or format() with user input may enable prompt injection',
        remediation: 'Use template systems with input validation and sanitization',
        cweId: 'CWE-74',
        languages: ['python']
    },
    {
        id: 'LLM01-003',
        pattern: /`[^`]*\$\{[^}]*\}[^`]*`/gi,
        severity: 'medium',
        category: 'GenAI Prompt Injection',
        owaspCategory: 'LLM01: Prompt Injection',
        message: 'Template literal with variables - ensure user input is sanitized for LLM prompts',
        remediation: 'Validate and sanitize user input before including in LLM prompts',
        cweId: 'CWE-74',
        languages: ['javascript', 'typescript']
    },

    // ===============================
    // OWASP GenAI Security - LLM02: Insecure Output Handling
    // ===============================
    {
        id: 'LLM02-001',
        pattern: /(?:response|completion|result)\.(?:choices\[0\]\.)?(?:message\.content|text)\s*(?!\.(?:strip|trim|replace|filter|sanitize))/gi,
        severity: 'high',
        category: 'GenAI Insecure Output Handling',
        owaspCategory: 'LLM02: Insecure Output Handling',
        message: 'LLM output used without validation - potential code injection or XSS',
        remediation: 'Validate, sanitize, and escape LLM outputs before use in application logic',
        cweId: 'CWE-20',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM02-002',
        pattern: /exec\s*\(\s*(?:response|completion|result|llm_output)/gi,
        severity: 'critical',
        category: 'GenAI Code Injection',
        owaspCategory: 'LLM02: Insecure Output Handling',
        message: 'Executing LLM output as code is extremely dangerous',
        remediation: 'Never execute LLM output directly. Parse and validate any code suggestions',
        cweId: 'CWE-95',
        languages: ['python', 'javascript', 'typescript']
    },
    {
        id: 'LLM02-003',
        pattern: /eval\s*\(\s*(?:response|completion|result|llm_output)/gi,
        severity: 'critical',
        category: 'GenAI Code Injection',
        owaspCategory: 'LLM02: Insecure Output Handling',
        message: 'Evaluating LLM output as code enables arbitrary code execution',
        remediation: 'Parse and validate LLM outputs instead of direct evaluation',
        cweId: 'CWE-95',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM03: Training Data Poisoning
    // ===============================
    {
        id: 'LLM03-001',
        pattern: /(?:fine_tune|finetune|train_model)\s*\([^)]*(?:user_data|external_data|untrusted_data)/gi,
        severity: 'high',
        category: 'GenAI Training Data Security',
        owaspCategory: 'LLM03: Training Data Poisoning',
        message: 'Training with external/user data without validation risks model poisoning',
        remediation: 'Validate, sanitize, and audit training data sources. Implement data provenance tracking',
        cweId: 'CWE-20',
        languages: ['python', 'javascript', 'typescript']
    },

    // ===============================
    // OWASP GenAI Security - LLM04: Model Denial of Service
    // ===============================
    {
        id: 'LLM04-001',
        pattern: /(?:max_tokens|max_length)\s*:\s*(?:[1-9]\d{4,}|\d{6,})/gi,
        severity: 'medium',
        category: 'GenAI Resource Management',
        owaspCategory: 'LLM04: Model Denial of Service',
        message: 'High token limit may cause resource exhaustion and increased costs',
        remediation: 'Implement reasonable token limits and rate limiting for LLM requests',
        cweId: 'CWE-400',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM04-002',
        pattern: /while\s*\(\s*true\s*\)\s*\{[^}]*(?:openai|anthropic|llm|model)\.(?:chat\.)?(?:complete|generate)/gi,
        severity: 'high',
        category: 'GenAI Resource Management',
        owaspCategory: 'LLM04: Model Denial of Service',
        message: 'Infinite loop with LLM calls can cause resource exhaustion',
        remediation: 'Implement proper loop termination conditions and rate limiting',
        cweId: 'CWE-400',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM06: Sensitive Information Disclosure
    // ===============================
    {
        id: 'LLM06-001',
        pattern: /(?:prompt|messages?)\s*[:=]\s*[^'"`]*(?:password|api_key|secret|token|credit_card|ssn|personal)/gi,
        severity: 'critical',
        category: 'GenAI Information Disclosure',
        owaspCategory: 'LLM06: Sensitive Information Disclosure',
        message: 'Sensitive information detected in LLM prompt - may be exposed in logs or training',
        remediation: 'Remove sensitive data from prompts, use data anonymization or tokenization',
        cweId: 'CWE-200',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM06-002',
        pattern: /(?:system_prompt|system_message)\s*[:=]\s*[^'"`]*(?:internal|confidential|proprietary|secret)/gi,
        severity: 'high',
        category: 'GenAI Information Disclosure',
        owaspCategory: 'LLM06: Sensitive Information Disclosure',
        message: 'System prompt contains confidential information that may be extracted',
        remediation: 'Avoid including sensitive system information in prompts',
        cweId: 'CWE-200',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM07: Insecure Plugin Design
    // ===============================
    {
        id: 'LLM07-001',
        pattern: /tools?\s*[:=]\s*\[[^]]*\{[^}]*(?:function|name)\s*[:=]\s*[^'"`][^}]*\}/gi,
        severity: 'high',
        category: 'GenAI Plugin Security',
        owaspCategory: 'LLM07: Insecure Plugin Design',
        message: 'LLM tool/plugin with dynamic function name - potential code injection risk',
        remediation: 'Use allowlisted function names and validate all plugin inputs',
        cweId: 'CWE-74',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM07-002',
        pattern: /function_call\s*[:=]\s*\{[^}]*name\s*[:=]\s*(?:response|llm_output|user_input)/gi,
        severity: 'critical',
        category: 'GenAI Plugin Security',
        owaspCategory: 'LLM07: Insecure Plugin Design',
        message: 'LLM function call name controlled by untrusted input',
        remediation: 'Validate function names against allowlist before execution',
        cweId: 'CWE-74',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM08: Excessive Agency
    // ===============================
    {
        id: 'LLM08-001',
        pattern: /(?:agent|autonomous).*?(?:execute|run|perform).*?(?:without|skip).*?(?:approval|confirmation|validation)/gi,
        severity: 'high',
        category: 'GenAI Excessive Agency',
        owaspCategory: 'LLM08: Excessive Agency',
        message: 'AI agent with excessive autonomy - lacks human oversight',
        remediation: 'Implement human-in-the-loop controls and approval workflows for critical actions',
        cweId: 'CWE-862',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM08-002',
        pattern: /(?:auto_approve|skip_confirmation|bypass_validation)\s*[:=]\s*true/gi,
        severity: 'medium',
        category: 'GenAI Excessive Agency',
        owaspCategory: 'LLM08: Excessive Agency',
        message: 'AI system configured to bypass human approval mechanisms',
        remediation: 'Require human approval for sensitive operations',
        cweId: 'CWE-862',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM09: Overreliance
    // ===============================
    {
        id: 'LLM09-001',
        pattern: /if\s*\(\s*(?:llm_response|ai_output|model_result)\s*\)\s*\{[^}]*(?:critical|important|security|financial)/gi,
        severity: 'medium',
        category: 'GenAI Overreliance',
        owaspCategory: 'LLM09: Overreliance',
        message: 'Critical decision based solely on LLM output without validation',
        remediation: 'Implement validation and human oversight for critical decisions',
        cweId: 'CWE-20',
        languages: ['javascript', 'typescript', 'python']
    },
    {
        id: 'LLM09-002',
        pattern: /(?:trust|accept|assume).*?(?:llm|ai|model).*?(?:always|completely|without.*?question)/gi,
        severity: 'low',
        category: 'GenAI Overreliance',
        owaspCategory: 'LLM09: Overreliance',
        message: 'Code comment suggests overreliance on AI output',
        remediation: 'Implement proper validation and error handling for AI outputs',
        cweId: 'CWE-20',
        languages: ['javascript', 'typescript', 'python']
    },

    // ===============================
    // OWASP GenAI Security - LLM10: Model Theft
    // ===============================
    {
        id: 'LLM10-001',
        pattern: /(?:model\.save|torch\.save|pickle\.dump)\s*\([^)]*(?:public|world_readable|777)/gi,
        severity: 'critical',
        category: 'GenAI Model Security',
        owaspCategory: 'LLM10: Model Theft',
        message: 'Model saved with overly permissive access permissions',
        remediation: 'Use restrictive file permissions and secure storage for model files',
        cweId: 'CWE-732',
        languages: ['python']
    },
    {
        id: 'LLM10-002',
        pattern: /(?:api_endpoint|model_url)\s*[:=]\s*['"`]https?:\/\/[^'"`]*['"`].*?(?:public|open|unrestricted)/gi,
        severity: 'high',
        category: 'GenAI Model Security',
        owaspCategory: 'LLM10: Model Theft',
        message: 'Model endpoint exposed without proper access controls',
        remediation: 'Implement authentication, authorization, and rate limiting for model endpoints',
        cweId: 'CWE-306',
        languages: ['javascript', 'typescript', 'python']
    }
] as const;

/**
 * Security configuration for different file types
 */
export const FILE_TYPE_RULES: Record<string, readonly string[]> = {
    javascript: ['A01-001', 'A02-001', 'A02-002', 'A03-001', 'A03-002', 'A07-001', 'A09-001', 'CISA-001', 'LLM01-001', 'LLM01-003', 'LLM02-001', 'LLM02-002', 'LLM02-003', 'LLM04-001', 'LLM04-002', 'LLM06-001', 'LLM07-001', 'LLM07-002', 'LLM08-001', 'LLM08-002', 'LLM09-001', 'LLM09-002', 'LLM10-002'],
    typescript: ['A01-001', 'A02-001', 'A02-002', 'A03-001', 'A03-002', 'A07-001', 'A09-001', 'CISA-001', 'LLM01-001', 'LLM01-003', 'LLM02-001', 'LLM02-002', 'LLM02-003', 'LLM04-001', 'LLM04-002', 'LLM06-001', 'LLM07-001', 'LLM07-002', 'LLM08-001', 'LLM08-002', 'LLM09-001', 'LLM09-002', 'LLM10-002'],
    python: ['A03-001', 'A07-001', 'A09-001', 'CISA-006', 'LLM01-001', 'LLM01-002', 'LLM02-001', 'LLM02-002', 'LLM02-003', 'LLM03-001', 'LLM04-001', 'LLM04-002', 'LLM06-001', 'LLM07-001', 'LLM07-002', 'LLM08-001', 'LLM08-002', 'LLM09-001', 'LLM09-002', 'LLM10-001', 'LLM10-002'],
    java: ['A07-001', 'A09-001', 'A08-001'],
    csharp: ['A07-001', 'A09-001'],
    php: ['A03-001', 'A07-001', 'A09-001'],
    ruby: ['A03-001', 'A07-001', 'A09-001'],
    go: ['A07-001', 'A09-001'],
    cpp: ['CISA-002', 'CISA-003'],
    c: ['CISA-002', 'CISA-003']
} as const;