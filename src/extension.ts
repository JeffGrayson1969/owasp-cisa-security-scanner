import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { SECURITY_RULES } from './securityRules';

// Security: Use allowlist of supported file extensions to prevent path traversal
const SUPPORTED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.cs', '.php', '.rb', '.go', '.cpp', '.c', '.h', '.hpp']);

// Security: Maximum file size to prevent DoS attacks (5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Default exclude patterns for common third-party directories
const DEFAULT_EXCLUDE_PATTERNS = [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
    '**/out/**',
    '**/target/**',
    '**/.git/**',
    '**/vendor/**',
    '**/venv/**',
    '**/__pycache__/**',
    '**/bin/**',
    '**/obj/**'
];

interface SecurityVulnerability {
    readonly line: number;
    readonly column: number;
    readonly severity: 'critical' | 'high' | 'medium' | 'low';
    readonly category: string;
    readonly message: string;
    readonly owaspCategory?: string;
    readonly cisaCategory?: string;
    readonly remediation: string;
    readonly cweId?: string;
    readonly references?: readonly string[];
}

class SecureCodeScanner {
    private readonly diagnosticCollection: vscode.DiagnosticCollection;
    private config: vscode.WorkspaceConfiguration;
    private readonly scanCache = new Map<string, { hash: string, vulnerabilities: SecurityVulnerability[] }>();
    private readonly ruleCache = new Map<string, typeof SECURITY_RULES>();

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('owaspCisaScanner');
        this.config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        // Listen for configuration changes
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('owaspCisaScanner')) {
                this.config = vscode.workspace.getConfiguration('owaspCisaScanner');
                // Clear caches when configuration changes
                this.scanCache.clear();
                this.ruleCache.clear();
            }
        });
    }

    /**
     * Security: Validates file path and size before processing
     */
    private async validateFile(filePath: string): Promise<boolean> {
        try {
            // Security: Check file extension allowlist
            const ext = path.extname(filePath).toLowerCase();
            if (!SUPPORTED_EXTENSIONS.has(ext)) {
                return false;
            }

            // Security: Check file size to prevent DoS
            const stats = await fs.promises.stat(filePath);
            const maxFileSize = this.config.get<number>('maxFileSize', MAX_FILE_SIZE);
            if (stats.size > maxFileSize) {
                vscode.window.showWarningMessage(`File ${filePath} is too large to scan (${stats.size} bytes, max ${maxFileSize})`);
                return false;
            }

            // Security: Ensure file is within workspace
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders) {
                return false;
            }

            const isInWorkspace = workspaceFolders.some(folder => 
                filePath.startsWith(path.resolve(folder.uri.fsPath))
            );

            if (!isInWorkspace) {
                vscode.window.showErrorMessage('File is outside workspace - security scan blocked');
                return false;
            }

            return true;
        } catch (error) {
            console.error('File validation error:', error);
            return false;
        }
    }

    /**
     * Check if file should be excluded based on patterns
     */
    private shouldExcludeFile(filePath: string): boolean {
        const relativePath = vscode.workspace.asRelativePath(filePath);
        
        // Check default exclude patterns
        for (const pattern of DEFAULT_EXCLUDE_PATTERNS) {
            if (this.matchesPattern(relativePath, pattern)) {
                return true;
            }
        }
        
        // Check custom exclude patterns from configuration
        const customPatterns = this.config.get<string[]>('excludePatterns', []);
        for (const pattern of customPatterns) {
            if (this.matchesPattern(relativePath, pattern)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Simple glob pattern matching
     */
    private matchesPattern(filePath: string, pattern: string): boolean {
        // Convert glob pattern to regex
        const regexPattern = pattern
            .replace(/\*\*/g, '.*')
            .replace(/\*/g, '[^/]*')
            .replace(/\?/g, '[^/]');
        
        const regex = new RegExp('^' + regexPattern + '$');
        return regex.test(filePath);
    }

    public async scanDocument(document: vscode.TextDocument): Promise<void> {
        try {
            // Check if file should be excluded
            if (this.shouldExcludeFile(document.uri.fsPath)) {
                this.diagnosticCollection.delete(document.uri);
                return;
            }

            const content = document.getText();
            
            // Check cache first
            const contentHash = this.hashContent(content);
            const cached = this.scanCache.get(document.uri.toString());
            
            let vulnerabilities: SecurityVulnerability[];
            if (cached && cached.hash === contentHash) {
                vulnerabilities = cached.vulnerabilities;
            } else {
                vulnerabilities = this.findVulnerabilities(content, document.languageId);
                // Cache the results
                this.scanCache.set(document.uri.toString(), {
                    hash: contentHash,
                    vulnerabilities
                });
                
                // Periodic cache cleanup
                this.cleanupCache();
            }
            
            const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
                const range = this.createDiagnosticRange(content, vuln);

                const diagnostic = new vscode.Diagnostic(
                    range,
                    vuln.message,
                    this.mapSeverityToDiagnostic(vuln.severity)
                );

                diagnostic.source = `OWASP/CISA Scanner - ${vuln.category}`;
                diagnostic.code = {
                    value: vuln.owaspCategory || vuln.cisaCategory || vuln.category,
                    target: vuln.cweId ? vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html`) : vscode.Uri.parse('https://owasp.org/www-project-top-ten/')
                };
                
                // Add related information for remediation
                diagnostic.relatedInformation = [
                    new vscode.DiagnosticRelatedInformation(
                        new vscode.Location(document.uri, range),
                        `💡 Remediation: ${vuln.remediation}`
                    )
                ];

                // Add references if available
                if (vuln.references && vuln.references.length > 0) {
                    vuln.references.forEach((ref: string) => {
                        diagnostic.relatedInformation!.push(
                            new vscode.DiagnosticRelatedInformation(
                                new vscode.Location(document.uri, range),
                                `📚 Reference: ${ref}`
                            )
                        );
                    });
                }

                return diagnostic;
            });

            this.diagnosticCollection.set(document.uri, diagnostics);
            
            // Show summary if vulnerabilities found
            if (vulnerabilities.length > 0) {
                const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
                const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
                const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
                const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;
                
                let summary = `Security scan found ${vulnerabilities.length} issue(s): `;
                if (criticalCount > 0) {summary += `${criticalCount} critical, `;}
                if (highCount > 0) {summary += `${highCount} high, `;}
                if (mediumCount > 0) {summary += `${mediumCount} medium, `;}
                if (lowCount > 0) {summary += `${lowCount} low`;}
                
                vscode.window.showWarningMessage(summary.replace(/, $/, ''));
            }
            
        } catch (error) {
            console.error('Document scan error:', error);
            vscode.window.showErrorMessage('Security scan failed');
        }
    }

    private findVulnerabilities(content: string, languageId?: string): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];
        const lines = content.split('\n');
        const enableHighSeverityOnly = this.config.get<boolean>('enableHighSeverityOnly', false);

        // Get language-specific rules
        const applicableRules = this.getApplicableRules(languageId);

        applicableRules.forEach(rule => {
            // Apply severity filtering if enabled
            if (enableHighSeverityOnly && !['critical', 'high'].includes(rule.severity)) {
                return;
            }
            lines.forEach((line, lineIndex) => {
                let match;
                // Security: Reset regex lastIndex to prevent infinite loops
                rule.pattern.lastIndex = 0;
                
                while ((match = rule.pattern.exec(line)) !== null) {
                    vulnerabilities.push({
                        line: lineIndex + 1,
                        column: match.index,
                        severity: rule.severity,
                        category: rule.category,
                        message: rule.message,
                        owaspCategory: rule.owaspCategory,
                        cisaCategory: rule.cisaCategory,
                        remediation: rule.remediation,
                        cweId: rule.cweId,
                        references: rule.references
                    });

                    // Security: Prevent infinite loops with global regex
                    if (!rule.pattern.global) {
                        break;
                    }
                }
            });
        });

        return vulnerabilities;
    }

    /**
     * Create a more accurate diagnostic range based on the actual match
     */
    private createDiagnosticRange(content: string, vuln: SecurityVulnerability): vscode.Range {
        const lines = content.split('\n');
        const line = lines[vuln.line - 1];
        
        if (!line) {
            return new vscode.Range(
                new vscode.Position(Math.max(0, vuln.line - 1), 0),
                new vscode.Position(Math.max(0, vuln.line - 1), 1)
            );
        }

        // Try to find the actual length of the problematic code
        let endColumn = vuln.column + 10; // Default fallback
        
        // For common patterns, try to find the actual end
        const commonPatterns = [
            /eval\s*\([^)]*\)/gi,
            /innerHTML\s*=/gi,
            /crypto\.createHash\s*\([^)]*\)/gi,
            /Math\.random\s*\(\)/gi,
            /exec\s*\([^)]*\)/gi
        ];
        
        for (const pattern of commonPatterns) {
            pattern.lastIndex = 0;
            const match = pattern.exec(line);
            if (match && match.index === vuln.column) {
                endColumn = vuln.column + match[0].length;
                break;
            }
        }
        
        return new vscode.Range(
            new vscode.Position(Math.max(0, vuln.line - 1), Math.max(0, vuln.column)),
            new vscode.Position(Math.max(0, vuln.line - 1), Math.min(line.length, endColumn))
        );
    }

    /**
     * Simple hash function for content caching
     */
    private hashContent(content: string): string {
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
            const char = content.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString();
    }

    /**
     * Get security rules applicable to the current language (with caching)
     */
    private getApplicableRules(languageId?: string): typeof SECURITY_RULES {
        if (!languageId) {
            return SECURITY_RULES;
        }

        // Check cache first
        const cached = this.ruleCache.get(languageId);
        if (cached) {
            return cached;
        }

        // Filter rules for this language
        const applicableRules = SECURITY_RULES.filter(rule => {
            // If rule has no language restrictions, apply to all languages
            if (!rule.languages || rule.languages.length === 0) {
                return true;
            }
            
            // Check if current language is in rule's target languages
            return rule.languages.includes(languageId);
        });

        // Cache the filtered rules
        this.ruleCache.set(languageId, applicableRules);
        return applicableRules;
    }

    private mapSeverityToDiagnostic(severity: string): vscode.DiagnosticSeverity {
        switch (severity) {
            case 'critical': return vscode.DiagnosticSeverity.Error;
            case 'high': return vscode.DiagnosticSeverity.Error;
            case 'medium': return vscode.DiagnosticSeverity.Warning;
            case 'low': return vscode.DiagnosticSeverity.Information;
            default: return vscode.DiagnosticSeverity.Hint;
        }
    }

    public dispose(): void {
        this.diagnosticCollection.dispose();
        this.scanCache.clear();
        this.ruleCache.clear();
    }

    /**
     * Clean up old cache entries to prevent memory leaks
     */
    private cleanupCache(): void {
        if (this.scanCache.size > 100) { // Keep cache size reasonable
            // Remove oldest entries (simple LRU approximation)
            const entries = Array.from(this.scanCache.entries());
            const toRemove = entries.slice(0, 50);
            toRemove.forEach(([key]) => this.scanCache.delete(key));
        }
    }
}

export function activate(context: vscode.ExtensionContext): void {
    console.log('OWASP/CISA Scanner: Starting activation...');
    
    try {
        const scanner = new SecureCodeScanner();

        // Register commands with proper error handling
        const scanCommand = vscode.commands.registerCommand('owaspCisaScanner.scanCurrentFile', async () => {
            try {
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showInformationMessage('No active editor found');
                    return;
                }

                await scanner.scanDocument(editor.document);
                vscode.window.showInformationMessage('Security scan completed');
            } catch (error) {
                console.error('Scan command error:', error);
                vscode.window.showErrorMessage('Security scan failed');
            }
        });

        // Auto-scan on file save with debouncing
        let scanTimeout: NodeJS.Timeout | undefined;
        const autoScanHandler = vscode.workspace.onDidSaveTextDocument(async (document) => {
            try {
                // Check if auto-scan is enabled
                const config = vscode.workspace.getConfiguration('owaspCisaScanner');
                if (!config.get<boolean>('enableAutoScan', true)) {
                    return;
                }

                // Security: Clear existing timeout to prevent spam
                if (scanTimeout) {
                    clearTimeout(scanTimeout);
                }

                // Security: Debounce to prevent excessive scanning
                scanTimeout = setTimeout(async () => {
                    await scanner.scanDocument(document);
                }, 500);
            } catch (error) {
                console.error('Auto-scan error:', error);
            }
        });

        // Auto-scan on file open
        const openHandler = vscode.workspace.onDidOpenTextDocument(async (document) => {
            try {
                await scanner.scanDocument(document);
            } catch (error) {
                console.error('Open scan error:', error);
            }
        });

        context.subscriptions.push(scanCommand, autoScanHandler, openHandler, scanner);
        
        console.log('OWASP/CISA Scanner: Successfully activated');
        vscode.window.showInformationMessage('OWASP/CISA Security Scanner activated - Ready to scan for vulnerabilities!');
        
    } catch (error) {
        console.error('Extension activation error:', error);
        vscode.window.showErrorMessage('Failed to activate OWASP/CISA Security Scanner: ' + error);
    }
}

export function deactivate(): void {
    console.log('OWASP/CISA Scanner: Deactivated');
}