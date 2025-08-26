import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { SECURITY_RULES } from './securityRules';

// Security: Use allowlist of supported file extensions to prevent path traversal
const SUPPORTED_EXTENSIONS = new Set(['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.cs', '.php', '.rb', '.go', '.cpp', '.c', '.h', '.hpp']);

// Security: Maximum file size to prevent DoS attacks (5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

interface SecurityVulnerability {
    readonly line: number;
    readonly column: number;
    readonly severity: 'critical' | 'high' | 'medium' | 'low';
    readonly category: string;
    readonly message: string;
    readonly owaspCategory?: string;
    readonly cisaCategory?: string;
    readonly remediation: string;
}

class SecureCodeScanner {
    private readonly diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('owaspCisaScanner');
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
            if (stats.size > MAX_FILE_SIZE) {
                vscode.window.showWarningMessage(`File ${filePath} is too large to scan (${stats.size} bytes, max ${MAX_FILE_SIZE})`);
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

    public async scanDocument(document: vscode.TextDocument): Promise<void> {
        try {
            const content = document.getText();
            const vulnerabilities = this.findVulnerabilities(content);
            
            const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
                const range = new vscode.Range(
                    new vscode.Position(Math.max(0, vuln.line - 1), Math.max(0, vuln.column)),
                    new vscode.Position(Math.max(0, vuln.line - 1), Math.max(0, vuln.column + 10))
                );

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `${vuln.message} - ${vuln.remediation}`,
                    this.mapSeverityToDiagnostic(vuln.severity)
                );

                diagnostic.source = `OWASP/CISA Scanner - ${vuln.category}`;
                diagnostic.code = vuln.owaspCategory || vuln.cisaCategory || vuln.category;

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
                if (criticalCount > 0) summary += `${criticalCount} critical, `;
                if (highCount > 0) summary += `${highCount} high, `;
                if (mediumCount > 0) summary += `${mediumCount} medium, `;
                if (lowCount > 0) summary += `${lowCount} low`;
                
                vscode.window.showWarningMessage(summary.replace(/, $/, ''));
            }
            
        } catch (error) {
            console.error('Document scan error:', error);
            vscode.window.showErrorMessage('Security scan failed');
        }
    }

    private findVulnerabilities(content: string): SecurityVulnerability[] {
        const vulnerabilities: SecurityVulnerability[] = [];
        const lines = content.split('\n');

        SECURITY_RULES.forEach(rule => {
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
                        remediation: rule.remediation
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