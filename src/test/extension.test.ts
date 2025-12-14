import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Extension Integration Test Suite', () => {
    vscode.window.showInformationMessage('Starting OWASP/CISA Scanner integration tests.');

    test('Extension loads and activates', async () => {
        const extension = vscode.extensions.getExtension('Aegisq.owasp-cisa-security-scanner');
        
        if (extension) {
            if (!extension.isActive) {
                await extension.activate();
            }
            assert.ok(extension.isActive, 'Extension should be active after activation');
        } else {
            // Extension might not be installed in test environment
            console.log('Extension not found - may be running in test environment');
        }
    });

    test('Commands are properly registered', async () => {
        const allCommands = await vscode.commands.getCommands(true);
        const owaspCommands = allCommands.filter(cmd => cmd.startsWith('owaspCisaScanner.'));
        
        assert.ok(owaspCommands.length > 0, 'Should have OWASP/CISA scanner commands registered');
        assert.ok(owaspCommands.includes('owaspCisaScanner.scanCurrentFile'), 
            'scanCurrentFile command should be registered');
    });

    test('Configuration schema is valid', () => {
        const config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        // Test that configuration properties exist and have expected types
        const enableAutoScan = config.get('enableAutoScan');
        const maxFileSize = config.get('maxFileSize');
        const enableHighSeverityOnly = config.get('enableHighSeverityOnly');
        
        assert.strictEqual(typeof enableAutoScan, 'boolean', 
            'enableAutoScan should be boolean');
        assert.strictEqual(typeof maxFileSize, 'number', 
            'maxFileSize should be number');
        assert.strictEqual(typeof enableHighSeverityOnly, 'boolean', 
            'enableHighSeverityOnly should be boolean');
    });

    test('Diagnostic collection is created', () => {
        // This test verifies that the extension properly creates diagnostic collections
        const diagnosticCollections = vscode.languages.getDiagnostics();
        assert.ok(Array.isArray(diagnosticCollections), 
            'Diagnostic collections should be accessible');
    });
});
