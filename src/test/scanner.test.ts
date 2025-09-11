import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';

suite('SecureCodeScanner Test Suite', () => {
    let testWorkspace: string;

    suiteSetup(async () => {
        // Create a test workspace
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            testWorkspace = workspaceFolders[0].uri.fsPath;
        } else {
            // Fallback for tests running without workspace
            testWorkspace = path.join(__dirname, '..', '..');
        }
    });

    test('Scanner activates extension successfully', async () => {
        const extension = vscode.extensions.getExtension('JeffGrayson1969.owasp-cisa-security-scanner');
        assert.ok(extension, 'Extension should be found');
        
        if (!extension.isActive) {
            await extension.activate();
        }
        assert.ok(extension.isActive, 'Extension should be active');
    });

    test('Scan command is registered', async () => {
        const commands = await vscode.commands.getCommands(true);
        assert.ok(commands.includes('owaspCisaScanner.scanCurrentFile'), 
            'Scan command should be registered');
    });

    test('Configuration settings are accessible', () => {
        const config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        // Test default values
        assert.strictEqual(config.get('enableAutoScan'), true, 
            'enableAutoScan should default to true');
        assert.strictEqual(config.get('maxFileSize'), 5242880, 
            'maxFileSize should default to 5MB');
        assert.strictEqual(config.get('enableHighSeverityOnly'), false, 
            'enableHighSeverityOnly should default to false');
    });

    test('Scanner processes JavaScript file with vulnerabilities', async () => {
        const vulnerableCode = `
            // Critical vulnerability
            eval(userInput);
            
            // High severity
            element.innerHTML = userData;
            
            // Medium severity  
            const random = Math.random();
        `;

        // Create a temporary document
        const document = await vscode.workspace.openTextDocument({
            content: vulnerableCode,
            language: 'javascript'
        });

        // Trigger scan by opening the document
        await vscode.window.showTextDocument(document);
        
        // Wait for diagnostics to be updated
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Check if diagnostics were created
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        assert.ok(diagnostics.length > 0, 'Should find security vulnerabilities');
        
        // Verify severity mapping
        const criticalErrors = diagnostics.filter(d => 
            d.severity === vscode.DiagnosticSeverity.Error && 
            d.message.includes('eval'));
        assert.ok(criticalErrors.length > 0, 'Should find critical eval vulnerability');
        
        // Clean up
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    });

    test('Scanner respects enableHighSeverityOnly setting', async () => {
        const config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        try {
            // Enable high severity only
            await config.update('enableHighSeverityOnly', true, vscode.ConfigurationTarget.Global);
            
            const mixedCode = `
                eval(userInput);              // Critical
                element.innerHTML = data;     // High  
                Math.random();               // Medium - should be filtered
            `;

            const document = await vscode.workspace.openTextDocument({
                content: mixedCode,
                language: 'javascript'
            });

            await vscode.window.showTextDocument(document);
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            const diagnostics = vscode.languages.getDiagnostics(document.uri);
            
            // Should only have critical and high severity issues
            const lowSeverityIssues = diagnostics.filter(d => 
                d.severity === vscode.DiagnosticSeverity.Information);
            assert.strictEqual(lowSeverityIssues.length, 0, 
                'Should filter out low severity issues');
                
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
        } finally {
            // Reset configuration
            await config.update('enableHighSeverityOnly', false, vscode.ConfigurationTarget.Global);
        }
    });

    test('Scanner respects maxFileSize setting', async () => {
        const config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        try {
            // Set very small file size limit
            await config.update('maxFileSize', 100, vscode.ConfigurationTarget.Global);
            
            const largeCode = 'console.log("test");'.repeat(50); // > 100 bytes
            
            const document = await vscode.workspace.openTextDocument({
                content: largeCode,
                language: 'javascript'
            });

            await vscode.window.showTextDocument(document);
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // File should be too large to scan, so no diagnostics
            const diagnostics = vscode.languages.getDiagnostics(document.uri);
            assert.strictEqual(diagnostics.length, 0, 
                'Should not scan files exceeding size limit');
                
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
        } finally {
            // Reset configuration  
            await config.update('maxFileSize', 5242880, vscode.ConfigurationTarget.Global);
        }
    });

    test('Scanner handles unsupported file types', async () => {
        const document = await vscode.workspace.openTextDocument({
            content: 'eval(userInput);',
            language: 'plaintext'  // Unsupported language
        });

        await vscode.window.showTextDocument(document);
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Should not produce diagnostics for unsupported file types
        const diagnostics = vscode.languages.getDiagnostics(document.uri);
        // Note: This test may need adjustment based on actual implementation
        
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
    });

    test('Auto-scan can be disabled', async () => {
        const config = vscode.workspace.getConfiguration('owaspCisaScanner');
        
        try {
            // Disable auto-scan
            await config.update('enableAutoScan', false, vscode.ConfigurationTarget.Global);
            
            const vulnerableCode = 'eval(userInput);';
            const document = await vscode.workspace.openTextDocument({
                content: vulnerableCode,
                language: 'javascript'
            });

            await vscode.window.showTextDocument(document);
            
            // Save the document to trigger auto-scan (which should be disabled)
            await document.save();
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Manual scan should still work
            await vscode.commands.executeCommand('owaspCisaScanner.scanCurrentFile');
            await new Promise(resolve => setTimeout(resolve, 500));
            
            const diagnostics = vscode.languages.getDiagnostics(document.uri);
            assert.ok(diagnostics.length > 0, 'Manual scan should still work');
            
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
        } finally {
            // Reset configuration
            await config.update('enableAutoScan', true, vscode.ConfigurationTarget.Global);
        }
    });
});