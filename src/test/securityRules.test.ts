import * as assert from 'assert';
import { SECURITY_RULES } from '../securityRules';

suite('Security Rules Test Suite', () => {
    
    test('All rules have required properties', () => {
        SECURITY_RULES.forEach(rule => {
            assert.ok(rule.id, `Rule missing id: ${JSON.stringify(rule)}`);
            assert.ok(rule.pattern, `Rule ${rule.id} missing pattern`);
            assert.ok(['critical', 'high', 'medium', 'low'].includes(rule.severity), 
                `Rule ${rule.id} has invalid severity: ${rule.severity}`);
            assert.ok(rule.category, `Rule ${rule.id} missing category`);
            assert.ok(rule.message, `Rule ${rule.id} missing message`);
            assert.ok(rule.remediation, `Rule ${rule.id} missing remediation`);
        });
    });

    test('Rule IDs are unique', () => {
        const ids = SECURITY_RULES.map(rule => rule.id);
        const uniqueIds = new Set(ids);
        assert.strictEqual(ids.length, uniqueIds.size, 'Duplicate rule IDs found');
    });

    suite('OWASP A01: Broken Access Control', () => {
        test('Detects innerHTML XSS vulnerability', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A01-001');
            assert.ok(rule, 'A01-001 rule not found');
            
            // Positive cases - should match
            const vulnerableCases = [
                'element.innerHTML = userInput;',
                'div.outerHTML = "<div>" + data + "</div>";',
                'elem.innerHTML = `<p>${untrustedData}</p>`;'
            ];
            
            vulnerableCases.forEach(code => {
                rule!.pattern.lastIndex = 0;
                assert.ok(rule!.pattern.test(code), 
                    `Should detect XSS in: ${code}`);
            });
            
            // Negative cases - should not match
            const safeCases = [
                'element.innerHTML = "";',
                'element.textContent = userInput;',
                'element.innerHTML = "static content";'
            ];
            
            safeCases.forEach(code => {
                rule!.pattern.lastIndex = 0;
                assert.ok(!rule!.pattern.test(code), 
                    `Should not flag safe code: ${code}`);
            });
        });

        test('Detects React dangerouslySetInnerHTML', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A01-002');
            assert.ok(rule, 'A01-002 rule not found');
            
            const vulnerableCode = '<div dangerouslySetInnerHTML={{__html: userContent}} />';
            rule!.pattern.lastIndex = 0;
            assert.ok(rule!.pattern.test(vulnerableCode), 
                'Should detect dangerouslySetInnerHTML');
        });
    });

    suite('OWASP A02: Cryptographic Failures', () => {
        test('Detects MD5 usage', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A02-001');
            assert.ok(rule, 'A02-001 rule not found');
            
            const vulnerableCases = [
                'crypto.createHash("md5")',
                "crypto.createHash('md5')",
                'crypto.createHash(`md5`)'
            ];
            
            vulnerableCases.forEach(code => {
                rule!.pattern.lastIndex = 0;
                assert.ok(rule!.pattern.test(code), 
                    `Should detect MD5 usage in: ${code}`);
            });
        });

        test('Detects SHA-1 usage', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A02-002');
            assert.ok(rule, 'A02-002 rule not found');
            
            const vulnerableCode = 'crypto.createHash("sha1")';
            rule!.pattern.lastIndex = 0;
            assert.ok(rule!.pattern.test(vulnerableCode), 
                'Should detect SHA-1 usage');
        });

        test('Detects insecure Math.random()', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A02-004');
            assert.ok(rule, 'A02-004 rule not found');
            
            const vulnerableCases = [
                'const token = Math.random();',
                'Math.random() * 1000',
                'password = Math.random().toString(36)'
            ];
            
            vulnerableCases.forEach(code => {
                rule!.pattern.lastIndex = 0;
                assert.ok(rule!.pattern.test(code), 
                    `Should detect Math.random() in: ${code}`);
            });
        });
    });

    suite('OWASP A03: Injection', () => {
        test('Detects eval() usage', () => {
            const rule = SECURITY_RULES.find(r => r.id === 'A03-001');
            assert.ok(rule, 'A03-001 rule not found');
            
            const vulnerableCases = [
                'eval(userInput)',
                'eval("console.log(data)")',
                '  eval(  code  )  '
            ];
            
            vulnerableCases.forEach(code => {
                rule!.pattern.lastIndex = 0;
                assert.ok(rule!.pattern.test(code), 
                    `Should detect eval() in: ${code}`);
            });
        });
    });

    test('Performance: Rules execute within reasonable time', () => {
        const testCode = `
            // Large test file with various patterns
            element.innerHTML = userInput;
            crypto.createHash("md5");
            eval(userCode);
            Math.random();
            console.log("password:", userPass);
        `.repeat(100);
        
        const start = Date.now();
        
        SECURITY_RULES.forEach(rule => {
            const lines = testCode.split('\n');
            lines.forEach(line => {
                rule.pattern.lastIndex = 0;
                rule.pattern.test(line);
            });
        });
        
        const duration = Date.now() - start;
        assert.ok(duration < 1000, `Rules took too long: ${duration}ms`);
    });
});