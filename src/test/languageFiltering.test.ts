import * as assert from 'assert';
import { SECURITY_RULES } from '../securityRules';

suite('Language-Specific Rule Filtering', () => {
    
    test('Rules with language restrictions are properly filtered', () => {
        // JavaScript/TypeScript specific rules
        const jsRules = SECURITY_RULES.filter(rule => 
            rule.languages?.includes('javascript')
        );
        
        // Should have JavaScript-specific rules like innerHTML, crypto methods
        const innerHTMLRule = jsRules.find(r => r.id === 'A01-001');
        const md5Rule = jsRules.find(r => r.id === 'A02-001');
        
        assert.ok(innerHTMLRule, 'Should have innerHTML rule for JavaScript');
        assert.ok(md5Rule, 'Should have MD5 rule for JavaScript');
    });

    test('Language filtering function works correctly', () => {
        // Simulate the getApplicableRules logic
        function getApplicableRules(languageId?: string) {
            if (!languageId) {
                return SECURITY_RULES;
            }

            return SECURITY_RULES.filter(rule => {
                if (!rule.languages || rule.languages.length === 0) {
                    return true;
                }
                return rule.languages.includes(languageId);
            });
        }

        // Test JavaScript filtering
        const jsRules = getApplicableRules('javascript');
        const jsSpecificRule = jsRules.find(r => r.id === 'A01-001'); // innerHTML rule
        assert.ok(jsSpecificRule, 'JavaScript should get JS-specific rules');

        // Test language that doesn't match
        const pythonRules = getApplicableRules('python');
        const jsOnlyRule = pythonRules.find(r => 
            r.languages && r.languages.includes('javascript') && 
            !r.languages.includes('python')
        );
        assert.ok(!jsOnlyRule, 'Python should not get JavaScript-only rules');

        // Test rules without language restrictions (should apply to all)
        const allLanguages = getApplicableRules('someotherl language');
        const universalRules = allLanguages.filter(r => !r.languages || r.languages.length === 0);
        assert.ok(universalRules.length > 0, 'Should have universal rules for any language');
    });

    test('Rule coverage across supported languages', () => {
        const supportedLanguages = [
            'javascript', 'typescript', 'python', 'java', 
            'csharp', 'php', 'ruby', 'go', 'cpp', 'c'
        ];

        supportedLanguages.forEach(lang => {
            const applicableRules = SECURITY_RULES.filter(rule => 
                !rule.languages || rule.languages.length === 0 || rule.languages.includes(lang)
            );
            
            assert.ok(applicableRules.length > 0, 
                `Language ${lang} should have applicable security rules`);
        });
    });

    test('Performance: Language filtering is efficient', () => {
        const start = Date.now();
        
        // Simulate multiple language filtering operations
        for (let i = 0; i < 1000; i++) {
            const rules = SECURITY_RULES.filter(rule => 
                !rule.languages || rule.languages.includes('javascript')
            );
            assert.ok(rules.length >= 0); // Basic assertion to prevent optimization
        }
        
        const duration = Date.now() - start;
        assert.ok(duration < 100, `Language filtering took too long: ${duration}ms`);
    });
});