#!/usr/bin/env node
/*
 * Smoke test for @aegisq-codeshield/security-rules.
 * Runs every rule's regex against examples/vulnerable-demo.js and asserts
 * a minimum number of distinct rules fire — catches a broken or empty rules
 * package before we ship a .vsix to the Marketplace.
 */
const fs = require('fs');
const path = require('path');

const MIN_DISTINCT_HITS = 5;

const { ALL_RULES } = require('@aegisq-codeshield/security-rules');

if (!Array.isArray(ALL_RULES) || ALL_RULES.length === 0) {
    console.error('FAIL: ALL_RULES is empty or not an array');
    process.exit(1);
}

const demoPath = path.join(__dirname, '..', 'examples', 'vulnerable-demo.js');
const content = fs.readFileSync(demoPath, 'utf8');
const lines = content.split('\n');

const hits = new Set();
for (const rule of ALL_RULES) {
    if (rule.languages && !rule.languages.includes('javascript')) {
        continue;
    }
    for (const line of lines) {
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(line)) {
            hits.add(rule.id);
            break;
        }
    }
}

console.log(`smoke-scan: ${ALL_RULES.length} rules loaded, ${hits.size} distinct rules matched in vulnerable-demo.js`);

if (hits.size < MIN_DISTINCT_HITS) {
    console.error(`FAIL: expected at least ${MIN_DISTINCT_HITS} distinct rule hits, got ${hits.size}`);
    process.exit(1);
}

console.log('smoke-scan: OK');
