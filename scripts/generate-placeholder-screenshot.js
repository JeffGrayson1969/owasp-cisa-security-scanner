#!/usr/bin/env node
/**
 * Generate a placeholder screenshot for the README
 */

const sharp = require('sharp');
const path = require('path');

const width = 800;
const height = 400;

// Create a simple placeholder SVG
const svg = `
<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%" fill="#1e1e1e"/>

  <!-- Title bar -->
  <rect x="0" y="0" width="100%" height="30" fill="#3c3c3c"/>
  <circle cx="15" cy="15" r="6" fill="#ff5f56"/>
  <circle cx="35" cy="15" r="6" fill="#ffbd2e"/>
  <circle cx="55" cy="15" r="6" fill="#27ca40"/>
  <text x="400" y="20" fill="#cccccc" text-anchor="middle" font-family="monospace" font-size="12">vulnerable-demo.js - OWASP/CISA Security Scanner</text>

  <!-- Code area with sample code -->
  <rect x="0" y="30" width="550" height="370" fill="#1e1e1e"/>
  <text x="20" y="60" fill="#6a9955" font-family="monospace" font-size="11">// Security vulnerabilities detected</text>
  <text x="20" y="80" fill="#c586c0" font-family="monospace" font-size="11">function</text>
  <text x="80" y="80" fill="#dcdcaa" font-family="monospace" font-size="11">processInput</text>
  <text x="165" y="80" fill="#d4d4d4" font-family="monospace" font-size="11">(userInput) {</text>

  <!-- Red squiggly line simulation -->
  <text x="30" y="100" fill="#569cd6" font-family="monospace" font-size="11">  eval</text>
  <text x="65" y="100" fill="#d4d4d4" font-family="monospace" font-size="11">(userInput);</text>
  <line x1="30" y1="103" x2="120" y2="103" stroke="#f44747" stroke-width="2" stroke-dasharray="2,1"/>

  <text x="30" y="120" fill="#d4d4d4" font-family="monospace" font-size="11">  element.</text>
  <text x="95" y="120" fill="#9cdcfe" font-family="monospace" font-size="11">innerHTML</text>
  <text x="165" y="120" fill="#d4d4d4" font-family="monospace" font-size="11"> = data;</text>
  <line x1="95" y1="123" x2="175" y2="123" stroke="#f44747" stroke-width="2" stroke-dasharray="2,1"/>

  <text x="20" y="140" fill="#d4d4d4" font-family="monospace" font-size="11">}</text>

  <!-- Problems panel -->
  <rect x="550" y="30" width="250" height="370" fill="#252526"/>
  <rect x="550" y="30" width="250" height="25" fill="#3c3c3c"/>
  <text x="560" y="48" fill="#cccccc" font-family="sans-serif" font-size="11" font-weight="bold">PROBLEMS</text>
  <text x="720" y="48" fill="#f44747" font-family="sans-serif" font-size="10">5</text>

  <!-- Problem items -->
  <rect x="555" y="60" width="240" height="40" fill="#2d2d30"/>
  <circle cx="570" cy="80" r="8" fill="#f44747"/>
  <text x="570" y="84" fill="white" text-anchor="middle" font-family="sans-serif" font-size="10" font-weight="bold">!</text>
  <text x="585" y="75" fill="#f44747" font-family="sans-serif" font-size="10">Critical: eval() detected</text>
  <text x="585" y="90" fill="#808080" font-family="sans-serif" font-size="9">A03: Injection - CWE-94</text>

  <rect x="555" y="105" width="240" height="40" fill="#2d2d30"/>
  <circle cx="570" cy="125" r="8" fill="#f44747"/>
  <text x="570" y="129" fill="white" text-anchor="middle" font-family="sans-serif" font-size="10" font-weight="bold">!</text>
  <text x="585" y="120" fill="#f44747" font-family="sans-serif" font-size="10">High: innerHTML assignment</text>
  <text x="585" y="135" fill="#808080" font-family="sans-serif" font-size="9">A01: XSS - CWE-79</text>

  <rect x="555" y="150" width="240" height="40" fill="#2d2d30"/>
  <circle cx="570" cy="170" r="8" fill="#cca700"/>
  <text x="570" y="174" fill="black" text-anchor="middle" font-family="sans-serif" font-size="10" font-weight="bold">!</text>
  <text x="585" y="165" fill="#cca700" font-family="sans-serif" font-size="10">Medium: Weak crypto (MD5)</text>
  <text x="585" y="180" fill="#808080" font-family="sans-serif" font-size="9">A02: Cryptographic Failures</text>

  <!-- Footer text -->
  <text x="400" y="380" fill="#4CAF50" text-anchor="middle" font-family="sans-serif" font-size="14" font-weight="bold">OWASP/CISA Security Scanner</text>
</svg>`;

async function generate() {
    const outputPath = path.join(__dirname, '..', 'images', 'demo-problems-panel.png');

    await sharp(Buffer.from(svg))
        .png()
        .toFile(outputPath);

    console.log('Placeholder screenshot generated: images/demo-problems-panel.png');
    console.log('Replace with a real screenshot for better marketplace presentation.');
}

generate().catch(console.error);
