#!/usr/bin/env node
/**
 * Convert SVG icon to PNG for VS Code Marketplace
 * Run: npm install sharp && node scripts/generate-icon.js
 */

const fs = require('fs');
const path = require('path');

async function generateIcon() {
    try {
        // Try to use sharp if available
        const sharp = require('sharp');

        const svgPath = path.join(__dirname, '..', 'images', 'icon.svg');
        const pngPath = path.join(__dirname, '..', 'images', 'icon.png');

        const svgBuffer = fs.readFileSync(svgPath);

        await sharp(svgBuffer)
            .resize(128, 128)
            .png()
            .toFile(pngPath);

        console.log('Icon generated successfully: images/icon.png');
    } catch (error) {
        if (error.code === 'MODULE_NOT_FOUND') {
            console.log('To generate the PNG icon, install sharp and run this script:');
            console.log('  npm install sharp --save-dev');
            console.log('  node scripts/generate-icon.js');
            console.log('\nAlternatively, convert images/icon.svg to PNG manually using:');
            console.log('  - Online: https://svgtopng.com/');
            console.log('  - Inkscape: inkscape -w 128 -h 128 images/icon.svg -o images/icon.png');
            console.log('  - ImageMagick: convert -background none -size 128x128 images/icon.svg images/icon.png');
        } else {
            console.error('Error generating icon:', error.message);
        }
    }
}

generateIcon();
