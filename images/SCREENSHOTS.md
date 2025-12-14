# Screenshot Instructions

This folder should contain screenshots for the VS Code Marketplace and README.

## Required Screenshots

### 1. `demo-problems-panel.png` (Main screenshot for README)
**How to capture:**
1. Open VS Code with this extension installed
2. Open `examples/vulnerable-demo.js`
3. The scanner will automatically detect vulnerabilities
4. Open the Problems panel (View → Problems or Ctrl+Shift+M)
5. Take a screenshot showing:
   - Code editor with red squiggly underlines
   - Problems panel listing detected vulnerabilities
   - Mix of Critical, High, and Medium severity issues

**Recommended size:** 1200x800 pixels

### 2. `demo-hover-tooltip.png` (Optional)
**How to capture:**
1. Open `examples/vulnerable-demo.js`
2. Hover over a red squiggly underline (e.g., `eval(userInput)`)
3. Wait for the tooltip to appear with remediation advice
4. Screenshot the tooltip showing the vulnerability details

### 3. `demo-context-menu.png` (Optional)
**How to capture:**
1. Right-click in any code file
2. Show the "Scan for Security Issues" context menu option

## Tips
- Use a clean VS Code theme (default dark or light)
- Ensure the Problems panel shows a variety of severity levels
- Crop to focus on the relevant areas
- Keep file sizes reasonable (< 500KB)
