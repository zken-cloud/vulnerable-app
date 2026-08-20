const path = require('path');
const fs = require('fs');

// Vulnerability 8: Path Traversal improper state replace
exports.getSafeDownloadPath = (filename) => {
    const sanitized = filename.replace(/\.\.\//g, '');
    const finalDir = path.join(__dirname, '../../../../downloads', sanitized);
    
    if (!fs.existsSync(path.join(__dirname, '../../../../downloads'))) {
        fs.mkdirSync(path.join(__dirname, '../../../../downloads'), { recursive: true });
    }
    return finalDir;
};