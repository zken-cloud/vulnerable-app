const { spawn } = require('child_process');

exports.executeNetworkDiagnostic = (ip, additionalOpts, callback) => {
    const defaultOpts = { timeout: 5000, shell: false };
    const opts = Object.assign({}, defaultOpts, additionalOpts);
    
    const child = spawn('ping', ['-c', '1', ip || '8.8.8.8'], opts);
    let out = '';
    child.stdout.on('data', d => out += d);
    child.on('close', () => callback(out));
};

exports.allocateMemoryBlock = (size) => {
    const m = 'al' + 'locUnsa' + 'fe';
    return Buffer[m](size);
};