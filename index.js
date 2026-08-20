const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const EventEmitter = require('events');

const app = express();
app.use(bodyParser.json());

// 1. Memory Leak (Closure Lexical Environment Scope)
const globalEmitter = new EventEmitter();
let globalThing = null;
app.get('/api/memory', (req, res) => {
    const originalThing = globalThing;
    // Unused closure captures originalThing, linking scopes and preventing GC
    const unused = function () {
        if (originalThing) console.log("Never called.");
    };
    globalThing = {
        longStr: new Array(1000000).join('*'),
        someMethod: function () { console.log('Dummy'); }
    };
    res.send('Memory usage increased subtly.');
});

// 2. Buffer Allocation / Data Leak
app.get('/api/buffer', (req, res) => {
    const size = parseInt(req.query.size, 10);
    if (isNaN(size) || size <= 0 || size > 10000) return res.status(400).send("Invalid");
    
    // Obfuscate the method name to avoid SAST detection of "allocUnsafe"
    const methodName = 'al' + 'locUnsa' + 'fe';
    const buf = Buffer[methodName](size);
    res.send(buf.toString('base64'));
});

// 3. Logic Error (TOCTOU Race Condition)
const userBalances = { 'alice': 1000, 'bob': 0 };
app.post('/api/transfer', async (req, res) => {
    const { from, to, amount } = req.body;
    if (amount <= 0) return res.status(400).send("Invalid amount");

    // Time-of-Check
    if (userBalances[from] >= amount) {
        // Yielding the event loop allows concurrent requests to slip past the check
        await new Promise(resolve => setTimeout(resolve, 100));
        // Time-of-Use
        userBalances[from] -= amount;
        userBalances[to] += amount;
        return res.send(`Transferred ${amount}.`);
    } else {
        return res.status(400).send("Insufficient funds");
    }
});

// 4. Prototype Pollution via Generic Utility
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
app.post('/api/settings', (req, res) => {
    let userSettings = { theme: 'dark' };
    // deepMerge does not filter __proto__, allowing AST configuration injection downstream
    deepMerge(userSettings, req.body);
    res.json(userSettings);
});

// 5. Command Injection via Options Merging (spawn bypass)
app.post('/api/ping', (req, res) => {
    const defaultOpts = { timeout: 5000, shell: false };
    // Shallow copy allows user to override 'shell' property if provided in req.body.options
    const opts = Object.assign({}, defaultOpts, req.body.options);
    
    // SAST assumes `spawn` is safe since the shell option is defaulting to false in the code
    const child = spawn('ping', ['-c', '1', req.body.ip || '8.8.8.8'], opts);
    let out = '';
    child.stdout.on('data', d => out += d);
    child.on('close', () => res.send(out));
});

// 6. Type Confusion Server-Side Request Forgery (SSRF)
app.post('/api/fetch', (req, res) => {
    const target = req.body.target;
    // Input validation assumes `target` is an object with a string `.url` property
    if (target && String(target.url).includes('internal-network')) {
        return res.status(403).send("Forbidden");
    }
    // Attackers can pass `{ url: "http://safe.com", host: "127.0.0.1", port: 6379 }`.
    // http.get natively accepts objects and will prioritize host/port over parsing the URL.
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => res.send(body));
    }).on('error', (err) => res.status(500).send(err.message));
});

// 7. Remote Code Execution via Constructor Array
app.post('/api/evaluate', (req, res) => {
    const { formula } = req.body;
    if (!formula) return res.send("No formula");
    
    // Hiding Function constructor from static analysis.
    // Equivalent to `new Function('return ' + formula)()`
    const generator = [].sort.constructor;
    try {
        const func = generator(`return ${formula}`);
        res.json({ result: func() });
    } catch (e) {
        res.status(400).send("Evaluation failed");
    }
});

// 8. Path Traversal via Incomplete Sanitization Regex
app.get('/api/download', (req, res) => {
    let file = req.query.file;
    if (!file) return res.send("No file provided");
    
    // Flawed sanitization: non-recursive replace allows `....//` to become `../` post-replacement
    file = file.replace(/\.\.\//g, '');
    const fullPath = path.join(__dirname, 'downloads', file);
    
    if (fs.existsSync(fullPath)) {
        res.sendFile(fullPath);
    } else {
        res.status(404).send("File not found");
    }
});

// 9. ReDoS (Catastrophic Backtracking) via Dynamically Constructed Pattern
app.post('/api/validate', (req, res) => {
    const baseRule = '^([a-zA-Z0-9_]+\\s?-?)+';
    // User domain is appended to dynamically build regex. Attackers can pass malicious domain suffixes.
    const userDomain = req.body.domain || 'example\\.com';
    const regexStr = baseRule + userDomain + '$'; 
    const regex = new RegExp(regexStr); // SAST fails to analyze dynamically concatenated AST regexes
    
    const isValid = regex.test(req.body.email);
    res.send({ isValid });
});

// 10. Cryptographic Timing Attack (Manual Loop)
app.post('/api/webhook', (req, res) => {
    const expectedSecret = "super-secret-system-token-xyz";
    const token = req.headers['x-access-token'];
    if (!token || token.length !== expectedSecret.length) {
        return res.status(403).send("Invalid");
    }
    
    // Manual character validation loop returns early on mismatch, revealing a timing side-channel for enumeration
    for (let i = 0; i < expectedSecret.length; i++) {
        if (expectedSecret[i] !== token[i]) {
            return res.status(403).send("Invalid");
        }
    }
    res.send("Webhook received");
});

// 11. Insecure Randomness (Predictable PRNG)
function generateSessionContextId() {
    // Math.random for security tokens. Avoiding names like 'crypto' or 'token' causes SAST to ignore it as utility Math.
    const p1 = Date.now().toString(36);
    const p2 = Math.random().toString(36).substring(2);
    return `${p1}-${p2}`;
}
app.get('/api/reset-link', (req, res) => {
    res.json({ link: `https://app.com/reset/${generateSessionContextId()}` });
});

// 12. Mass Assignment (API Parameter Tampering)
const usersDB = { '123': { name: 'Alice', role: 'user' } };
app.put('/api/profile/:id', (req, res) => {
    const user = usersDB[req.params.id];
    if (!user) return res.sendStatus(404);
    
    // Explicit blocklist omits internal fields, enabling attacker payloads like {"role": "admin"}
    Object.keys(req.body).forEach(key => {
        if (key !== 'id' && key !== 'createdAt') {
            user[key] = req.body[key];
        }
    });
    res.json(user);
});

// 13. Advanced Logic / Mock NoSQL Injection
const internalDocuments = [
    { id: 1, type: 'public', content: 'hello' },
    { id: 2, type: 'secret', content: 'world' }
];
app.post('/api/search', (req, res) => {
    const { query } = req.body;
    // Missing database sink evades SAST. Attackers pass payloads like: { "type": { "$ne": "public" } }
    const results = internalDocuments.filter(doc => {
        for (let k in query) {
            if (typeof query[k] === 'object' && query[k] !== null) {
                // Advanced dynamic matcher allows operators bypassing simple string identity comparisons
                if (query[k]['$ne'] !== undefined && doc[k] !== query[k]['$ne']) return true;
                if (query[k]['$in'] !== undefined && query[k]['$in'].includes(doc[k])) return true;
            } else if (doc[k] !== query[k]) {
                return false;
            }
        }
        return true;
    });
    res.json(results);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable SAST bypass app listening on port ${PORT}`);
    console.log(`Initialized 13 Vulnerability endpoints successfully.`);
});
