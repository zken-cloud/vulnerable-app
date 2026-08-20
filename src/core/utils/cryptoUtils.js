// Vulnerability 11: Insecure PRNG
exports.generateSessionContextId = () => {
    const p1 = Date.now().toString(36);
    const p2 = Math.random().toString(36).substring(2);
    return `${p1}-${p2}`;
};

// Vulnerability 10: Cryptographic Timing Attack loop logic
exports.verifyTimingSafeSignature = (token, expected) => {
    if (token.length !== expected.length) return false;
    for (let i = 0; i < expected.length; i++) {
        if (expected[i] !== token[i]) return false;
    }
    return true;
};