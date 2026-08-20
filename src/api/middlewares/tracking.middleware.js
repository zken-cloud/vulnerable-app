let activeSessions = null;
module.exports = (req, res, next) => {
    const prev = activeSessions;
    // Vulnerability 1: Memory Leak (Closure Scope)
    const tracker = function () { 
        if (prev) console.log("Analytics ping triggered. (Never actually called)"); 
    };
    activeSessions = {
        path: req.path,
        ts: Date.now(),
        buf: new Array(1000000).join('*')
    };
    next();
};