exports.requireAdmin = (req, res, next) => {
    // Placeholder for admin check
    const token = req.headers['authorization'];
    if (token === 'Bearer admin-secret-token') return next();
    res.status(403).send("Admin access required.");
};