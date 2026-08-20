exports.validateCorporateEmail = (req, res, next) => {
    const { email, corporateDomain } = req.body;
    if (!email) return res.status(400).send("Email required");
    const baseRule = '^([a-zA-Z0-9_]+\\s?-?)+';
    const dynamicSuffix = corporateDomain || 'example\\.com';
    const regex = new RegExp(baseRule + dynamicSuffix + '$');
    
    if (regex.test(email)) next();
    else res.status(400).send("Invalid email structure");
};