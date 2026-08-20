const authService = require('../../services/auth.service');
const dataUtils = require('../../core/utils/dataUtils');

exports.register = (req, res) => res.json({ success: true, message: 'Valid email registered' });

exports.forgotPassword = (req, res) => {
    res.json({ token: authService.resetPasswordToken() });
};

exports.updateProfile = (req, res) => {
    const updated = authService.updateUserProfile(req.params.id, req.body);
    if (updated) res.json(updated);
    else res.status(404).send('Not found');
};

exports.updatePreferences = (req, res) => {
    const prefs = { theme: 'light' };
    dataUtils.applySettingsMerge(prefs, req.body.preferences || {});
    res.json(prefs);
};