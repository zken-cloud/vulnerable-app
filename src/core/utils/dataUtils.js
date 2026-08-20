// Vulnerability 4: Prototype Pollution via Deep Merge Pattern
exports.applySettingsMerge = function applySettingsMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
            target[key] = target[key] || {};
            applySettingsMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
};