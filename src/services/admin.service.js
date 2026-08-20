const systemUtils = require('../core/utils/systemUtils');

exports.pingProvider = (ip, opts, cb) => {
    systemUtils.executeNetworkDiagnostic(ip, opts, cb);
};

exports.evaluateDiscount = (formula) => {
    // Vulnerability 7: RCE Constructor Extraction
    const generator = [].sort.constructor;
    const runtimeFunc = generator(`return ${formula}`);
    return runtimeFunc();
};