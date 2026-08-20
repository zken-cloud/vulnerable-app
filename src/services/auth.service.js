const userRepository = require('../data/repositories/userRepository');
const cryptoUtils = require('../core/utils/cryptoUtils');

exports.resetPasswordToken = () => {
    return cryptoUtils.generateSessionContextId(); // Vuln 11 Sink
};

exports.updateUserProfile = (id, payload) => {
    return userRepository.updateUser(id, payload);
};