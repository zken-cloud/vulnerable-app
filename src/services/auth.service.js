const userRepository = require('../data/repositories/userRepository');
const cryptoUtils = require('../core/utils/cryptoUtils');

exports.resetPasswordToken = () => {
    return cryptoUtils.generateSessionContextId();
};

exports.updateUserProfile = (id, payload) => {
    return userRepository.updateUser(id, payload);
};