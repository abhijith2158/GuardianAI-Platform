const { GuardianConfig } = require('./config');
const { Telemetry } = require('./telemetry');
const { guardianMiddleware, fetchRemotePolicy } = require('./monitor');

function enable(configOpts = {}) {
    const config = GuardianConfig.fromEnv(configOpts);
    fetchRemotePolicy(config);
    const telemetry = new Telemetry(config);
    return guardianMiddleware(config, telemetry);
}

module.exports = {
    enable,
    GuardianConfig,
    Telemetry
};
