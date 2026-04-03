const path = require('path');

class GuardianConfig {
    constructor({
        serviceName = "unknown-service",
        environment = "dev",
        logPath = "security.log",
        ingestUrl = null,
        enabled = true,
        mode = "monitor"
    } = {}) {
        this.serviceName = serviceName;
        this.environment = environment;
        this.logPath = logPath;
        this.ingestUrl = ingestUrl;
        this.enabled = enabled;
        this.mode = mode; // "monitor" or "block"
    }

    static fromEnv(overrides = {}) {
        return new GuardianConfig({
            serviceName: process.env.GUARDIAN_SERVICE_NAME || overrides.serviceName || "unknown-node-service",
            environment: process.env.GUARDIAN_ENV || overrides.environment || "dev",
            logPath: overrides.logPath || process.env.GUARDIAN_LOG_PATH || path.join(process.cwd(), 'security.log'),
            ingestUrl: overrides.ingestUrl || process.env.GUARDIAN_INGEST_URL || null,
            enabled: ["0", "false", "False"].includes(process.env.GUARDIAN_ENABLED?.trim()) ? false : (overrides.enabled !== undefined ? overrides.enabled : true),
            mode: (process.env.GUARDIAN_MODE?.trim().toLowerCase() || overrides.mode) || "monitor"
        });
    }
}

module.exports = { GuardianConfig };
