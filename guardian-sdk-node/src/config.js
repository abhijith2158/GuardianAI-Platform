const path = require('path');

function normalizeIngestUrl(value) {
    if (!value || typeof value !== 'string') {
        return null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return null;
    }

    try {
        const url = new URL(trimmed);
        let pathname = (url.pathname || '/').replace(/\/+$/, '');
        if (!pathname || pathname === '') {
            pathname = '/v1/telemetry';
        } else if (pathname === '/') {
            pathname = '/v1/telemetry';
        } else if (!pathname.endsWith('/v1/telemetry')) {
            pathname = `${pathname}/v1/telemetry`;
        }
        url.pathname = pathname;
        return url.toString().replace(/\/$/, '');
    } catch (_err) {
        const stripped = trimmed.replace(/\/+$/, '');
        if (stripped.endsWith('/v1/telemetry')) {
            return stripped;
        }
        return `${stripped}/v1/telemetry`;
    }
}

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
            ingestUrl: normalizeIngestUrl(overrides.ingestUrl || process.env.GUARDIAN_INGEST_URL || null),
            enabled: ["0", "false", "False"].includes(process.env.GUARDIAN_ENABLED?.trim()) ? false : (overrides.enabled !== undefined ? overrides.enabled : true),
            mode: (process.env.GUARDIAN_MODE?.trim().toLowerCase() || overrides.mode) || "monitor"
        });
    }
}

module.exports = { GuardianConfig };
