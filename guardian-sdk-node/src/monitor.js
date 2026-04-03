const http = require('http');
const https = require('https');
const { URL } = require('url');
const { detectSqli, detectSsrf, clampSeverity } = require('./detectors');

function _safeStr(x, maxLen = 500) {
    let s;
    try {
        s = (typeof x === 'object') ? JSON.stringify(x) : String(x);
    } catch (e) {
        s = String(x);
    }
    if (!s) return "";
    s = s.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
    if (s.length > maxLen) {
        return s.substring(0, maxLen) + "â€¦";
    }
    return s;
}

function _emitDetection(telemetry, config, det, event_type, extra) {
    let verdict = det.verdict;
    if (config.mode === "block") {
        verdict = "BLOCKED";
    }

    telemetry.emit({
        event_type,
        message: det.reason,
        severity: clampSeverity(det.severity),
        category: det.category,
        verdict,
        extra
    });
}

function applyRemotePolicy(config, policy) {
    if (!policy || typeof policy !== 'object') {
        return;
    }
    if (typeof policy.mode === 'string' && policy.mode.trim()) {
        config.mode = policy.mode.trim().toLowerCase();
    }
    if (typeof policy.enabled === 'boolean') {
        config.enabled = policy.enabled;
    }
    if (typeof policy.severity_threshold === 'number') {
        config.severityThreshold = policy.severity_threshold;
    }
    console.log(`GuardianAI remote policy applied: mode=${config.mode} enabled=${config.enabled}`);
}

function fetchRemotePolicy(config) {
    if (!config.ingestUrl) {
        return;
    }

    let policyUrl;
    try {
        policyUrl = new URL(config.ingestUrl);
        const basePath = policyUrl.pathname.endsWith('/v1/telemetry')
            ? policyUrl.pathname.slice(0, -'/v1/telemetry'.length)
            : policyUrl.pathname.replace(/\/$/, '');
        policyUrl.pathname = `${basePath}/v1/policy`;
        policyUrl.search = '';
        policyUrl.searchParams.set('service_name', config.serviceName || 'unknown-node-service');
    } catch (err) {
        return;
    }

    const client = policyUrl.protocol === 'https:' ? https : http;
    const req = client.request(
        {
            method: 'GET',
            hostname: policyUrl.hostname,
            port: policyUrl.port || (policyUrl.protocol === 'https:' ? 443 : 80),
            path: `${policyUrl.pathname}${policyUrl.search}`,
            headers: {
                'X-API-KEY': process.env.GUARDIAN_API_KEY || ''
            },
            timeout: 1000
        },
        (res) => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                if (res.statusCode !== 200) {
                    return;
                }
                try {
                    applyRemotePolicy(config, JSON.parse(body));
                } catch (err) {
                }
            });
        }
    );

    req.on('error', () => {});
    req.on('timeout', () => {
        req.destroy();
    });
    req.end();
}

function guardianMiddleware(config, telemetry) {
    if (config.enabled) {
        telemetry.emit({
            event_type: "guardian.sdk.enabled",
            message: "guardian node sdk enabled",
            severity: 1,
            category: "sdk",
            verdict: "INFO"
        });
    }

    return function (req, res, next) {
        if (!config.enabled) {
            return next();
        }

        const url = req.url || '';
        const bodyStr = _safeStr(req.body, 1200);
        const queryStr = _safeStr(req.query, 1200);

        const ssrfDet = detectSsrf(url) || detectSsrf(queryStr) || detectSsrf(bodyStr);
        if (ssrfDet) {
            _emitDetection(telemetry, config, ssrfDet, "guardian.rasp.request", {
                method: req.method,
                url: _safeStr(url),
                source: "express_middleware"
            });
            if (config.mode === "block") {
                return res.status(403).json({ error: "Blocked by GuardianAI: " + ssrfDet.reason });
            }
        }

        let sqliDet = null;
        if (!sqliDet && url) sqliDet = detectSqli(decodeURIComponent(url));
        if (!sqliDet && bodyStr) sqliDet = detectSqli(bodyStr);
        if (!sqliDet && queryStr) sqliDet = detectSqli(queryStr);

        if (sqliDet) {
            _emitDetection(telemetry, config, sqliDet, "guardian.rasp.request", {
                method: req.method,
                url: _safeStr(url),
                source: "express_middleware"
            });
            if (config.mode === "block") {
                return res.status(403).json({ error: "Blocked by GuardianAI: " + sqliDet.reason });
            }
        }

        next();
    };
}

module.exports = { guardianMiddleware, fetchRemotePolicy, applyRemotePolicy };
