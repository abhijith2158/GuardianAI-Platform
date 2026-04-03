const fs = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const { URL } = require('url');

function utcIso() {
    return new Date().toISOString().replace(/\.[0-9]{3}Z$/, '+00:00'); // Close enough to python's isoformat with seconds
}

class TelemetryEvent {
    constructor({
        ts, service, env, event_type, message, severity = 1,
        category = null, verdict = null, pid = process.pid,
        host = os.hostname(), extra = {}
    }) {
        this.ts = ts;
        this.service = service;
        this.env = env;
        this.event_type = event_type;
        this.message = message;
        this.severity = severity;
        this.category = category;
        this.verdict = verdict;
        this.pid = pid;
        this.host = host;
        this.extra = extra;
    }
}

class FileTelemetrySink {
    constructor(config) {
        this.config = config;
    }

    emit(ev) {
        const line = this.formatLine(ev);
        const path = this.config.logPath || "security.log";
        try {
            fs.appendFileSync(path, line + '\n', { encoding: 'utf-8' });
        } catch (err) {
            // Never break app because logging failed
        }
    }

    formatLine(ev) {
        const payload = { ...ev };
        const jsonBlob = JSON.stringify(payload);
        
        const datePrefix = ev.ts ? ev.ts.substring(0, 10) : new Date().toISOString().substring(0, 10);
        
        let core = `${datePrefix} guardian event_type=${ev.event_type} service=${ev.service} env=${ev.env} severity=${ev.severity} message=${ev.message}`;
        if (ev.category) core += ` category=${ev.category}`;
        if (ev.verdict) core += ` verdict=${ev.verdict}`;
        
        return core + ' | ' + jsonBlob;
    }
}

class RemoteTelemetrySink {
    constructor(config) {
        this.config = config;
    }

    emit(ev) {
        const ingestUrl = this.config.ingestUrl;
        if (!ingestUrl) {
            return;
        }

        const apiKey = process.env.GUARDIAN_API_KEY || '';
        const payload = JSON.stringify({ ...ev });

        setImmediate(() => {
            try {
                const url = new URL(ingestUrl);
                const client = url.protocol === 'https:' ? https : http;
                const req = client.request(
                    {
                        method: 'POST',
                        hostname: url.hostname,
                        port: url.port || (url.protocol === 'https:' ? 443 : 80),
                        path: `${url.pathname}${url.search}`,
                        headers: {
                            'Content-Type': 'application/json',
                            'Content-Length': Buffer.byteLength(payload),
                            'X-API-KEY': apiKey
                        },
                        timeout: 1000
                    },
                    (res) => {
                        res.resume();
                    }
                );

                req.on('error', () => {});
                req.on('timeout', () => {
                    req.destroy();
                });
                req.write(payload);
                req.end();
            } catch (err) {
                // Never break app because remote telemetry failed.
            }
        });
    }
}

class Telemetry {
    constructor(config) {
        this.config = config;
        this.fileSink = new FileTelemetrySink(config);
        this.remoteSink = new RemoteTelemetrySink(config);
    }

    emit({ event_type, message, severity = 1, category = null, verdict = null, extra = {} }) {
        if (!this.config.enabled) return;

        const ev = new TelemetryEvent({
            ts: new Date().toISOString(),
            service: this.config.serviceName,
            env: this.config.environment,
            event_type,
            message,
            severity: parseInt(severity, 10),
            category,
            verdict,
            extra
        });
        this.fileSink.emit(ev);
        this.remoteSink.emit(ev);
    }
}

module.exports = { Telemetry, TelemetryEvent, FileTelemetrySink, RemoteTelemetrySink };
