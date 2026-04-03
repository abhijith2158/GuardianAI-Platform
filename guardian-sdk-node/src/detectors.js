class Detection {
    constructor(category, verdict, severity, reason, indicators = []) {
        this.category = category;
        this.verdict = verdict;
        this.severity = severity;
        this.reason = reason;
        this.indicators = indicators;
    }
}

const SQLI_REGEXES = [
    ["union-select", /\bunion\b\s+\bselect\b/i],
    ["tautology", /(\bor\b|\band\b)\s+[\w'"]+\s*=\s*[\w'"]+/i],
    ["comment-seq", /(--|#|\/\*)/i],
    ["stacked", /;\s*(drop|alter|create|insert|update|delete)\b/i],
    ["sleep", /\b(sleep|pg_sleep|benchmark)\s*\(/i]
];

function detectSqli(query) {
    const q = (query || "").trim();
    if (!q) return null;

    const hits = [];
    for (const [name, rx] of SQLI_REGEXES) {
        if (rx.test(q)) {
            hits.push(name);
        }
    }

    if (hits.length === 0) return null;

    return new Detection(
        "sql_injection",
        "SUSPICIOUS",
        7,
        "sql injection pattern detected",
        [...hits, "sql injection"]
    );
}

const PRIVATE_HOST_LITERALS = ["localhost", "127.0.0.1", "0.0.0.0"];
const METADATA_IPS = ["169.254.169.254"];

function isIpPrivate(ipStr) {
    const parts = ipStr.split('.');
    if (parts.length !== 4) return false;
    
    const p1 = parseInt(parts[0], 10);
    const p2 = parseInt(parts[1], 10);
    
    // 10.x.x.x
    if (p1 === 10) return true;
    // 172.16.x.x - 172.31.x.x
    if (p1 === 172 && p2 >= 16 && p2 <= 31) return true;
    // 192.168.x.x
    if (p1 === 192 && p2 === 168) return true;
    // Loopback 127.x.x.x
    if (p1 === 127) return true;
    // Link local 169.254.x.x
    if (p1 === 169 && p2 === 254) return true;
    
    return false;
}

function detectSsrf(url) {
    const u = (url || "").trim();
    if (!u) return null;

    const uLc = u.toLowerCase();

    if (uLc.startsWith("file://") || uLc.startsWith("gopher://") || uLc.startsWith("ftp://")) {
        return new Detection("ssrf", "SUSPICIOUS", 8, "dangerous outbound scheme (possible SSRF)", ["ssrf", "outbound request"]);
    }

    if (PRIVATE_HOST_LITERALS.some(h => uLc.includes(h))) {
        return new Detection("ssrf", "SUSPICIOUS", 8, "outbound request to localhost (possible SSRF)", ["ssrf", "localhost"]);
    }

    for (const ip of METADATA_IPS) {
        if (uLc.includes(ip)) {
            return new Detection("ssrf", "SUSPICIOUS", 9, "outbound request to instance metadata (possible SSRF)", ["ssrf", "metadata", ip]);
        }
    }

    const ipMatch = u.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
    if (ipMatch && isIpPrivate(ipMatch[1])) {
        return new Detection("ssrf", "SUSPICIOUS", 8, "outbound request to private IP (possible SSRF)", ["ssrf", "private ip", ipMatch[1]]);
    }

    return null;
}

function clampSeverity(sev) {
    let v = parseInt(sev, 10);
    if (isNaN(v)) v = 1;
    return Math.max(1, Math.min(10, v));
}

module.exports = { Detection, detectSqli, detectSsrf, clampSeverity };
