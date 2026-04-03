const { detectSqli, detectSsrf } = require('../src/detectors');

describe('Detector regex checks', () => {
    test('SQL Injection tautology detection', () => {
        const payload = "admin' OR 1=1 --";
        const result = detectSqli(payload);
        expect(result).not.toBeNull();
        expect(result.category).toBe("sql_injection");
        expect(result.indicators).toContain("tautology");
    });

    test('SQL Injection sleep detection', () => {
        const payload = "pg_sleep(10)";
        const result = detectSqli(payload);
        expect(result).not.toBeNull();
        expect(result.indicators).toContain("sleep");
    });

    test('SSRF localhost detection', () => {
        const payload = "http://127.0.0.1/admin";
        const result = detectSsrf(payload);
        expect(result).not.toBeNull();
        expect(result.category).toBe("ssrf");
    });

    test('SSRF metadata detection', () => {
        const payload = "http://169.254.169.254/latest/meta-data/";
        const result = detectSsrf(payload);
        expect(result).not.toBeNull();
        expect(result.indicators).toContain("metadata");
    });

    test('Safe URL is not flagged', () => {
        const payload = "https://google.com";
        const result = detectSsrf(payload);
        expect(result).toBeNull();
    });
});
