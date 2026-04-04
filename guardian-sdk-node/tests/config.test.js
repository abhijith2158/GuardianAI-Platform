const { GuardianConfig } = require('../src/config');

describe('GuardianConfig ingest URL normalization', () => {
    const previousEnv = process.env.GUARDIAN_INGEST_URL;

    afterEach(() => {
        if (previousEnv === undefined) {
            delete process.env.GUARDIAN_INGEST_URL;
        } else {
            process.env.GUARDIAN_INGEST_URL = previousEnv;
        }
    });

    test('appends /v1/telemetry to a base URL', () => {
        process.env.GUARDIAN_INGEST_URL = 'https://api.example.com/';

        const config = GuardianConfig.fromEnv();

        expect(config.ingestUrl).toBe('https://api.example.com/v1/telemetry');
    });

    test('preserves an explicit telemetry endpoint', () => {
        process.env.GUARDIAN_INGEST_URL = 'https://api.example.com/v1/telemetry/';

        const config = GuardianConfig.fromEnv();

        expect(config.ingestUrl).toBe('https://api.example.com/v1/telemetry');
    });
});
