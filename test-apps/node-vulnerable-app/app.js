const express = require('express');
const guardian = require('guardian-sdk-node');
const path = require('path');

const app = express();

// 1. MUST parse the body first so the Guardian SDK can read it
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));

// 2. Enable GuardianAI middleware in 'block' mode
app.use(guardian.enable({
    serviceName: 'node-test-app',
    logPath: path.join(__dirname, '../../security.log'),
    mode: 'block'
}));

// 3. Define Routes last
app.get('/', (req, res) => {
    res.send('Vulnerable App Running');
});

// Vulnerable Login Route (SQLi target)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // Simulate raw query execution
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    res.json({ status: 'attempted', queryExecuted: query });
});

// Vulnerable Fetch Route (SSRF target)
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    // Simulate fetching the URL
    res.json({ status: 'fetching', targetUrl: url });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
