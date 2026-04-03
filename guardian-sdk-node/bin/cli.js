#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const command = process.argv[2];

if (command === 'init') {
    console.log('Initializing GuardianAI Security...');

    const hookSource = path.join(__dirname, '../lib/templates/pre-commit');
    const hookDest = path.join(process.cwd(), '.git/hooks/pre-commit');

    if (fs.existsSync(hookSource) && fs.existsSync(path.dirname(hookDest))) {
        fs.copyFileSync(hookSource, hookDest);
        fs.chmodSync(hookDest, '755');
        console.log('Git pre-commit hook installed.');
    } else {
        console.log('Skipped git hook install because no git hooks directory was found.');
    }

    const workflowDir = path.join(process.cwd(), '.github/workflows');
    if (!fs.existsSync(workflowDir)) {
        fs.mkdirSync(workflowDir, { recursive: true });
    }

    console.log('GitHub Security Audit workflow directory prepared.');
} else {
    console.log('Usage: guardian-cli init');
}
