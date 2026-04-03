const { detectSqli, detectSsrf } = require('./src/detectors');

// Test 1: Tautology
const r1 = detectSqli("admin' OR 1=1 --");
console.log("Test1 tautology:", r1 ? "PASS" : "FAIL", JSON.stringify(r1));

// Test 2: Sleep
const r2 = detectSqli("pg_sleep(10)");
console.log("Test2 sleep:", r2 ? "PASS" : "FAIL", JSON.stringify(r2));

// Test 3: SSRF localhost
const r3 = detectSsrf("http://127.0.0.1/admin");
console.log("Test3 ssrf:", r3 ? "PASS" : "FAIL", JSON.stringify(r3));

// Test 4: Safe URL
const r4 = detectSsrf("https://google.com");
console.log("Test4 safe:", r4 === null ? "PASS" : "FAIL");

// Test 5: Variant tautology
const r5 = detectSqli("' OR 'a'='a'");
console.log("Test5 variant:", r5 ? "PASS" : "FAIL", JSON.stringify(r5));

console.log("\nAll quick tests done.");
