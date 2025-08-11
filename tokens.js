const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./tokens.db');

// Create the table when the app starts
db.run(`CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY,
  access_token TEXT,
  refresh_token TEXT,
  expires_at DATETIME,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

async function saveTokens(accessToken, refreshToken, expiresIn) {
  return new Promise((resolve, reject) => {
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    db.run(
      `INSERT OR REPLACE INTO tokens (id, access_token, refresh_token, expires_at) 
       VALUES (1, ?, ?, ?)`,
      [accessToken, refreshToken, expiresAt],
      (err) => err ? reject(err) : resolve()
    );
  });
}

async function getTokens() {
  return new Promise((resolve, reject) => {
    db.get(`SELECT * FROM tokens WHERE id = 1`, (err, row) => {
      err ? reject(err) : resolve(row);
    });
  });
}

async function getValidAccessToken() {
  const tokens = await getTokens();
  
  // If we have a token that expires more than 5 minutes from now, use it
  if (tokens && new Date(tokens.expires_at) > new Date(Date.now() + 5 * 60 * 1000)) {
    console.log('✅ Using existing token');
    return tokens.access_token;
  }
  
  console.log('🔄 Refreshing token...');
  
  // Refresh the token
  const response = await fetch('https://services.leadconnectorhq.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: process.env.GHL_CLIENT_ID,
      client_secret: process.env.GHL_CLIENT_SECRET,
      grant_type: 'refresh_token',
      refresh_token: tokens?.refresh_token || process.env.GHL_REFRESH_TOKEN
    })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(`Token refresh failed: ${data.error || 'Unknown error'}`);
  }
  
  // Save the new tokens
  await saveTokens(
    data.access_token, 
    data.refresh_token || tokens?.refresh_token,
    data.expires_in
  );
  
  console.log('✅ Token refreshed successfully');
  return data.access_token;
}

module.exports = { getValidAccessToken, saveTokens };