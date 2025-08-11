const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

// Function to get persistent database path
function getDatabasePath() {
  if (process.env.NODE_ENV === 'production') {
    // Try persistent paths in order of preference
    const persistentPaths = [
      process.env.PERSISTENT_STORAGE_PATH && path.join(process.env.PERSISTENT_STORAGE_PATH, 'tokens.db'),
      '/data/tokens.db',
      '/app/data/tokens.db',
      '/var/lib/app/tokens.db'
    ].filter(Boolean);

    // Check if any persistent path is writable
    for (const dbPath of persistentPaths) {
      try {
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        // Test write access
        fs.writeFileSync(path.join(dir, 'test-write'), 'test');
        fs.unlinkSync(path.join(dir, 'test-write'));
        console.log(`✅ Using persistent storage: ${dbPath}`);
        return dbPath;
      } catch (error) {
        console.log(`⚠️ Cannot use ${dbPath}: ${error.message}`);
      }
    }
    
    // Fallback with warning
    console.warn('⚠️ WARNING: No persistent storage available, tokens will be lost on restart!');
    console.warn('⚠️ Set PERSISTENT_STORAGE_PATH environment variable for persistent tokens');
    return '/tmp/tokens.db';
  }
  
  // Development
  return path.join(__dirname, 'tokens.db');
}

const db = new sqlite3.Database(getDatabasePath());
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
  
  if (!tokens || !tokens.refresh_token) {
    throw new Error('No tokens found. Please complete OAuth flow first at /auth/ghl');
  }
  
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
      refresh_token: tokens.refresh_token
    })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    if (response.status === 400 || response.status === 401) {
      throw new Error('Refresh token expired. Please re-authorize at /auth/ghl');
    }
    throw new Error(`Token refresh failed: ${data.error || 'Unknown error'}`);
  }
  
  // Save the new tokens
  await saveTokens(
    data.access_token, 
    data.refresh_token || tokens.refresh_token,
    data.expires_in
  );
  
  console.log('✅ Token refreshed successfully');
  return data.access_token;
}

module.exports = { getValidAccessToken, saveTokens };