// Only load .env in development - Render provides env vars directly  
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
} else {
  // In production, variables are provided by Render directly
  console.log('🏭 Running in production mode - using Render environment variables');
}

// Validate required environment variables
const REQUIRED_ENV = ['GHL_LOCATION_ID', 'GHL_CLIENT_ID', 'GHL_CLIENT_SECRET'];
REQUIRED_ENV.forEach(v => {
  if (!process.env[v]) { 
    console.error(`❌ Missing required environment variable: ${v}`); 
    process.exit(1); 
  }
});

// Only log sensitive info in development
if (process.env.NODE_ENV !== 'production') {
  console.log('Client ID:', process.env.GHL_CLIENT_ID?.substring(0, 8) + '...');
  console.log('Refresh Token exists:', !!process.env.GHL_REFRESH_TOKEN);
}

const express = require('express');
const axios = require('axios');
const nodemailer = require('nodemailer');
const app = express();
const { getValidAccessToken } = require('./tokens');


// ---------------- Email Configuration ----------------
let transporter = null;

function initializeEmailTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log('⚠️ Email configuration missing, email alerts will be disabled');
    return;
  }

  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    },
    // Additional options for better reliability
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    rateDelta: 1000,
    rateLimit: 10
  });

  // Verify the transporter configuration
  transporter.verify((error, success) => {
    if (error) {
      console.error('❌ Email transporter verification failed:', error);
      transporter = null;
    } else {
      console.log('✅ Email transporter ready');
    }
  });
}

// Initialize email on startup
initializeEmailTransporter();

// ---------------- Request Logging Middleware ----------------
app.use((req, res, next) => {
  const start = Date.now();
  const originalSend = res.send;
  
  // Override res.send to capture response
  res.send = function(data) {
    const duration = Date.now() - start;
    const bodyHash = req.body ? require('crypto').createHash('md5').update(JSON.stringify(req.body)).digest('hex').substring(0, 8) : 'none';
    
    // Smart logging: Always log API calls, only log health checks if slow/failed
    const shouldLog = req.path !== '/health' && req.path !== '/' || // Always log non-health
                     res.statusCode >= 400 ||                        // Always log errors
                     duration > 1000;                                // Always log slow requests (>1s)
    
    if (shouldLog) {
      const logLevel = res.statusCode >= 400 ? '🚨' : duration > 500 ? '⚠️' : '📊';
      console.log(`${logLevel} ${req.method} ${req.path} ${res.statusCode} ${duration}ms [body:${bodyHash}] [ip:${req.ip}]`);
    }
    
    // Call original send
    originalSend.call(this, data);
  };
  
  next();
});

// ---------------- Rate Limiting ----------------
const rateLimitStore = new Map();

function rateLimit(windowMs = 15 * 60 * 1000, maxRequests = 100) {
  return (req, res, next) => {
    const clientId = req.ip || 'unknown';
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Clean old entries
    for (const [key, timestamps] of rateLimitStore.entries()) {
      rateLimitStore.set(key, timestamps.filter(t => t > windowStart));
      if (rateLimitStore.get(key).length === 0) {
        rateLimitStore.delete(key);
      }
    }
    
    // Get current requests for this client
    const clientRequests = rateLimitStore.get(clientId) || [];
    const recentRequests = clientRequests.filter(t => t > windowStart);
    
    if (recentRequests.length >= maxRequests) {
      console.log(`🚫 Rate limit exceeded for ${clientId}: ${recentRequests.length}/${maxRequests} requests`);
      return res.status(429).json({ 
        error: 'Too many requests', 
        retryAfter: Math.ceil(windowMs / 1000),
        limit: maxRequests,
        windowMs
      });
    }
    
    // Add current request
    recentRequests.push(now);
    rateLimitStore.set(clientId, recentRequests);
    
    // Add headers
    res.set({
      'X-RateLimit-Limit': maxRequests,
      'X-RateLimit-Remaining': Math.max(0, maxRequests - recentRequests.length),
      'X-RateLimit-Reset': new Date(now + windowMs).toISOString()
    });
    
    next();
  };
}

// Apply rate limiting to API routes (exclude health checks)
app.use('/api/', rateLimit(15 * 60 * 1000, 100)); // 100 requests per 15 minutes

// Add support for both JSON and form-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const POLL_MS = parseInt(process.env.POLL_INTERVAL_MS, 10) || 300000;

// ---------------- ENV Variables ----------------
const {
  GHL_LOCATION_ID,
  GHL_CLIENT_ID,
  GHL_CLIENT_SECRET,
  GHL_REDIRECT_URI,
  GHL_ACCESS_TOKEN,
  GHL_REFRESH_TOKEN,
  LENDINGDOX_CUSTOMER_ID,
  LENDINGDOX_USER_ID,
  DEFAULT_PIPELINE_ID,
  DEFAULT_STAGE_ID,
  POLL_INTERVAL_MS
} = process.env;


// ---------------- Enhanced GHL Request with Retry Logic ----------------
async function ghlRequestWithRetry(method, url, body, params, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await ghlRequest(method, url, body, params);
    } catch (error) {
      const isRetryable = error?.response?.status >= 500 || // Server errors
                         error?.response?.status === 429 || // Rate limit
                         error.code === 'ECONNRESET' ||     // Connection issues
                         error.code === 'ETIMEDOUT';        // Timeout

      if (attempt === maxRetries || !isRetryable) {
        console.error(`❌ GHL request failed after ${attempt} attempts:`, {
          method,
          url,
          status: error?.response?.status,
          error: error?.response?.data || error.message
        });
        throw error;
      }

      const delay = Math.pow(2, attempt) * 1000; // Exponential backoff: 2s, 4s, 8s
      console.log(`🔄 Retry ${attempt}/${maxRetries} for ${method} ${url} after ${delay}ms (Status: ${error?.response?.status})`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

async function ghlRequest(method, url, body, params) {
  const base = 'https://services.leadconnectorhq.com';
  
const accessToken = await getValidAccessToken();
const headers = {
  Authorization: `Bearer ${accessToken}`,
  Version: '2021-07-28',
  'Content-Type': 'application/json',
  Accept: 'application/json'
};
  
  try {
    const config = { method, url: `${base}${url}`, headers, timeout: 30000 }; // 30s timeout
    if (body) config.data = body;
    if (params) config.params = params;
    
    console.log('📤 Making GHL request:', {
      method,
      url: `${base}${url}`,
      data: body,
      params
    });
    
    const res = await axios(config);
    return res.data;
  } catch (err) {
  console.error('GHL Request Error:', {
    status: err.response?.status,
    statusText: err.response?.statusText,
    data: err.response?.data,
    url: `${base}${url}`,
    method,
    requestData: body
  });
  throw err;
  }
}

// ---------------- Email Alert System ----------------
async function sendAlert(subject, message) {
  // Check if email is configured and enabled
  if (!transporter || !process.env.ALERT_EMAIL_TO) {
    console.log('⚠️ Email alerts not configured, skipping alert:', subject);
    return;
  }

  try {
    const mailOptions = {
      from: `"GHL Integration Alert" <${process.env.SMTP_USER}>`,
      to: process.env.ALERT_EMAIL_TO,
      subject: `🚨 ${subject}`,
      text: message,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #d32f2f;">🚨 ${subject}</h2>
          <div style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
            <pre style="white-space: pre-wrap; font-family: monospace; font-size: 14px;">${message}</pre>
          </div>
          <hr style="margin: 20px 0;">
          <p style="color: #666; font-size: 12px;">
            <strong>Timestamp:</strong> ${new Date().toISOString()}<br>
            <strong>Server:</strong> ${process.env.APP_URL || 'Unknown'}<br>
            <strong>Environment:</strong> ${process.env.NODE_ENV || 'development'}
          </p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('📧 Alert email sent successfully:', info.messageId);
  } catch (error) {
    console.error('❌ Failed to send alert email:', error.message);
    
    // Try to reinitialize transporter if it failed
    if (error.code === 'EAUTH' || error.code === 'ECONNECTION') {
      console.log('🔄 Attempting to reinitialize email transporter...');
      initializeEmailTransporter();
    }
  }
}

// ---------------- Contact Helpers ----------------
async function findContactByEmail(email) {
  if (!email) return null;
  try {
    const data = await ghlRequestWithRetry('get', '/contacts/', null, { 
      query: email, 
      locationId: GHL_LOCATION_ID, 
      limit: 50 
    });
    const list = data?.contacts || data?.data || [];
    return list.find(c => (c.email || '').toLowerCase() === email.toLowerCase()) || null;
  } catch (error) {
    console.error('Error finding contact by email:', error.message);
    return null;
  }
}

async function createContact({ email, firstName, lastName, phone }) {
  const payload = { 
    locationId: GHL_LOCATION_ID, 
    email, 
    firstName, 
    lastName, 
    phone 
  };
  
  try {
    const data = await ghlRequestWithRetry('post', '/contacts/', payload);
    console.log('✅ Contact created:', data?.contact?.id || data?.id);
    return data?.contact || data;
  } catch (error) {
    console.error('Error creating contact:', error.response?.data || error.message);
    throw error;
  }
}

async function ensureContactByEmail({ email, firstName, lastName, phone }) {
  if (!email) {
    console.log('❌ No email provided for contact');
    return null;
  }
  
  // Skip search, try to create directly
  console.log('🆕 Attempting to create contact:', { email, firstName, lastName, phone });
  try {
    const created = await createContact({ email, firstName, lastName, phone });
    const contactId = created?.id || created?.contact?.id;
    
    if (!contactId) {
      console.error('❌ Contact creation failed - no ID returned:', created);
      return null;
    }
    
    console.log('✅ Contact created successfully:', contactId);
    return contactId;
  } catch (error) {
    // Check if the error is due to duplicate contact
    if (error.response?.data?.message?.includes('duplicated contacts') && 
        error.response?.data?.meta?.contactId) {
      const existingContactId = error.response.data.meta.contactId;
      console.log('✅ Contact already exists, using existing ID:', existingContactId);
      return existingContactId;
    }
    
    console.error('❌ Contact creation failed:', error.response?.data || error.message);
    return null;
  }
}

// ---------------- Opportunity Helpers ----------------
async function findOppByLoanId(loanId, pipelineId) {
  if (!loanId) return null;
  
  try {
    const data = await ghlRequestWithRetry('get', '/opportunities/', null, {
      pipelineId: pipelineId || DEFAULT_PIPELINE_ID,
      locationId: GHL_LOCATION_ID,
      limit: 100
    });
    
    const list = data?.opportunities || data?.data || [];
    return list.find(o => {
      const cf = o.customFields || {};
      if (Array.isArray(cf)) {
        return cf.some(f =>
          (f.key === 'loanId' || f.customFieldKey === 'loanId' || f.id === 'loanId') &&
          String(f.value) === String(loanId)
        );
      }
      if (typeof cf === 'object') return String(cf.loanId) === String(loanId);
      return false;
    }) || null;
  } catch (error) {
    console.error('Error finding opportunity by loan ID:', error.message);
    return null;
  }
}

function buildCustomFields(customFields, loanId) {
  console.log('🔧 buildCustomFields called with:', { customFields, loanId });
  
  const out = { ...(customFields || {}) };
  if (loanId) out.loanId = loanId;
  
  // Convert object to array format expected by GHL API
  const result = Object.entries(out).map(([key, value]) => ({
    key,
    field_value: String(value ?? '')
  }));
  
  console.log('🔧 buildCustomFields result:', result);
  return result;
}

function mapCreateOpportunity(payload) {
  const {
    loanId,
    name,
    value,
    contactId,
    pipelineId = DEFAULT_PIPELINE_ID,
    pipelineStageId = DEFAULT_STAGE_ID,  // FIXED: renamed parameter
    status = 'open',
    customFields
  } = payload;

  console.log('🔧 Mapping opportunity with pipelineStageId:', pipelineStageId);

  const opportunityData = {
    locationId: GHL_LOCATION_ID,
    name,
    pipelineId,
    pipelineStageId: pipelineStageId,  // FIXED: correct field name
    status,
    monetaryValue: value,
    contactId: contactId || undefined
  };

  const customFieldsArray = buildCustomFields(customFields, loanId);
  console.log('🔧 Custom fields array:', customFieldsArray);
  
  if (customFieldsArray && customFieldsArray.length > 0) {
    opportunityData.customFields = customFieldsArray;
  }

  console.log('🔧 Final opportunityData:', JSON.stringify(opportunityData, null, 2));
  return opportunityData;
}

function mapUpdateOpportunity(payload) {
  const { loanId, name, value, contactId, status, customFields } = payload;
  const body = {
    ...(name ? { name } : {}),
    ...(value != null ? { monetaryValue: value } : {}),
    ...(contactId ? { contactId } : {}),
    ...(status ? { status } : {})
  };
  
  const customFieldsArray = buildCustomFields(customFields, loanId);
  if (customFieldsArray && customFieldsArray.length > 0) {
    body.customFields = customFieldsArray;
  }
  
  return body;
}

// ---------------- Core Business Logic ----------------
async function upsertOpportunityFromPayload(payload) {
  const {
    loanId, name, value, contactEmail, contactFirstName, contactLastName, contactPhone,
    pipelineId, pipelineStageId, status, customFields
  } = payload || {};

  if (!contactEmail) throw new Error('contactEmail is required for opportunity upsert');

  // Step 1: Ensure contact exists
  console.log('👤 Ensuring contact exists for:', contactEmail);
  const contactId = await ensureContactByEmail({
    email: contactEmail, 
    firstName: contactFirstName, 
    lastName: contactLastName, 
    phone: contactPhone
  });
  
  if (!contactId) throw new Error('Failed to create/find contact. Contact ID is required for opportunities.');
  console.log('✅ Contact ID obtained:', contactId);

  // Step 2: Build opportunity payload
  const opportunityPayload = {
    contactId,
    locationId: GHL_LOCATION_ID,
    pipelineId: pipelineId || DEFAULT_PIPELINE_ID,
    monetaryValue: typeof value === 'number' ? value : (value ? parseInt(value, 10) : 100000),
    ...(name && { name }),
    ...(pipelineStageId && { pipelineStageId }),
    ...(status && { status })
  };

  // Add custom fields if provided
  const customFieldsArray = buildCustomFields(customFields, loanId);
  if (customFieldsArray?.length) opportunityPayload.customFields = customFieldsArray;

  console.log('🏗️ Upserting opportunity with payload:', JSON.stringify(opportunityPayload, null, 2));

  // Step 3: Try upsert, fallback to create (WITH RETRY LOGIC)
  try {
    const result = await ghlRequestWithRetry('post', '/opportunities/upsert', opportunityPayload);
    console.log('✅ Opportunity upserted successfully:', result?.opportunity?.id || result?.id);
    return result;
  } catch (upsertError) {
    console.log('⚠️ Upsert failed, trying create endpoint...');
    const result = await ghlRequestWithRetry('post', '/opportunities/', opportunityPayload);
    console.log('✅ Opportunity created successfully:', result?.opportunity?.id || result?.id);
    return result;
  }
}

async function updateOpportunity(id, body) {
  try {
    console.log('🔄 Updating opportunity:', id, 'with:', JSON.stringify(body, null, 2));
    const result = await ghlRequestWithRetry('put', `/opportunities/${id}`, body);
    console.log('✅ Opportunity updated:', id);
    return result;
  } catch (error) {
    console.error('Error updating opportunity:', error.response?.data || error.message);
    throw error;
  }
}

// ---------------- API Key Middleware ----------------
function requireApiKey(req, res, next) {
  if (process.env.INTERNAL_API_KEY && req.get('X-API-Key') !== process.env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }
  next();
}

// ---------------- Routes ----------------
app.get('/', (_, res) => res.send('GHL-LendingDox Integration Server is Running!'));

app.post('/api/contact-upsert', requireApiKey, async (req, res) => {
  try {
    const { email, firstName, lastName, phone } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email is required' });
    
    const contactId = await ensureContactByEmail({ email, firstName, lastName, phone });
    if (!contactId) return res.status(500).json({ error: 'Failed to upsert contact' });
    
    res.json({ contactId });
  } catch (e) {
    console.error('contact-upsert error:', e?.response?.data || e.message);
    res.status(500).json({ error: e?.response?.data || e.message });
  }
});

app.post('/api/opportunity', requireApiKey, async (req, res) => {
  try {
    console.log('📨 Received opportunity request:', JSON.stringify(req.body, null, 2));
    
    const result = await upsertOpportunityFromPayload(req.body);
    res.json({ success: true, action: 'upserted', data: result });
  } catch (e) {
    console.error('❌ API error:', e?.response?.data || e.message);
    res.status(400).json({ error: e?.response?.data || e.message });
  }
});

// ---------------- Manual Trigger Route (for testing) ----------------
app.post('/api/trigger-poll', requireApiKey, async (req, res) => {
  try {
    console.log('🔥 Manual poll triggered via API');
    
    // Override the minutes parameter if provided
    const minutes = req.body.minutes || 15;
    console.log(`🕐 Looking back ${minutes} minutes`);
    
    const params = { 
      CustomerID: LENDINGDOX_CUSTOMER_ID, 
      UserID: LENDINGDOX_USER_ID, 
      Minutes: minutes 
    };
    
    const response = await axios.get('https://www.lendingdoxapi.com/api/Loans/GetLoanChanges/', { params });
    const loanChanges = response.data;
    const loanCount = Array.isArray(loanChanges?.loans) ? loanChanges.loans.length : 0;
    console.log(`📊 Manual poll - Loan changes received: ${loanCount}`);
    
    let processedLoans = 0;
    let skippedLoans = 0;
    const results = [];
    
    if (loanCount > 0) {
      for (const loan of loanChanges.loans || []) {
        // Skip loans without email
        if (!loan.borrower?.contacts?.email) {
          console.log(`⚠️ Skipping loan ${loan.loanId} - no borrower email`);
          skippedLoans++;
          results.push({
            loanId: loan.loanId,
            status: 'skipped',
            reason: 'No borrower email'
          });
          continue;
        }
        
        const payload = {
          loanId: loan.loanId,
          name: `Loan #${loan.loanNumber} – ${loan.borrower?.firstName} ${loan.borrower?.lastName}`.trim(),
          value: parseInt(loan.loanAmount) || 100000,
          
          // Extract from nested borrower object
          contactEmail: loan.borrower?.contacts?.email,
          contactFirstName: loan.borrower?.firstName,
          contactLastName: loan.borrower?.lastName,
          contactPhone: loan.borrower?.contacts?.mobilePhone || loan.borrower?.contacts?.homePhone || loan.borrower?.contacts?.workPhone,
          
          customFields: {
  loan_status: loan.loanStatus?.name,
  program: loan.program,
  apr: loan.apr || loan.APR,
  property_type: loan.propertyType?.name || loan.property_type?.name,
  occupancy: loan.occupancy?.name,
  purpose: loan.purpose?.name,
  loan_type: loan.loanType?.name

          }
        };
        
        try {
          const result = await upsertOpportunityFromPayload(payload);
          processedLoans++;
          console.log(`✅ Processed loan: ${payload.loanId}`);
          results.push({
            loanId: loan.loanId,
            loanNumber: loan.loanNumber,
            borrowerEmail: loan.borrower?.contacts?.email,
            status: 'processed',
            opportunityId: result?.opportunity?.id || result?.id
          });
        } catch (err) {
          console.error('❌ Error processing loan:', err.message);
          results.push({
            loanId: loan.loanId,
            status: 'error',
            error: err.message
          });
        }
      }
    }
    
    res.json({ 
      success: true, 
      summary: {
        loansFound: loanCount,
        loansProcessed: processedLoans,
        loansSkipped: skippedLoans,
        minutesBack: minutes
      },
      results: results,
      message: `Manual poll completed. Found ${loanCount} loans, processed ${processedLoans}, skipped ${skippedLoans}.`
    });
    
  } catch (error) {
    console.error('❌ Manual poll error:', error.message);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      details: error.response?.data || 'Unknown error during manual poll'
    });
  }
});

// Test route for email alerts
app.post('/api/test-alert', requireApiKey, async (req, res) => {
  try {
    await sendAlert(
      'Test Alert', 
      'This is a test email from your GHL integration. If you receive this, email alerts are working correctly!\n\nTest details:\n- Server is running normally\n- Email configuration is working\n- Nodemailer is properly configured'
    );
    res.json({ success: true, message: 'Test alert sent' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ---------------- LendingDox Polling ----------------
async function pollLendingDox() {
  console.log('🔍 Polling LendingDox for loan changes...');
  const params = { 
    CustomerID: LENDINGDOX_CUSTOMER_ID, 
    UserID: LENDINGDOX_USER_ID, 
    Minutes: 15 
  };
  
  try {
    // Check if we have valid tokens before starting
    await getValidAccessToken();
    
    const response = await axios.get('https://www.lendingdoxapi.com/api/Loans/GetLoanChanges/', { params });
    const loanChanges = response.data;
    const loanCount = Array.isArray(loanChanges?.loans) ? loanChanges.loans.length : 0;
    console.log(`📊 Loan changes received: ${loanCount}`);
    
    if (loanCount > 0) {
      for (const loan of loanChanges.loans || []) {
        // Skip loans without email
        if (!loan.borrower?.contacts?.email) {
          console.log(`⚠️ Skipping loan ${loan.loanId} - no borrower email`);
          continue;
        }
        
        const payload = {
          loanId: loan.loanId,
          name: `Loan #${loan.loanNumber} – ${loan.borrower?.firstName} ${loan.borrower?.lastName}`.trim(),
          value: parseInt(loan.loanAmount) || 100000,
          
          // Extract from nested borrower object
          contactEmail: loan.borrower?.contacts?.email,
          contactFirstName: loan.borrower?.firstName,
          contactLastName: loan.borrower?.lastName,
          contactPhone: loan.borrower?.contacts?.mobilePhone || loan.borrower?.contacts?.homePhone || loan.borrower?.contacts?.workPhone,
          
          customFields: {
            loan_status: loan.loanStatus?.name,
            program: loan.program,
            apr: loan.apr || loan.APR,
            property_type: loan.propertyType?.name || loan.property_type?.name,
            occupancy: loan.occupancy?.name,
            purpose: loan.purpose?.name,
            loan_type: loan.loanType?.name
          }
        };
        
        try {
          // Call function directly with retry logic built-in
          await upsertOpportunityFromPayload(payload);
          console.log(`✅ Upserted opportunity for loanId: ${payload.loanId}`);
        } catch (err) {
          console.error('❌ Error upserting opportunity:', err.message);
        }
      }
    }
  } catch (error) {
    console.error('❌ Error polling LendingDox:', error.message);
    
    // If it's a token error, send alert and skip this poll
    if (error.message.includes('tokens')) {
      console.log('⚠️ Token issue detected, skipping this poll cycle');
      await sendAlert('Polling Token Error', `Polling failed due to token issue: ${error.message}\n\nPlease check token status at /auth/status`);
    }
  }
}

// Only start polling if enabled
// Only start polling if enabled
if (process.env.ENABLE_POLL === 'true') {
  // Wait 5 seconds for database to initialize
  setTimeout(() => {
    pollLendingDox();
    setInterval(pollLendingDox, POLL_MS);
  }, 5000);
}

// ---------------- OAuth Routes ----------------
app.get('/auth/callback', (req, res) => {
  // Redirect to your actual OAuth handler with all query parameters
  const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
  res.redirect(`/oauth/callback${queryString}`);
});
app.get('/debug/tokens', requireApiKey, async (req, res) => {
  try {
    const token = await getValidAccessToken();
    res.json({
      accessToken: token ? 'Present' : 'Missing',
      tokenLength: token ? token.length : 0,
      status: 'Using database storage'
    });
  } catch (error) {
    res.json({
      accessToken: 'Error',
      error: error.message
    });
  }
});

app.get('/auth/ghl', (req, res) => {
  const redirectUri = GHL_REDIRECT_URI || `http://localhost:${PORT}/oauth/callback`;
  const scopes = 'contacts.write opportunities.write associations.write objects/record.write';
  const authUrl = `https://marketplace.gohighlevel.com/oauth/chooselocation?response_type=code&client_id=${encodeURIComponent(GHL_CLIENT_ID)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scopes)}`;
  res.redirect(authUrl);
});

app.get('/oauth/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Authorization code missing');
  }

  try {
    const tokenResponse = await axios.post(
      'https://services.leadconnectorhq.com/oauth/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: GHL_CLIENT_ID,
        client_secret: GHL_CLIENT_SECRET,
        redirect_uri: GHL_REDIRECT_URI || `http://localhost:${PORT}/oauth/callback`
      }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    
const { access_token, refresh_token } = tokenResponse.data;
// Save tokens to database using our new system
const { saveTokens } = require('./tokens');
await saveTokens(access_token, refresh_token, 3600); // 1 hour default    
    console.log('✅ OAuth Success');
    
    // Only log tokens in development
if (process.env.NODE_ENV !== 'production') {
  console.log('Tokens saved to database successfully');
}
    
    res.send(`
      <h1>OAuth Successful!</h1>
      <p>Tokens received and logged to terminal.</p>
      <p>Make sure to update your .env file with the new tokens.</p>
      <p><a href="/">Back to Home</a></p>
    `);
  } catch (error) {
    console.error('OAuth Error:', error.response?.data || error.message);
    res.status(500).send(`OAuth failed: ${error.response?.data?.error_description || error.message}`);
  }
});

// ---------------- Health Check Route ----------------
app.get('/health', async (req, res) => {
  let tokenStatus = { hasAccessToken: false, hasRefreshToken: false, error: null };
  
  try {
    const token = await getValidAccessToken();
    tokenStatus.hasAccessToken = !!token;
    tokenStatus.hasRefreshToken = true; // If getValidAccessToken() succeeds, refresh token is working
  } catch (error) {
    tokenStatus.error = error.message;
  }
  
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    hasAccessToken: tokenStatus.hasAccessToken,
    hasRefreshToken: tokenStatus.hasRefreshToken,
    tokenError: tokenStatus.error,
    locationId: GHL_LOCATION_ID,
    pollingEnabled: process.env.ENABLE_POLL === 'true',
    emailConfigured: !!transporter && !!process.env.ALERT_EMAIL_TO,
    version: '1.0.0'
  });
});

// ---------------- Error Handling ----------------
process.on('uncaughtException', err => {
  console.error('💥 Uncaught Exception:', err);
  sendAlert('Server Error - Uncaught Exception', `An uncaught exception occurred:\n\n${err.stack}`);
});

process.on('unhandledRejection', reason => {
  console.error('💥 Unhandled Rejection:', reason);
  sendAlert('Server Error - Unhandled Rejection', `An unhandled promise rejection occurred:\n\n${reason}`);
});

// ---------------- Start Server ----------------
// ---------------- Start Server ----------------
const server = app.listen(PORT, () => {
  console.log(`🚀 Server listening on port ${PORT}`);
  console.log(`📍 Location ID: ${GHL_LOCATION_ID}`);
  console.log(`🔑 Token System: Database Storage`);
  console.log(`🔄 Polling Enabled: ${process.env.ENABLE_POLL === 'true'}`);
  if (process.env.ENABLE_POLL === 'true') {
    console.log(`🔄 Polling Interval: ${POLL_MS}ms`);
  }
  console.log(`🔒 API Key Protection: ${!!process.env.INTERNAL_API_KEY}`);
  console.log(`📧 Email Alerts: ${!!transporter && !!process.env.ALERT_EMAIL_TO ? 'Enabled' : 'Disabled'}`);
});// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed');
    process.exit(0);
  });
});
// - change for change 3