  import   express from 'express';
  import   cors    from 'cors';
  import   fs      from 'fs/promises';
  import   crypto  from 'crypto';
  import   path    from 'path';
  import   csrf    from 'csurf';
  import { initFVARS } from './setFVARS.mjs';

// Initialize FVARS
  const pFVARS          = initFVARS( 57353, 57303 );

  const SERVER_PORT     = pFVARS.SERVER_PORT     
  const SERVER_API_URL  = pFVARS.SERVER_API_URL || `http://localhost:${SERVER_PORT}/api`;
  const CORS_ORIGINS    = pFVARS.CORS_ORIGINS

  const REGISTRY_FILE   = path.join( pFVARS.DATA_PATH, 'api-registry.json');

        console.log( '  Server starting on port:', SERVER_PORT);
        console.log( '  Registry file:          ', REGISTRY_FILE);
        console.log( "  CORS_Origins:           ", CORS_ORIGINS.join('\n     '))

  const app   =  express();
        app.use( express.json() );
        app.use( cors({ origin: CORS_ORIGINS }));

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

class APIRegistry {
  static apiKeyIndex = new Map();
  
  static async load() {
    try {
      console.log('Trying to read:', REGISTRY_FILE);
      const data = await fs.readFile(REGISTRY_FILE, 'utf8');
      console.log('File loaded successfully');
      const registry = JSON.parse(data);
      
      // Build API key index for O(1) lookups
      this.apiKeyIndex.clear();
      for (const [userId, user] of Object.entries(registry.users || {})) {
        if (user.apiKey) {
          this.apiKeyIndex.set(user.apiKey, user);
        }
      }
      
      return registry;
    } catch (error) {
      console.log('File read error:', error.message);
      this.apiKeyIndex.clear();
      return { users: {}, apiApps: {} };
    }
  }

  static async save(registry) {
    try {
      console.log('Saving to:', REGISTRY_FILE);
      await fs.writeFile(REGISTRY_FILE, JSON.stringify(registry, null, 2));
      
      // Update API key index
      this.apiKeyIndex.clear();
      for (const [userId, user] of Object.entries(registry.users || {})) {
        if (user.apiKey) {
          this.apiKeyIndex.set(user.apiKey, user);
        }
      }
    } catch (error) {
      console.error('Error saving registry:', error.message);
      throw error;
    }
  }
}

// Admin authentication middleware
const ADMIN_KEY = process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex');
if (!process.env.ADMIN_API_KEY) {
  console.warn('⚠️  ADMIN_API_KEY not set. Generated temporary key: ' + ADMIN_KEY.substring(0, 8) + '...');
}

function requireAdmin(req, res, next) {
  const adminKey = req.headers['x-admin-key'];
  if (!adminKey || adminKey.length !== ADMIN_KEY.length) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const match = crypto.timingSafeEqual(
    Buffer.from(adminKey),
    Buffer.from(ADMIN_KEY)
  );
  
  if (!match) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  next();
}

// Register new user with API key
app.post('/api/register', csrfProtection, requireAdmin, async (req, res) => {
  const { userId, allowedOrigins, allowedApis } = req.body;
  
  // Prevent prototype pollution
  if (!userId || typeof userId !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  
  const registry = await APIRegistry.load();
  
  const apiKey = `key_${crypto.randomBytes(16).toString('hex')}`;
  
  registry.users[userId] = {
    apiKey,
    allowedOrigins: allowedOrigins || [],
    allowedApis: allowedApis || [],
    active: true,
    createdAt: new Date().toISOString()
  };
  
  await APIRegistry.save(registry);
  res.json({ success: true, userId, apiKey });
});

// Get all users
app.get('/api/users', requireAdmin, async (req, res) => {
  const registry = await APIRegistry.load();
  res.json(registry.users);
});

// Update user origins
app.put('/api/users/:userId/origins', csrfProtection, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  const { origins } = req.body;
  
  // Prevent prototype pollution
  if (!userId || typeof userId !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  
  // Validate origins is an array
  if (!Array.isArray(origins)) {
    return res.status(400).json({ error: 'Origins must be an array' });
  }
  
  const registry = await APIRegistry.load();
  
  if (registry.users[userId]) {
    registry.users[userId].allowedOrigins = origins;
    await APIRegistry.save(registry);
    res.json({ success: true, user: registry.users[userId] });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Delete user
app.delete('/api/users/:userId', csrfProtection, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  
  // Prevent prototype pollution
  if (!userId || typeof userId !== 'string' || ['__proto__', 'constructor', 'prototype'].includes(userId)) {
    return res.status(400).json({ error: 'Invalid userId' });
  }
  
  const registry = await APIRegistry.load();
  
  if (!registry.users[userId]) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  delete registry.users[userId];
  await APIRegistry.save(registry);
  res.json({ success: true });
});

// Validate API key and origin
app.get('/api/validate', async (req, res) => {
  const origin = req.headers.origin;
  const apiKey = req.headers['x-api-key'];
  const appId  = req.query.appId;
  
  if (!origin || !apiKey || !appId) {
    return res.status(400).json({ 
      valid: false, 
      error: 'Missing origin, x-api-key header, or appId query parameter' 
    });
  }
  
  await APIRegistry.load();
  
  // Use O(1) index lookup instead of O(n) linear search
  const user = APIRegistry.apiKeyIndex.get(apiKey);
  
  if (!user || !user.active) {
    return res.json({ valid: false, error: 'Invalid or inactive API key' });
  }
  
  const originAllowed = user.allowedOrigins.includes(origin);
  const appAllowed = user.allowedApis.includes(appId);
  
  res.json({ 
    valid: originAllowed && appAllowed,
    origin: originAllowed,
    app: appAllowed,
    user: user.apiKey.substring(0, 8) + '...' 
  });
});
/*
app.get('*', async (req, res) => {
  res.send( `<br>Use http://localhost:${PORT}/api` )
});
*/
app.listen(SERVER_PORT, () => {
  console.log(`CORS Registration API running on ${SERVER_API_URL}`);
});