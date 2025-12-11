  import   express from 'express';
  import   cors    from 'cors';
  import   fs      from 'fs/promises';
  import   crypto  from 'crypto';
  import   path    from 'path';
  import { initFVARS } from './setFVARS.mjs';

// Initialize FVARS
  const pFVARS          = initFVARS( 57353, 57303 );

  const SERVER_PORT     = pFVARS.SERVER_PORT     
  const SERVER_API_URL  = pFVARS.SERVER_API_URL || `http://localhost:${SERVER_PORT}/api`;
  const CORS_ORIGINS    = pFVARS.CORS_ORIGINS

  const REGISTRY_FILE   = path.join( pFVARS.DATA_PATH, 'api-registry.json');

        console.log( '  Server starting on port:', PORT);
        console.log( '  Registry file:          ', REGISTRY_FILE);
        console.log( "  CORS_Origins:           ", CORS_ORIGINS.join('\n     '))
process.exit() 
  const app   =  express();
        app.use( express.json() );
        app.use( cors({ origin: CORS_ORIGINS }));

class APIRegistry {
  static async load() {
    try {
      console.log('Trying to read:', REGISTRY_FILE);
      const data = await fs.readFile(REGISTRY_FILE, 'utf8');
      console.log('File loaded successfully');
      return JSON.parse(data);
    } catch (error) {
      console.log('File read error:', error.message);
      return { users: {}, apiApps: {} };
    }
  }

  static async save(registry) {
    console.log('Saving to:', REGISTRY_FILE);
    await fs.writeFile(REGISTRY_FILE, JSON.stringify(registry, null, 2));
  }
}

// Register new user with API key
app.post('/api/register', async (req, res) => {
  const { userId, allowedOrigins, allowedApis } = req.body;
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
app.get('/api/users', async (req, res) => {
  const registry = await APIRegistry.load();
  res.json(registry.users);
});

// Update user origins
app.put('/api/users/:userId/origins', async (req, res) => {
  const { userId } = req.params;
  const { origins } = req.body;
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
app.delete('/api/users/:userId', async (req, res) => {
  const { userId } = req.params;
  const registry = await APIRegistry.load();
  
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
  
  const registry = await APIRegistry.load();
  console.log('Available API keys:', Object.values(registry.users).map(u => u.apiKey));
  const user = Object.values(registry.users).find(u => u.apiKey === apiKey);
  
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
app.listen(PORT, () => {
  console.log(`CORS Registration API running on ${SERVER_API_URL}`);
});