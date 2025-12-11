import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import crypto from 'crypto';

const app = express();
const PORT = 3000;
const REGISTRY_FILE = './api-registry.json';

app.use(express.json());

class APIRegistry {
  static async load() {
    const data = await fs.readFile(REGISTRY_FILE, 'utf8');
    return JSON.parse(data);
  }

  static async save(registry) {
    await fs.writeFile(REGISTRY_FILE, JSON.stringify(registry, null, 2));
  }

  static async validateAccess(apiKey, origin, apiApp) {
    const registry = await this.load();
    const user = Object.values(registry.users).find(u => u.apiKey === apiKey);
    
    return user?.active && 
           user.allowedOrigins.includes(origin) && 
           user.allowedApis.includes(apiApp);
  }
}

// Dynamic CORS middleware
app.use(cors({
  origin: async (origin, callback) => {
    const apiKey = callback.req?.headers['x-api-key'];
    const apiApp = callback.req?.headers['x-api-app'];
    
    if (!origin || !apiKey || !apiApp) {
      return callback(null, false);
    }

    const allowed = await APIRegistry.validateAccess(apiKey, origin, apiApp);
    callback(null, allowed);
  }
}));

// User registration
app.post('/register', async (req, res) => {
  const { userId, allowedOrigins, allowedApis } = req.body;
  const registry = await APIRegistry.load();
  
  const apiKey = `key_${crypto.randomBytes(16).toString('hex')}`;
  
  registry.users[userId] = {
    apiKey,
    allowedOrigins,
    allowedApis,
    active: true
  };
  
  await APIRegistry.save(registry);
  res.json({ userId, apiKey });
});

// Add origin to existing user
app.post('/users/:userId/origins', async (req, res) => {
  const { userId } = req.params;
  const { origin } = req.body;
  const registry = await APIRegistry.load();
  
  if (registry.users[userId]) {
    registry.users[userId].allowedOrigins.push(origin);
    await APIRegistry.save(registry);
  }
  
  res.json(registry.users[userId]);
});

// Validation endpoint for API apps
app.get('/validate', async (req, res) => {
  const { origin, 'x-api-key': apiKey, 'x-api-app': apiApp } = req.headers;
  const allowed = await APIRegistry.validateAccess(apiKey, origin, apiApp);
  res.json({ allowed });
});

app.listen(PORT, () => {
  console.log(`API Gateway running on http://localhost:${PORT}`);
});