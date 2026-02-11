import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import crypto from 'crypto';
import csrf from 'csurf';

const app = express();
const PORT = 3000;
const REGISTRY_FILE = './api-registry.json';

app.use(express.json());

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']
});

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
    let user = null;
    for (const u of Object.values(registry.users)) {
      if (u.apiKey && apiKey && u.apiKey.length === apiKey.length) {
        const match = crypto.timingSafeEqual(
          Buffer.from(u.apiKey),
          Buffer.from(apiKey)
        );
        if (match) {
          user = u;
          break;
        }
      }
    }
    
    return user?.active && 
           user.allowedOrigins.includes(origin) && 
           user.allowedApis.includes(apiApp);
  }
}

// Admin authentication middleware
const ADMIN_KEY = process.env.ADMIN_API_KEY || crypto.randomBytes(32).toString('hex');
if (!process.env.ADMIN_API_KEY) {
  console.warn('⚠️  ADMIN_API_KEY not set. Generated temporary key:', ADMIN_KEY);
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
app.post('/register', csrfProtection, requireAdmin, async (req, res) => {
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
app.post('/users/:userId/origins', csrfProtection, requireAdmin, async (req, res) => {
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