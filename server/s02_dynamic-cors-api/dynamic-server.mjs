import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';

const app = express();
const PORT = 3000;
const CORS_DB = './cors-database.json';

app.use(express.json());

// CORS Database operations
class CorsDB {
  static async load() {
    try {
      const data = await fs.readFile(CORS_DB, 'utf8');
      return JSON.parse(data);
    } catch {
      return { allowedOrigins: ['http://localhost:3000'] };
    }
  }

  static async save(data) {
    await fs.writeFile(CORS_DB, JSON.stringify(data, null, 2));
  }

  static async addOrigin(origin) {
    const db = await this.load();
    if (!db.allowedOrigins.includes(origin)) {
      db.allowedOrigins.push(origin);
      await this.save(db);
    }
    return db.allowedOrigins;
  }

  static async removeOrigin(origin) {
    const db = await this.load();
    db.allowedOrigins = db.allowedOrigins.filter(o => o !== origin);
    await this.save(db);
    return db.allowedOrigins;
  }
}

// Dynamic CORS middleware
app.use(cors({
  origin: async (origin, callback) => {
    const db = await CorsDB.load();
    const allowed = !origin || db.allowedOrigins.includes(origin);
    callback(null, allowed);
  },
  credentials: true
}));

// CSRF protection middleware
function csrfProtection(req, res, next) {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  
  const token = req.headers['x-requested-with'];
  if (!token || token !== 'XMLHttpRequest') {
    return res.status(403).json({ error: 'Invalid request' });
  }
  
  next();
}

// CORS management API
app.get('/cors/origins', async (req, res) => {
  const db = await CorsDB.load();
  res.json(db);
});

app.post('/cors/origins', csrfProtection, async (req, res) => {
  const origins = await CorsDB.addOrigin(req.body.origin);
  res.json({ allowedOrigins: origins });
});

app.delete('/cors/origins', csrfProtection, async (req, res) => {
  const origins = await CorsDB.removeOrigin(req.body.origin);
  res.json({ allowedOrigins: origins });
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'Dynamic CORS working',
    requestOrigin: req.headers.origin,
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`Dynamic CORS API running on http://localhost:${PORT}`);
});