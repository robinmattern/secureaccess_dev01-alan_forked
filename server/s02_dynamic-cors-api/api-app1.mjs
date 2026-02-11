import express from 'express';
import cors from 'cors';

const app = express();
const PORT = 3001;
const GATEWAY_URL = 'http://localhost:3000';

app.use(express.json());

// CORS middleware that checks with gateway
app.use(cors({
  origin: async (origin, callback) => {
    const apiKey = callback.req?.headers['x-api-key'];
    
    if (!origin || !apiKey) return callback(null, false);
    
    try {
      const response = await fetch(`${GATEWAY_URL}/validate`, {
        headers: {
          'origin': origin,
          'x-api-key': apiKey,
          'x-api-app': 'APIapp1'
        }
      });
      const { allowed } = await response.json();
      callback(null, allowed);
    } catch {
      callback(null, false);
    }
  }
}));

// Authentication middleware
async function requireAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const origin = req.headers['origin'];
  
  if (!apiKey || !origin) {
    return res.status(401).json({ error: 'Missing authentication' });
  }
  
  try {
    const response = await fetch(`${GATEWAY_URL}/validate`, {
      headers: {
        'origin': origin,
        'x-api-key': apiKey,
        'x-api-app': 'APIapp1'
      }
    });
    const { allowed } = await response.json();
    
    if (!allowed) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    
    next();
  } catch {
    return res.status(500).json({ error: 'Authentication failed' });
  }
}

// API endpoints
app.get('/users', requireAuth, (req, res) => {
  res.json({ message: 'Users from APIapp1', data: ['user1', 'user2'] });
});

app.get('/orders', requireAuth, (req, res) => {
  res.json({ message: 'Orders from APIapp1', data: ['order1', 'order2'] });
});

app.listen(PORT, () => {
  console.log(`APIapp1 running on http://localhost:${PORT}`);
});