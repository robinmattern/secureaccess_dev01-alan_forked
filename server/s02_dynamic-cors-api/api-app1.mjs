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

// API endpoints
app.get('/users', (req, res) => {
  res.json({ message: 'Users from APIapp1', data: ['user1', 'user2'] });
});

app.get('/orders', (req, res) => {
  res.json({ message: 'Orders from APIapp1', data: ['order1', 'order2'] });
});

app.listen(PORT, () => {
  console.log(`APIapp1 running on http://localhost:${PORT}`);
});