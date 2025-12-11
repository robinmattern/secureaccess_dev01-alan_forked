import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';

const app = express();
const PORT = 3000;
const ORIGINS_FILE = './allowed-origins.json';

app.use(express.json());

// Load origins from file
let allowedOrigins = [];
try {
  const data = await fs.readFile(ORIGINS_FILE, 'utf8');
  allowedOrigins = JSON.parse(data);
} catch {
  allowedOrigins = ['http://localhost:3000'];
  await saveOrigins();
}

async function saveOrigins() {
  await fs.writeFile(ORIGINS_FILE, JSON.stringify(allowedOrigins, null, 2));
}

// Dynamic CORS
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));

// API endpoints
app.get('/origins', (req, res) => {
  res.json({ allowedOrigins });
});

app.post('/origins', async (req, res) => {
  const { origin } = req.body;
  if (!allowedOrigins.includes(origin)) {
    allowedOrigins.push(origin);
    await saveOrigins();
  }
  res.json({ allowedOrigins });
});

app.delete('/origins', async (req, res) => {
  const { origin } = req.body;
  allowedOrigins = allowedOrigins.filter(o => o !== origin);
  await saveOrigins();
  res.json({ allowedOrigins });
});

app.get('/test', (req, res) => {
  res.json({ message: 'CORS test successful', origin: req.headers.origin });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Allowed origins: ${allowedOrigins.join(', ')}`);
});