require('dotenv').config();
const express = require('express');
const { Pool } = require('pg'); // Using PostgreSQL
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(express.json()); // Middleware for JSON parsing

// PostgreSQL Database connection setup using Render's DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Required for Render-hosted PostgreSQL
});

// Test the connection to PostgreSQL
pool.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch(err => console.error('Database connection error:', err));

// Function to create tables if they don't exist
const createTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS items (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Tables ensured to exist");
  } catch (error) {
    console.error("❌ Error creating tables:", error);
  }
};
createTables(); // Ensure tables exist on startup

// Rate Limiting Middleware
const rateLimit = {};
const RATE_LIMIT = 100; // Max allowed requests per IP
const WINDOW_MS = 15 * 60 * 1000; // 15-minute window

function rateLimiter(req, res, next) {
  const ip = req.ip;
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 0, timestamp: Date.now() };
  }
  const timeElapsed = Date.now() - rateLimit[ip].timestamp;
  if (timeElapsed > WINDOW_MS) {
    rateLimit[ip] = { count: 1, timestamp: Date.now() };
    return next();
  }
  if (rateLimit[ip].count < RATE_LIMIT) {
    rateLimit[ip].count++;
    return next();
  }
  res.status(429).json({ message: 'Rate limit exceeded, try again later.' });
}
app.use(rateLimiter);

// User Registration
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    await pool.query('INSERT INTO users (username, password, email) VALUES ($1, $2, $3)',
      [username, hashedPassword, email]);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'User not found' });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, 'token', { expiresIn: '52h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Login error' });
  }
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(403).json({ message: 'No token provided' });
  jwt.verify(token, 'token', (err, decoded) => {
    if (err) return res.status(500).json({ message: 'Token authentication failed' });
    req.userId = decoded.userId;
    next();
  });
}
app.use('/api/items', verifyToken);

// CRUD Operations for Items
app.get('/api/items', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM items');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/items', async (req, res) => {
  const { name, description } = req.body;
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
  try {
    const result = await pool.query(
      'INSERT INTO items (name, description, created_at) VALUES ($1, $2, $3) RETURNING *',
      [name, description, timestamp]
    );
    await fs.appendFile('logs.json', JSON.stringify(result.rows[0], null, 2) + '\n');
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Error creating item' });
  }
});

app.put('/api/items/:id', async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  try {
    const result = await pool.query(
      'UPDATE items SET name = $1, description = $2 WHERE id = $3 RETURNING *',
      [name, description, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Item not found' });
    res.json({ message: 'Item updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/items/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM items WHERE id = $1', [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Item not found' });
    res.json({ message: 'Item deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
