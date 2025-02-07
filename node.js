// using msql

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const fs = require('fs').promises;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Switched to bcryptjs to avoid native binding issues
const app = express();

// Middleware for parsing incoming JSON data
app.use(express.json());

// MySQL Database connection setup
// const connection = mysql.createConnection(process.env.DATABASE_URL);

const connection = mysql.createConnection({
  host: process.env.DB_HOST, // Render MySQL host
  user: process.env.DB_USER, // Database username
  password: process.env.DB_PASSWORD, // Database password
  database: process.env.DB_NAME, // Database name
});

// Test the connection to the MySQL database
connection.connect(err => {
  if (err) {
    console.error('Error connecting to the database: ', err);
    return;
  }
  console.log('Connected to the database');
});

// Rate Limiting Middleware: Limits requests per IP address
const rateLimit = {};
const RATE_LIMIT = 100; // Max allowed requests per IP
const WINDOW_MS = 15 * 60 * 1000; // 15-minute window for rate limiting

function rateLimiter(req, res, next) {
  const ip = req.ip; // Get the user's IP address
  if (!rateLimit[ip]) {
    rateLimit[ip] = { count: 0, timestamp: Date.now() }; // Initialize IP counter
  }

  const timeElapsed = Date.now() - rateLimit[ip].timestamp; // Calculate time difference
  if (timeElapsed > WINDOW_MS) {
    rateLimit[ip] = { count: 1, timestamp: Date.now() }; // Reset the counter after 15 minutes
    return next();
  }

  // Allow next request if under the rate limit
  if (rateLimit[ip].count < RATE_LIMIT) {
    rateLimit[ip].count++;
    return next();
  }

  // If the limit is exceeded, inform the user with a retry time
  const retryTime = Math.ceil((WINDOW_MS - timeElapsed) / 60000); 
  res.status(429).json({ message: `Rate limit exceeded, try again in ${retryTime} minutes.` });
}

app.use(rateLimiter); // Apply rate limiting middleware globally

// User Registration Route
app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Please provide all required fields: username, password, and email.' });
  }

  // Hash the password before saving it in the database for security
  const hashedPassword = await bcrypt.hash(password, 10);

  // SQL query to insert a new user into the users table
  const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';

  connection.query(query, [username, hashedPassword, email], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to register user' }); // Handle errors
    }
    res.status(201).json({ message: 'User registered successfully' }); // Success message
  });
});

// User Login Route with JWT Authentication
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Please provide both username and password.' });
  }

  // SQL query to find the user by username
  const query = 'SELECT * FROM users WHERE username = ?';
  
  connection.query(query, [username], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    if (results.length === 0) {
      return res.status(401).json({ message: 'Unauthorized: User not found' }); // User not found
    }

    const user = results[0];

    // Compare provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Unauthorized: Incorrect password' }); // Incorrect password
    }

    // Generate JWT token if login is successful
    const token = jwt.sign({ userId: user.id }, 'token', { expiresIn: '52h' }); // Token expires in 52 hours
    return res.json({ token }); // Return the generated token
  });
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1]; // Get token from the Authorization header
  if (!token) return res.status(403).json({ message: 'No token provided' });

  jwt.verify(token, 'token', (err, decoded) => {
    if (err) return res.status(500).json({ message: 'Failed to authenticate token' });
    req.userId = decoded.userId; // Save user ID to request object
    next(); // Proceed to the next middleware
  });
}

app.use('/api/items', verifyToken); // Protect /api/items routes with JWT verification

// CRUD Routes for managing Items
// Get all items from the database
app.get('/api/items', (req, res) => {
  connection.query('SELECT * FROM items', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results); // Return all items
  });
});

// Get a specific item by ID
app.get('/api/items/:id', (req, res) => {
  const { id } = req.params;
  connection.query('SELECT * FROM items WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (results.length === 0) return res.status(404).json({ error: 'Item not found' });
    res.json(results[0]); // Return the item
  });
});

// Create a new item
app.post('/api/items', async (req, res) => {
  const { name, description } = req.body;
  
  // Convert the current timestamp to MySQL-compatible format
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19); // Remove 'T' and 'Z'
  
  const newItem = { name, description, created_at: timestamp };

  connection.query('INSERT INTO items SET ?', newItem, async (err, result) => {
    if (err) return res.status(500).json({ error: err.message });

    // Log the creation of a new item
    const logEntry = {
      id: result.insertId,
      timestamp,
      name,
      description
    };

    try {
      // Append item creation log to logs.json file
      await fs.appendFile('logs.json', JSON.stringify(logEntry, null, 2) + '\n');
      res.status(201).json(newItem); // Respond with the new item
    } catch (error) {
      res.status(500).json({ error: 'Failed to log data' });
    }
  });
});

// Update an existing item
app.put('/api/items/:id', (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;

  connection.query(
    'UPDATE items SET name = ?, description = ? WHERE id = ?',
    [name, description, id],
    (err, result) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (result.affectedRows === 0) return res.status(404).json({ error: 'Item not found' });
      res.json({ message: 'Item updated successfully' });
    }
  );
});

// Delete an item by ID
app.delete('/api/items/:id', (req, res) => {
  const { id } = req.params;

  connection.query('DELETE FROM items WHERE id = ?', [id], (err, result) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Item not found' });
    res.json({ message: 'Item deleted successfully' });
  });
});

// Start the server on port 5000
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
