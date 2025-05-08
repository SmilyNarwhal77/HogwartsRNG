const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// In-memory store (replace with a database in production)
const users = {};
const gameStates = {};
const activeSessions = {};

// Secret for JWT (replace with an environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware to verify JWT
function verifyToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.split(' ')[1];
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = async (req, res) => {
  const { method, body } = req;

  if (req.url === '/api/auth/register' && method === 'POST') {
    const { username, password } = body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
    if (users[username]) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    users[username] = { password: hashedPassword };
    gameStates[username] = null;
    return res.status(201).json({ message: 'Registration successful' });
  }

  if (req.url === '/api/auth/login' && method === 'POST') {
    const { username, password } = body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
    const user = users[username];
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    if (user.password !== hashedPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
    // Invalidate previous session
    if (activeSessions[username]) {
      delete activeSessions[username];
    }
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    activeSessions[username] = token;
    return res.status(200).json({
      token,
      state: gameStates[username] || {
        coins: 0,
        spinCost: 10,
        inventory: [],
        equipped: [null, null, null, null, null],
        forgeSlots: [null, null, null],
        altarTarget: null,
        altarFuel: [null, null, null, null, null],
        redeemedCodes: [],
        changelog: []
      }
    });
  }

  if (req.url === '/api/auth/logout' && method === 'POST') {
    const payload = verifyToken(req);
    if (!payload) {
      return res.status(401).json({ message: 'Invalid or missing token' });
    }
    const { username } = payload;
    if (activeSessions[username] && activeSessions[username] === req.headers.authorization.split(' ')[1]) {
      delete activeSessions[username];
    }
    return res.status(200).json({ message: 'Logged out successfully' });
  }

  if (req.url === '/api/auth/save' && method === 'POST') {
    const payload = verifyToken(req);
    if (!payload) {
      return res.status(401).json({ message: 'Invalid or missing token' });
    }
    const { username } = payload;
    if (!activeSessions[username] || activeSessions[username] !== req.headers.authorization.split(' ')[1]) {
      return res.status(401).json({ message: 'Session invalidated' });
    }
    gameStates[username] = body;
    return res.status(200).json({ message: 'Game state saved' });
  }

  if (req.url === '/api/auth/verify' && method === 'GET') {
    const payload = verifyToken(req);
    if (!payload) {
      return res.status(401).json({ message: 'Invalid or missing token' });
    }
    const { username } = payload;
    if (!activeSessions[username] || activeSessions[username] !== req.headers.authorization.split(' ')[1]) {
      return res.status(401).json({ message: 'Session invalidated' });
    }
    return res.status(200).json({
      username,
      state: gameStates[username] || {
        coins: 0,
        spinCost: 10,
        inventory: [],
        equipped: [null, null, null, null, null],
        forgeSlots: [null, null, null],
        altarTarget: null,
        altarFuel: [null, null, null, null, null],
        redeemedCodes: [],
        changelog: []
      }
    });
  }

  return res.status(404).json({ message: 'Endpoint not found' });
};
