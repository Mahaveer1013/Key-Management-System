

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Secret key for signing JWTs (in production, use env vars or secure storage)
const JWT_SECRET = 'your-very-secure-secret';
const JWT_EXPIRES_IN = '30d';

// POST /issue - Issue a JWT token
app.post('/issue', (req, res) => {
    try {
        const payload = req.body;
        if (!payload || typeof payload !== 'object') {
            return res.status(400).json({ error: 'Invalid payload' });
        }
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
        res.json({ token });
    } catch (error) {
        console.error('Error issuing token:', error);
        res.status(500).json({ error: 'Failed to issue token' });
    }
});

// POST /verify - Verify a JWT token
app.post('/verify', (req, res) => {

    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ error: 'Token required' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, payload: decoded });
    } catch (err) {
        res.status(401).json({ valid: false, error: 'Invalid token' });
    }
});

const PORT = 8002;
app.listen(PORT, () => {
    console.log(`Auth service running on port ${PORT}`);
});
