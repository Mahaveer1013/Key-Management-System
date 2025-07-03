// ----------------------
// App A: Master Key Manager (Express + MySQL)
// ----------------------

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());

// MySQL config
const dbConfig = {
    host: '127.0.0.1',
    user: 'root',
    password: 'root',
    database: 'kms',
    port: 3306
};

async function getDbConnection() {
    return await mysql.createConnection(dbConfig);
}

app.post('/api/keys', async (req, res) => {
    const { data, user_id } = req.body;
    if (!data || !user_id) return res.status(400).json({ error: 'User ID and data are required' });
    //   const { data } = req.body;
    //   if (!data) return res.status(400).json({ error: 'User ID and data are required' });
    //     const token = req.headers['authorization']?.replace('Bearer ', '');
    //     if (!token) return res.status(401).json({ error: 'Missing token' });
    //     let user_id;
    //     try {
    //         const response = await axios.post('http://localhost:8002/verify', { token });
    //         if (!response.data || !response.data.valid || !response.data.payload.user_id) {
    //             return res.status(500).json({ error: 'Failed to verify token' });
    //         }
    //         user_id = response.data.payload.id;
    //     } catch (e) {
    //         return res.status(401).json({ error: 'Invalid token', details: e.message });
    //     }
    const plainData = Buffer.from(data);
    const dek = crypto.randomBytes(32).toString('hex');

    try {
        const response = await axios.post('http://localhost:8001/api/encrypt', {
            data: plainData.toString('base64'),
            dek,
            user_id
        });

        const { encrypted_key, encrypted_dek } = response.data;
        console.log("encrypted_dek: ", encrypted_dek);

        const conn = await getDbConnection();
        await conn.execute(`CREATE TABLE IF NOT EXISTS kms_keys (
      user_id VARCHAR(64) PRIMARY KEY,
      encrypted_key TEXT,
      encrypted_dek TEXT,
      created_at DATETIME
    )`);

        await conn.execute(
            'INSERT INTO kms_keys (user_id, encrypted_key, encrypted_dek, created_at) VALUES (?, ?, ?, ?)',
            [user_id, encrypted_key, encrypted_dek, new Date()]
        );
        await conn.end();

        const token_data = await axios.post('http://localhost:8002/issue', { id: user_id });

        if (!token_data.data || !token_data.data.token) {
            return res.status(500).json({ error: 'Failed to issue token' });
        }
        const token = token_data.data.token;
        res.json({ message: 'Key stored successfully', access_token: token });
    } catch (err) {
        res.status(500).json({ error: 'App B error or DB error', details: err.message });
    }
});

app.get('/api/keys', async (req, res) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let user_id;
    try {
        const response = await axios.post('http://localhost:8002/verify', { token });
        if (!response.data || !response.data.valid || !response.data.payload.id) {
            return res.status(500).json({ error: 'Failed to verify token' });
        }

        user_id = response.data.payload.id;
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token', details: e.message });
    }

    try {
        const conn = await getDbConnection();
        const [rows] = await conn.execute('SELECT * FROM kms_keys WHERE user_id = ?', [user_id]);
        await conn.end();
        console.log(rows[0]);

        if (!rows.length) return res.status(404).json({ error: 'Key not found' });
        const row = rows[0];
        if (row.user_id !== user_id) return res.status(403).json({ error: 'Unauthorized' });

        const response = await axios.post('http://localhost:8001/api/decrypt-dek', {
            encrypted_dek: row.encrypted_dek,
            user_id
        }, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const dek = response.data.dek;
        const encryptedKeyBuf = Buffer.from(row.encrypted_key, 'base64');
        const dekBuf = Buffer.from(dek, 'hex');
        const iv = encryptedKeyBuf.slice(0, 16);
        const ciphertext = encryptedKeyBuf.slice(16);

        const decipher = crypto.createDecipheriv('aes-256-cbc', dekBuf, iv);
        let paddedPlain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const padLen = paddedPlain[paddedPlain.length - 1];
        const plain = paddedPlain.slice(0, -padLen).toString();

        res.json({ data: plain });
    } catch (e) {
        res.status(500).json({ error: 'Decryption failed or App B error', details: e.message });
    }
});

// Dummy rotate MK endpoint
app.get('/api/rotate-mk', (req, res) => {
    // Implement actual key rotation logic here if needed
    res.json({ message: 'Master key rotation initiated' });
});

app.listen(8000, () => {
    console.log('Master Key Manager running on http://localhost:8000');
});
