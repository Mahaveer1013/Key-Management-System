// ----------------------
// App B: Key Vault Server (Express + Node.js)
// ----------------------

const express = require('express');
const crypto = require('crypto');
const { getActiveMasterKey } = require('./master_key_manager'); // Import from master_key_manager
const axios = require('axios');

const app = express();
app.use(express.json()); // Use built-in JSON parser

// PKCS7 Padding Helpers
function pkcs7Pad(buf) {
    const padLen = 16 - (buf.length % 16);
    const padding = Buffer.alloc(padLen, padLen);
    return Buffer.concat([buf, padding]);
}

function pkcs7Unpad(buf) {
    const padLen = buf[buf.length - 1];
    return buf.slice(0, -padLen);
}

// Encrypt endpoint
app.post('/api/encrypt', async (req, res) => {
    const { data: base64Data, dek } = req.body;
    if (!base64Data || !dek) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        const { keyMaterial: masterKey } = await getActiveMasterKey();
        if (masterKey.length !== 32) throw new Error('Invalid master key length');

        const plainData = Buffer.from(base64Data, 'base64');
        const dekBuf = Buffer.from(dek, 'hex');
        if (dekBuf.length !== 32) throw new Error('Invalid DEK length');

        // Encrypt data with DEK
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', dekBuf, iv);
        const encryptedKey = Buffer.concat([iv, cipher.update(pkcs7Pad(plainData)), cipher.final()]);
        const encryptedKeyB64 = encryptedKey.toString('base64');

        // Encrypt DEK with master key
        const iv2 = crypto.randomBytes(16);
        const cipher2 = crypto.createCipheriv('aes-256-cbc', masterKey, iv2);
        const encryptedDek = Buffer.concat([iv2, cipher2.update(pkcs7Pad(dekBuf)), cipher2.final()]);
        const encryptedDekB64 = encryptedDek.toString('base64');

        res.json({ encrypted_key: encryptedKeyB64, encrypted_dek: encryptedDekB64 });
    } catch (err) {
        console.error('Encryption error:', err);
        res.status(500).json({ error: 'Encryption failed' });
    }
});

// Decrypt DEK endpoint
app.post('/api/decrypt-dek', async (req, res) => {
    const { encrypted_dek: encryptedDekB64 } = req.body;
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token || !encryptedDekB64) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    try {
        // Token verification
        const payload = await axios.post(process.env.AUTH_URL || 'http://localhost:8002/verify', { token });
        if (!payload.data?.payload?.id) {
            return res.status(401).json({ error: 'Invalid token payload' });
        }
    } catch (err) {
        return res.status(401).json({ error: 'Token verification failed' });
    }

    try {
        const { keyMaterial: masterKey } = await getActiveMasterKey();
        if (masterKey.length !== 32) throw new Error('Invalid master key length');

        const encryptedDek = Buffer.from(encryptedDekB64, 'base64');
        const iv = encryptedDek.slice(0, 16);
        const ciphertext = encryptedDek.slice(16);
        const decipher = crypto.createDecipheriv('aes-256-cbc', masterKey, iv);
        const paddedDek = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        const dek = pkcs7Unpad(paddedDek);
        const dekHex = dek.toString('hex');

        res.json({ dek: dekHex });
    } catch (err) {
        console.error('Decryption error:', err);
        res.status(500).json({ error: 'Decryption failed' });
    }
});

const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
    console.log(`Key Vault Server running on http://localhost:${PORT}`);
});
