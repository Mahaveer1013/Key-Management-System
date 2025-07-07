// master_key_manager.js
// Professional master key management for KMS

const mysql = require('mysql2/promise');
const crypto = require('crypto');

const MYSQL_CONFIG = {
    host: '127.0.0.1',
    user: 'root',
    password: 'root',
    database: 'kms',
    port: 3306
};
const TABLE_NAME = 'master_keys';

// Root key for encrypting master keys (should be 32 bytes)
const PLAIN_ROOT_KEY = process.env.ROOT_KEY || 'caratlane@321';
const ROOT_KEY = crypto.createHash('sha256').update(PLAIN_ROOT_KEY).digest();


const KMS_TABLE_NAME = 'kms_keys';

// Fetch master keys from DB
let OLD_MASTER_KEY, NEW_MASTER_KEY;

function pkcs7Unpad(buf) {
    const padLen = buf[buf.length - 1];
    return buf.slice(0, -padLen);
}

function pkcs7Pad(buf) {
    const padLen = 16 - (buf.length % 16);
    const padding = Buffer.alloc(padLen, padLen);
    return Buffer.concat([buf, padding]);
}

function decryptDek(encryptedDekB64, masterKey) {
    const encryptedDek = Buffer.from(encryptedDekB64, 'base64');
    const mkBytes = Buffer.from(masterKey.padEnd(32, '0'));
    const iv = encryptedDek.slice(0, 16);
    const ciphertext = encryptedDek.slice(16);
    const decipher = crypto.createDecipheriv('aes-256-cbc', mkBytes, iv);
    const padded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return pkcs7Unpad(padded);
}

function encryptDek(dekBytes, masterKey) {
    const mkBytes = Buffer.from(masterKey.padEnd(32, '0'));
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', mkBytes, iv);
    const padded = pkcs7Pad(dekBytes);
    const encrypted = Buffer.concat([iv, cipher.update(padded), cipher.final()]);
    return encrypted.toString('base64');
}

async function rotateMasterKey() {
    // Get keys
    const active = await getActiveMasterKey();
    const retired = await getRetiredMasterKeys();
    if (retired.length === 0) throw new Error('No retired (old) master key found.');
    OLD_MASTER_KEY = retired[0].keyMaterial;
    NEW_MASTER_KEY = active.keyMaterial;

    const connection = await mysql.createConnection(MYSQL_CONFIG);
    const [rows] = await connection.execute(`SELECT key_id, encrypted_dek FROM ${KMS_TABLE_NAME}`);
    console.log(`Found ${rows.length} keys to rotate.`);

    for (const row of rows) {
        const { key_id, encrypted_dek } = row;
        try {
            const dekBytes = decryptDek(encrypted_dek, OLD_MASTER_KEY);
            const newEncryptedDek = encryptDek(dekBytes, NEW_MASTER_KEY);
            await connection.execute(
                `UPDATE ${KMS_TABLE_NAME} SET encrypted_dek = ? WHERE key_id = ?`,
                [newEncryptedDek, key_id]
            );
            console.log(`Rotated key_id: ${key_id}`);
        } catch (err) {
            console.error(`Failed to rotate key_id ${key_id}: ${err.message}`);
        }
    }

    await connection.end();
    console.log('Master key rotation complete.');
}

function encryptKey(keyBuf) {
    if (!Buffer.isBuffer(keyBuf)) keyBuf = Buffer.from(keyBuf, 'hex'); // expects hex string input

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ROOT_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(keyBuf), cipher.final()]);
    return Buffer.concat([iv, encrypted]).toString('base64'); // Store as base64 TEXT
}

function decryptKey(encryptedB64) {
    const buf = Buffer.from(encryptedB64, 'base64');
    const iv = buf.slice(0, 16);
    const encrypted = buf.slice(16);
    const decipher = crypto.createDecipheriv('aes-256-cbc', ROOT_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted; // return as Buffer
}

async function addMasterKey() {
    const keyId = `key-${Date.now()}`;
    const hexKey = crypto.randomBytes(32).toString('hex'); // 32 bytes = 256 bits
    const keyBuf = Buffer.from(hexKey, 'hex');
    const encrypted = encryptKey(keyBuf);
    const now = new Date();

    const connection = await mysql.createConnection(MYSQL_CONFIG);
    await connection.execute(
        `CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
        id INT AUTO_INCREMENT PRIMARY KEY,
        key_id VARCHAR(64) UNIQUE NOT NULL,
        key_material TEXT NOT NULL, -- base64-encoded encrypted key
        created_at DATETIME NOT NULL,
        status ENUM('active', 'retired') NOT NULL,
        description TEXT
    );`
    );
    await connection.execute(
        `INSERT INTO ${TABLE_NAME} (key_id, key_material, created_at, status) VALUES (?, ?, ?, 'active')`,
        [keyId, encrypted, now]
    );
    await connection.execute(
        `UPDATE ${TABLE_NAME} SET status = 'retired' WHERE key_id != ? AND status = 'active'`,
        [keyId]
    );
    await connection.end();
    await rotateMasterKey(); // Rotate keys after adding a new one
    console.log(`Master key ${keyId} added and active key rotated.`);
}

async function getActiveMasterKey() {
    const connection = await mysql.createConnection(MYSQL_CONFIG);
    const [rows] = await connection.execute(
        `SELECT key_id, key_material FROM ${TABLE_NAME} WHERE status = 'active' ORDER BY created_at DESC LIMIT 1`
    );
    await connection.end();

    if (rows.length === 0) {
        throw new Error("No active master key found");
    }
    return {
        keyId: rows[0].key_id,
        keyMaterial: decryptKey(rows[0].key_material) // return as Buffer
    };
}

async function getRetiredMasterKeys() {
    const connection = await mysql.createConnection(MYSQL_CONFIG);
    const [rows] = await connection.execute(
        `SELECT key_id, key_material FROM ${TABLE_NAME} WHERE status = 'retired'`
    );
    await connection.end();
    return rows.map(row => ({
        keyId: row.key_id,
        keyMaterial: decryptKey(row.key_material)
    }));
}

async function listMasterKeys() {
    const connection = await mysql.createConnection(MYSQL_CONFIG);
    const [rows] = await connection.execute(
        `SELECT key_id, created_at, status FROM ${TABLE_NAME} ORDER BY created_at DESC`
    );
    await connection.end();
    return rows;
}

module.exports = {
    addMasterKey,
    getActiveMasterKey,
    getRetiredMasterKeys,
    listMasterKeys
};

getRetiredMasterKeys().then((data) => console.log(data)).catch((err) => console.log(err));
getActiveMasterKey().then((data) => console.log(data)).catch((err) => console.log(err));
listMasterKeys().then((data) => console.log(data)).catch((err) => console.log(err));

addMasterKey()
    .then(() => {
        getRetiredMasterKeys().then((data) => console.log(data));
        getActiveMasterKey().then((data) => console.log(data));
        listMasterKeys().then((data) => console.log(data));

    })
    .catch((err) => console.log(err));
