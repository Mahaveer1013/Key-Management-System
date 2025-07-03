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

async function addMasterKey(keyId, hexKey) {
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
}

async function getActiveMasterKey() {
  const connection = await mysql.createConnection(MYSQL_CONFIG);
  const [rows] = await connection.execute(
    `SELECT key_id, key_material FROM ${TABLE_NAME} WHERE status = 'active' ORDER BY created_at DESC LIMIT 1`
  );
  await connection.end();

  if (rows.length === 0) throw new Error('No active master key');
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
