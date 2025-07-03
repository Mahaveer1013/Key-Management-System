// rotate_master_key.js

const mysql = require('mysql2/promise');
const crypto = require('crypto');

// --- CONFIG ---
const MYSQL_CONFIG = {
  host: '127.0.0.1',
  user: 'root',
  password: 'root',
  database: 'kms',
  port: 3306
};
const TABLE_NAME = 'kms_keys';

const keyManager = require('./master_key_manager');

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
  const active = await keyManager.getActiveMasterKey();
  const retired = await keyManager.getRetiredMasterKeys();
  if (retired.length === 0) throw new Error('No retired (old) master key found.');
  OLD_MASTER_KEY = retired[0].keyMaterial;
  NEW_MASTER_KEY = active.keyMaterial;

  const connection = await mysql.createConnection(MYSQL_CONFIG);
  const [rows] = await connection.execute(`SELECT key_id, encrypted_dek FROM ${TABLE_NAME}`);
  console.log(`Found ${rows.length} keys to rotate.`);

  for (const row of rows) {
    const { key_id, encrypted_dek } = row;
    try {
      const dekBytes = decryptDek(encrypted_dek, OLD_MASTER_KEY);
      const newEncryptedDek = encryptDek(dekBytes, NEW_MASTER_KEY);
      await connection.execute(
        `UPDATE ${TABLE_NAME} SET encrypted_dek = ? WHERE key_id = ?`,
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

rotateMasterKey().catch(console.error);
