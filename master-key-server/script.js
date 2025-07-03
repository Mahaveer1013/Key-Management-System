const { addMasterKey } = require('./master_key_manager');
const crypto = require('crypto');

// Generate a unique keyId (could be UUID, timestamp, or custom format)
const keyId = `key-${Date.now()}`;

// Generate a secure 32-byte master key (in hex format)
const hexKey = crypto.randomBytes(32).toString('hex');

addMasterKey(keyId, hexKey)
  .then(() => {
    console.log(`✅ Master key added: ${keyId}`);
  })
  .catch((err) => {
    console.error('❌ Error adding master key:', err);
  });
