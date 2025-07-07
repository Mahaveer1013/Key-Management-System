// const { addMasterKey } = require('./master_key_manager');
// const crypto = require('crypto');

// const addRandomMasterKey = async () => {
//     const keyId = `key-${Date.now()}`;
//     const hexKey = crypto.randomBytes(32).toString('hex'); // 32 bytes = 256 bits

//     try {
//         await addMasterKey(keyId, hexKey);
//     } catch (err) {
//         console.error('Error adding master key:', err);
//         throw err; // Rethrow so caller can handle failure
//     }
// };

// // Run the function to add a random master key
// addRandomMasterKey().then(() => {
//     console.log('Random master key addition complete.');
// }).catch(err => {
//     console.error('Error in adding random master key:', err);
// });
