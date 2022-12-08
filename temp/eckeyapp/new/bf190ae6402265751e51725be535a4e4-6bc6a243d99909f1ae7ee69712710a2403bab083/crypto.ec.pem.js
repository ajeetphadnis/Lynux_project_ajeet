// (Buffer is available in Node.js as a global, but we require it this way for compatibility)
// See: https://nodejs.org/api/buffer.html#buffer_buffer
const { Buffer } = require('buffer');
const crypto = require('crypto');

const keyPair = crypto.createECDH('secp256k1');

keyPair.generateKeys();

// Print the PEM-encoded private key
console.log(`-----BEGIN PRIVATE KEY-----
${Buffer.from(`308184020100301006072a8648ce3d020106052b8104000a046d306b0201010420${keyPair.getPrivateKey('hex')}a144034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
-----END PRIVATE KEY-----`);

// Print the PEM-encoded public key
console.log(`-----BEGIN PUBLIC KEY-----
${Buffer.from(`3056301006072a8648ce3d020106052b8104000a034200${keyPair.getPublicKey('hex')}`, 'hex').toString('base64')}
-----END PUBLIC KEY-----`);
