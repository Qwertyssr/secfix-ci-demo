const crypto = require('crypto');

function fingerprint(data) {
  // VULN (Fortify: Weak Cryptographic Hash) -> should become sha256
  return crypto.createHash('md5').update(data).digest('hex');
}

module.exports = { fingerprint };
