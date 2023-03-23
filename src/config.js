const envGet = require('./env');

module.exports = {
  SERVER_URL: envGet('SERVER_URL', ''),
  SERVER_NAME: envGet('SERVER_NAME', ''),
  FIREBASE_CREDENTIALS: JSON.parse(envGet('FIREBASE_CREDENTIALS')),
};
