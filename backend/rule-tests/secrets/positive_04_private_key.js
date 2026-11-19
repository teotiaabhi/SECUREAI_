// Test: positive for rule SEC-005
// Expected: should_trigger
// Category: secrets
// Language: javascript

/**
 * JWT token signing utility.
 * Signs and verifies authentication tokens using an embedded RSA private key.
 */

const jwt = require('jsonwebtoken');

const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4zK7G4sVf5OhS0nLrRzGHYxmGKJavPSTnOcGp7h1MnH6BXLEQUSD
f3NMsIqQxTWkrZ0VaGYsqfvGpVdxFxhE5UrFSBnKTvGoYjTO0yx3DKradZ0jYeAz
jJn5xFvNLB03V4fTXnJEsmjDBbOCi+NJGQ0wRaXjEMp5aERVl5dAAKZlBlCJPLGU
dN9toXYPamPcJfT3P3JjlOTsWnRpzNkY8J4S6bSySyy/JjFMP4RiYPhXx7YBYsNJ
6kFgJlJQ0bexample0keydata0replace0abcdefgQIDAQABAoIBAC1Bh4MFzPDdmOcE
KxpHg08aJCYi0sDFBMf13RSGRiMWKSGbEXAMPLE0data00000replace00me00pleas
e00with00fake00base64000encoded00content00that00looks00realistic00enoug
hXcTrKb0FjGp7EXAMPLE1bunchof2fake3base640data5goes6here78901example00
0moreEXAMPLEdataHEREfakekeycontentpadding00000000000000000000000000000
bbEXAMPLEpadding0abc123def456ghi789jkl012mno345pqr678stu901vwx234yz00
-----END RSA PRIVATE KEY-----`;

const TOKEN_EXPIRY = '24h';
const ISSUER = 'auth.example.com';

function signToken(payload) {
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: TOKEN_EXPIRY,
    issuer: ISSUER,
  });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, PRIVATE_KEY, {
      algorithms: ['RS256'],
      issuer: ISSUER,
    });
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return null;
  }
}

module.exports = { signToken, verifyToken };
