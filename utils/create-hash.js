const crypto = require('crypto')


const hashString = (string) =>
crypto.createHash('SHA-256').update(string).digest('hex')

module.exports = hashString