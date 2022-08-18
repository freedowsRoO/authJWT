const blacklist = require('./blacklist');
const { promisify } = require('util');
const { createHash } = require('crypto');
const jwt = require('jsonwebtoken');

const existsAsync = promisify(blacklist.exists).bind(blacklist);
const setAsync = promisify(blacklist.set).bind(blacklist);

function geraTokeHash(token) {
    return createHash('sha256')
            .update(token)
            .digest('hex');
}

module.exports = {
    adiciona: async token => {
        const dataExpiração = jwt.decode(token).exp;
        const tokenHash = geraTokeHash(token);
        await setAsync(tokenHash, '');
        blacklist.expireat(tokenHash, dataExpiração);
    },

    contemToken: async token => {
        const tokenHash = geraTokeHash(token);
        const result = await existsAsync(tokenHash);
        return result === 1 ? true : false;
    }
}