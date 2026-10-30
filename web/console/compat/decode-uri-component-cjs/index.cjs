// query-string 6 expects a CommonJS function; the fixed upstream decoder is ESM.
module.exports = require('safe-uri-decoder').default;
