// Umi 4's webpack server displays HOST but calls listen(port) without a host.
// Scope the workaround to this development process; never expose its API proxy.
const http = require('node:http');
const https = require('node:https');
const original = http.Server.prototype.listen;
const local = new Set(['127.0.0.1', '::1']);
function loopbackListen(...args) {
  if (typeof args[0] === 'number' || (typeof args[0] === 'string' && /^\d+$/.test(args[0]))) {
    if (typeof args[1] === 'string') {
      if (!local.has(args[1])) throw new Error('Console development listeners must use a loopback IP');
    } else args.splice(1, 0, '127.0.0.1');
  } else if (args[0] && typeof args[0] === 'object' && 'port' in args[0]) {
    const host = args[0].host || '127.0.0.1';
    if (!local.has(host)) throw new Error('Console development listeners must use a loopback IP');
    args[0] = { ...args[0], host };
  }
  return original.apply(this, args);
}
// Leave temporary raw TCP port-discovery probes alone.
http.Server.prototype.listen = loopbackListen;
https.Server.prototype.listen = loopbackListen;
