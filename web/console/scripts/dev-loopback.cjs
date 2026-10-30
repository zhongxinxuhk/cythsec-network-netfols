// Umi 4.7.27 的 webpack/utoopack 外层服务器未把 HOST 传给 listen；仅补开发入口这一端口。
const net = require('node:net');
const port = Number(process.env.PORT || 15173);
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  if (
    Number(args[0]) === port &&
    (args[1] === undefined || typeof args[1] === 'function')
  ) {
    args.splice(1, 0, '127.0.0.1');
  }
  return Reflect.apply(listen, this, args);
};
