// Check before loading Umi: its dev command clears .umi before STRICT_PORT validation.
require('./console-env.cjs');
const net = require('node:net');
const path = require('node:path');
const probe = net.createServer();
probe.once('error', (error) => {
  console.error(`Console port ${process.env.PORT} is unavailable (${error.code}); existing instance left running`);
  process.exitCode = 1;
});
probe.listen(Number(process.env.PORT), '127.0.0.1', () => {
  probe.close(() => {
    const cli = path.resolve(__dirname, '../node_modules/@umijs/max/bin/max.js');
    process.argv[1] = cli;
    require(cli);
  });
});
