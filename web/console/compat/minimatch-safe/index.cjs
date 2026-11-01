'use strict';

const core = require('minimatch-core');
const minimatch = core.minimatch;

Object.assign(minimatch, core, {
  minimatch,
  default: minimatch,
});

module.exports = minimatch;
