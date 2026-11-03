import { createRequire } from 'node:module';

const require = createRequire(`${process.env.ANTI_REA_E2E_RUNTIME}/package.json`);
const { web } = require('@e2e-dev/web');

export default {
  targets: [{
    name: 'flutter-todo-web',
    engine: web(),
    app: {
      url: 'http://127.0.0.1:0',
      command: { executable: 'node', args: ['anti-rea-example/server.cjs', '{port}'], reuseExisting: false },
    },
  }],
  workers: 1,
  retries: 0,
};
