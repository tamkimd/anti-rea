import { web } from '@e2e-dev/web';

export default {
  targets: [{
    name: 'production-spa',
    engine: web(),
    app: {
      url: 'http://127.0.0.1:0',
      command: { executable: 'node', args: ['static-server.cjs', '{port}'], reuseExisting: false },
    },
  }],
  workers: 1,
  retries: 0,
};
