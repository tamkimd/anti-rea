import { web } from '@e2e-dev/web';

export default {
  targets: [{
    name: 'web',
    engine: web(),
    app: {
      url: 'http://127.0.0.1:0',
      command: { executable: 'node', args: ['server.cjs', '{port}'], reuseExisting: false },
    },
  }],
  workers: 1,
  retries: 0,
};
