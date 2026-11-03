import { web } from '@e2e-dev/web';

export default {
  targets: [{
    name: 'todomvc-react',
    engine: web(),
    app: {
      url: 'http://127.0.0.1:0',
      command: { executable: 'node', args: ['anti-rea-example/server.cjs', '{port}'], reuseExisting: false },
    },
  }],
  workers: 1,
  retries: 0,
};
