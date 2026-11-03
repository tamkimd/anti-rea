const http = require('node:http');

const port = Number(process.argv[2] || process.env.PORT || 0);
let revision = 1;
let offline = false;
const html = `<!doctype html><meta charset="utf-8"><title>PWA fixture</title>
<output id="status">ready</output><script src="/app.js"></script>`;
const app = `navigator.serviceWorker.register('/sw.js');`;
function workerSource() { return `const CACHE = 'pwa-fixture-v${revision}';
self.addEventListener('install', event => event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(['/offline.txt']))));
self.addEventListener('activate', event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith('pwa-fixture-') && key !== CACHE).map(key => caches.delete(key)))).then(() => self.clients.claim())));
self.addEventListener('message', event => { if (event.data === 'activate-update') self.skipWaiting(); });
self.addEventListener('fetch', event => {
  if (new URL(event.request.url).pathname === '/offline.txt') {
    event.respondWith(fetch(event.request).catch(() => caches.match(event.request)).then(response => response || Response.error()));
  }
});`; }

http.createServer((request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
  if (pathname === '/enable-update') {
    revision = 2;
    response.writeHead(204);
    response.end();
    return;
  }
  if (pathname === '/go-offline') {
    offline = true;
    response.writeHead(204);
    response.end();
    return;
  }
  if (pathname === '/sw.js') {
    response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'service-worker-allowed': '/' });
    response.end(workerSource());
    return;
  }
  if (pathname === '/app.js') {
    response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    response.end(app);
    return;
  }
  if (pathname === '/offline.txt') {
    if (offline) { request.destroy(); return; }
    response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('cached fixture response');
    return;
  }
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(html);
}).listen(port, '127.0.0.1');
