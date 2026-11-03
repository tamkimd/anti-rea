const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve('dist');
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
http.createServer((request, response) => {
  let pathname;
  try { pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname); }
  catch { response.writeHead(400).end(); return; }
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const file = path.resolve(root, relative);
  if (file !== root && !file.startsWith(root + path.sep)) { response.writeHead(403).end(); return; }
  fs.readFile(file, (error, content) => {
    if (error) { response.writeHead(404).end(); return; }
    response.writeHead(200, { 'content-type': types[path.extname(file)] || 'application/octet-stream' }).end(content);
  });
}).listen(Number(process.argv[2]), '127.0.0.1');
