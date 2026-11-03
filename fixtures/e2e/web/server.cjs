const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const port = Number(process.argv[2] || process.env.PORT || 0);
const html = `<!doctype html><html><body>
<label for="name">Name</label><input id="name">
<button id="greet">Greet</button><output role="status"></output>
<script src="/app.js"></script>
</body></html>`;

http.createServer((request, response) => {
  if (request.url === '/app.js') {
    response.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    response.end(fs.readFileSync(path.join(__dirname, 'app.js')));
    return;
  }
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(html);
}).listen(port, '127.0.0.1');
