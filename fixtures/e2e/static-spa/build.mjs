import { mkdir, writeFile } from 'node:fs/promises';

await mkdir('dist/assets', { recursive: true });
await writeFile('dist/index.html', `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<link rel="stylesheet" href="/assets/site.css"><title>Greeting</title></head>
<body><main><label for="name">Name</label><input id="name"><button id="greet">Greet</button>
<p role="status"></p></main><script type="module" src="/assets/app.js"></script></body></html>`);
await writeFile('dist/assets/site.css', 'body { font: 16px sans-serif; margin: 3rem; }');
await writeFile('dist/assets/app.js', `document.querySelector('#greet').addEventListener('click', () => {
  const name = document.querySelector('#name').value.trim();
  document.querySelector('[role="status"]').textContent = name ? 'Hello, ' + name + '!' : 'Name is required.';
});\n`);
