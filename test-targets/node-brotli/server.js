// shellproof local test target — Node Brotli request-decode path (CVE-2026-111497).
// Zero deps: uses Node's built-in zlib to decompress `Content-Encoding: br` bodies,
// mirroring how Express 5 / body-parser 2.x transparently inflate request bodies.
//
// A current (patched) Node rejects malformed Brotli with a clean 400 → shellproof
// should read "PATCHED / clean-reject". An unpatched decoder would crash the process
// (connection reset) → "VULNERABLE". Good for validating the brotli probe's signal.
const http = require('http');
const zlib = require('zlib');

const PORT = process.env.PORT || 8090;

http
  .createServer((req, res) => {
    const enc = (req.headers['content-encoding'] || '').toLowerCase();
    if (req.method === 'POST' && enc.includes('br')) {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        try {
          const out = zlib.brotliDecompressSync(Buffer.concat(chunks));
          res.writeHead(200, { 'content-type': 'text/plain' });
          res.end('decoded ' + out.length + ' bytes\n');
        } catch (e) {
          res.writeHead(400, { 'content-type': 'text/plain' });
          res.end('bad brotli: ' + (e.code || e.message) + '\n');
        }
      });
      req.on('error', () => {
        try { res.writeHead(400); res.end('request error\n'); } catch (_) {}
      });
    } else {
      res.writeHead(200, { 'x-powered-by': 'Node.js', 'content-type': 'text/plain' });
      res.end('shellproof node test target\n');
    }
  })
  .listen(PORT, '127.0.0.1', () => console.error('node-brotli target on 127.0.0.1:' + PORT));
