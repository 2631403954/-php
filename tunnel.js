const http   = require('http');
const net    = require('net');
const dns    = require('dns');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PORT          = 8080;
const PHP_PORT      = 8081;
const TUNNEL_SECRET = process.env.RELAY_SECRET || '314159265358979**//**';

/* 启动 PHP 后端 */
const php = spawn('php', ['-S', `127.0.0.1:${PHP_PORT}`, '-t', '/app'], { stdio: 'inherit' });
php.on('exit', () => process.exit(1));
process.on('SIGTERM', () => { php.kill(); process.exit(0); });
process.on('SIGINT',  () => { php.kill(); process.exit(0); });

function isPrivateIP(ip) {
  if (!ip) return true;
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const a = +v4[1], b = +v4[2];
    if (a===0||a===10||a===127) return true;
    if (a===169 && b===254) return true;
    if (a===172 && b>=16 && b<=31) return true;
    if (a===192 && b===168) return true;
    if (a>=224) return true;
    return false;
  }
  const l = ip.toLowerCase();
  if (l==='::1'||l==='::') return true;
  if (l.startsWith('fc')||l.startsWith('fd')) return true;
  if (l.startsWith('fe80')) return true;
  return false;
}

function safeEq(a, b) {
  const ba = Buffer.from(String(a)), bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  try { return crypto.timingSafeEqual(ba, bb); } catch { return false; }
}

/* --------- /tunnel：TCP 隧道 --------- */
function handleTunnel(req, res) {
  const u = new URL(req.url, 'http://x');
  const sign = u.searchParams.get('sign') || '';
  const host = u.searchParams.get('host') || '';
  const port = parseInt(u.searchParams.get('port') || '443', 10);

  if (!safeEq(sign, TUNNEL_SECRET)) {
    res.writeHead(403); return res.end('bad sign');
  }
  if (!host || !port || port < 1 || port > 65535) {
    res.writeHead(400); return res.end('bad host/port');
  }

  dns.lookup(host, { all: true }, (err, addrs) => {
    if (err || !addrs) { res.writeHead(502); return res.end('dns fail'); }
    const good = addrs.filter(a => !isPrivateIP(a.address));
    if (!good.length) { res.writeHead(403); return res.end('private'); }

    const up = net.connect(port, good[0].address, () => {
      console.log(`[tunnel] ${host}:${port} -> ${good[0].address}`);
      res.writeHead(200, { 'Content-Type': 'application/octet-stream',
                           'Cache-Control': 'no-store' });
      res.flushHeaders && res.flushHeaders();
      req.pipe(up);
      up.pipe(res);
      const kill = () => { try{up.destroy();}catch{} try{req.destroy();}catch{} try{res.end();}catch{} };
      req.on('error', kill); req.on('close', kill);
      up.on('error', kill);  up.on('close', kill);
    });
    up.setTimeout(0);
    up.on('error', (e) => {
      if (!res.headersSent) { res.writeHead(502); }
      try { res.end('upstream: ' + e.message); } catch {}
    });
  });
}

/* --------- 其他请求 → 反代到 PHP --------- */
function proxyToPhp(req, res) {
  const p = http.request({
    hostname: '127.0.0.1', port: PHP_PORT,
    path: req.url, method: req.method, headers: req.headers,
  }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  p.on('error', () => { if (!res.headersSent) res.writeHead(502); res.end(); });
  req.pipe(p);
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/tunnel')) handleTunnel(req, res);
  else proxyToPhp(req, res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`gateway on :${PORT} (php:${PHP_PORT})`);
});
