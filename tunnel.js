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

/* 向 upgrade socket 返回错误 */
function rejectUpgrade(socket, code, msg) {
  try {
    socket.write(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`);
  } catch (e) {}
  socket.destroy();
}

/* --------- /tunnel：TCP 隧道（处理 Upgrade 请求） --------- */
function handleTunnelUpgrade(req, socket, head) {
  console.log(`[tunnel] UPGRADE event: url=${req.url} upgrade=${req.headers.upgrade}`);

  const u = new URL(req.url, 'http://x');
  const sign = u.searchParams.get('sign') || '';
  const host = u.searchParams.get('host') || '';
  const port = parseInt(u.searchParams.get('port') || '443', 10);

  if (!safeEq(sign, TUNNEL_SECRET)) {
    console.log('[tunnel] bad sign');
    return rejectUpgrade(socket, 403, 'Forbidden');
  }
  if (!host || !port || port < 1 || port > 65535) {
    console.log('[tunnel] bad host/port');
    return rejectUpgrade(socket, 400, 'Bad Request');
  }

  dns.lookup(host, { all: true }, (err, addrs) => {
    if (err || !addrs) {
      console.log(`[tunnel] dns fail: ${err && err.message}`);
      return rejectUpgrade(socket, 502, 'Bad Gateway');
    }
    const good = addrs.filter(a => !isPrivateIP(a.address));
    if (!good.length) {
      console.log('[tunnel] private ip');
      return rejectUpgrade(socket, 403, 'Forbidden');
    }

    let connected = false;
    const up = net.connect(port, good[0].address, () => {
      connected = true;
      console.log(`[tunnel] ${host}:${port} -> ${good[0].address}`);

      // 关键：返回 101，Upgrade 必须是 websocket（配合 Railway 边缘）
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        '\r\n'
      );

      // 客户端在 Upgrade 请求后可能已发送的数据
      if (head && head.length) up.write(head);

      socket.pipe(up);
      up.pipe(socket);

      const kill = () => {
        try { up.destroy(); } catch {}
        try { socket.destroy(); } catch {}
      };
      socket.on('error', kill);
      socket.on('close', kill);
      up.on('error', kill);
      up.on('close', kill);
    });

    up.setTimeout(0);
    up.on('error', (e) => {
      console.log(`[tunnel] upstream error: ${e.message}`);
      if (!connected) {
        if (!socket.destroyed) rejectUpgrade(socket, 502, 'Bad Gateway');
      } else {
        try { up.destroy(); } catch {}
        try { socket.destroy(); } catch {}
      }
    });
  });
}

/* --------- 其他请求 → 反代到 PHP --------- */
function proxyToPhp(req, res) {
  const p = http.request({
    hostname: '127.0.0.1', port: PHP_PORT,
    path: req.url, method: req.method, headers: req.headers,
  }, (r) => {
    res.writeHead(r.statusCode, r.headers);
    r.pipe(res);
  });
  p.on('error', () => {
    if (!res.headersSent) res.writeHead(502);
    res.end();
  });
  req.pipe(p);
}

const server = http.createServer((req, res) => {
  console.log(`[tunnel] REQUEST ${req.method} ${req.url} upgrade=${req.headers.upgrade || ''}`);

  // 如果 /tunnel 走到普通请求，说明 Upgrade 头没被 Node 识别或已被剥离
  if (req.url.startsWith('/tunnel')) {
    res.writeHead(426, { 'Content-Type': 'text/plain', 'Connection': 'close' });
    return res.end('Upgrade Required');
  }

  proxyToPhp(req, res);
});

/* 关键：监听 upgrade 事件 */
server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/tunnel')) {
    handleTunnelUpgrade(req, socket, head);
  } else {
    console.log(`[tunnel] UPGRADE event for non-tunnel: ${req.url}`);
    rejectUpgrade(socket, 404, 'Not Found');
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`gateway on :${PORT} (php:${PHP_PORT})`);
});
