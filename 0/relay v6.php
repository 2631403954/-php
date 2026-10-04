<?php
/**
 * relay.php —— 流式中继端（v6）
 *
 * v6 变更（性能调优）：
 *   - TIMEOUT 300 → 3600（长视频兜底）
 *   - LOW_SPEED_LIMIT 10 → 1024，LOW_SPEED_TIME 30 → 60
 *   - curl 参数：BUFFERSIZE=64KB, TCP_NODELAY, HTTP/1.1 强制
 *   - 再次显式关闭 zlib 输出压缩
 *
 * 与 v4（JSON + base64 全缓冲）的协议差异：
 *   - 成功时：直接把上游响应（status + headers + body）流式返回，
 *     不再用 JSON + base64 包装，没有大小限制。
 *   - 失败时（relay 自身错误）：返回 HTTP 4xx/5xx，
 *     并带 X-Relay-Error: 1 头，body 为纯文本错误说明。
 *
 * 请求参数（POST，application/x-www-form-urlencoded）：
 *   sign      必填，与 RELAY_SECRET 一致
 *   url       必填，必须是 https 绝对 URL
 *   method    可选，默认 GET
 *   body_b64  可选，base64 编码的请求体
 *   headers   可选，JSON 数组 [[name, value], ...]，
 *             用于把客户端的请求头（例如 Range）透传给上游
 *
 * 响应：
 *   成功：上游的 status + headers + body，透传（去掉 hop-by-hop 头）
 *   失败：4xx/5xx + X-Relay-Error: 1 + 纯文本 body
 */

/* ============================================================
 * 关闭所有输出缓冲——流式转发的前提
 * ============================================================ */
@ini_set('output_buffering', '0');
@ini_set('zlib.output_compression', '0');        /* ★ C1: 显式关闭 zlib */
@ini_set('implicit_flush', '1');
while (ob_get_level() > 0) { @ob_end_clean(); }
@ob_implicit_flush(true);

/* 有些 PHP-FPM 配置里 zlib 会在 runtime 被重新打开，双保险 */
if (function_exists('ini_set')) {
    @ini_set('zlib.output_compression', '0');
    @ini_set('zlib.output_compression_level', '-1');
}

/* ============================================================
 * 常量
 * ============================================================ */
define('RELAY_SECRET',      '314159265358979**//**');   // 与 2.c 一致
define('TIMEOUT',            3600);                     /* ★ C2: 1 小时 */
define('CONNECT_TIMEOUT',     10);
define('CHALLENGE_TTL',      300);
define('CHALLENGE_HTML_MAX', 16 * 1024);
define('LOW_SPEED_LIMIT',    1024);                     /* ★ C2: 1 KB/s */
define('LOW_SPEED_TIME',      60);                      /* ★ C2: 60 秒 */

/* ============================================================
 * relay 自身错误输出
 * ============================================================ */
function relay_error($http_code, $msg) {
    if (!headers_sent()) {
        http_response_code($http_code);
        header('X-Relay-Error: 1');
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo $msg;
    exit;
}

/* ============================================================
 * 挑战 cookie 缓存
 * ============================================================ */
function challenge_cache_key($host) {
    return 'relay_test_' . md5(strtolower($host));
}
function challenge_cache_get($host) {
    $key = challenge_cache_key($host);
    if (function_exists('apcu_fetch')) {
        $v = apcu_fetch($key);
        if ($v !== false && is_string($v) && $v !== '') return $v;
    }
    $path = sys_get_temp_dir() . '/' . $key . '.cache';
    if (!is_file($path)) return null;
    $data = @file_get_contents($path);
    if ($data === false) return null;
    $pos = strpos($data, '|');
    if ($pos === false) return null;
    $ts     = (int)substr($data, 0, $pos);
    $cookie = substr($data, $pos + 1);
    if ($cookie === '') return null;
    if (time() - $ts > CHALLENGE_TTL) { @unlink($path); return null; }
    return $cookie;
}
function challenge_cache_set($host, $cookie) {
    if ($cookie === '') return;
    $key = challenge_cache_key($host);
    if (function_exists('apcu_store')) { apcu_store($key, $cookie, CHALLENGE_TTL); return; }
    $path = sys_get_temp_dir() . '/' . $key . '.cache';
    @file_put_contents($path, time() . '|' . $cookie, LOCK_EX);
}
function challenge_cache_del($host) {
    $key = challenge_cache_key($host);
    if (function_exists('apcu_delete')) @apcu_delete($key);
    @unlink(sys_get_temp_dir() . '/' . $key . '.cache');
}

/* ============================================================
 * 挑战页解析（slowAES.decrypt）
 * ============================================================ */
function solve_challenge($html) {
    if (!preg_match('/a\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $html, $ma)) return null;
    if (!preg_match('/b\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $html, $mb)) return null;
    if (!preg_match('/c\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $html, $mc)) return null;

    $key    = @hex2bin($ma[1]);
    $iv     = @hex2bin($mb[1]);
    $cipher = @hex2bin($mc[1]);
    if ($key === false || $iv === false || $cipher === false) return null;

    $decrypted = @openssl_decrypt($cipher, 'aes-128-cbc', $key, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false || $decrypted === '') {
        $decrypted = @openssl_decrypt($cipher, 'aes-128-cbc', $key,
                                      OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($decrypted !== false && $decrypted !== '') {
            $decrypted = rtrim($decrypted, "\0");
        }
    }
    if ($decrypted === false || $decrypted === '') return null;

    return '__test=' . bin2hex($decrypted);
}

/* ============================================================
 * 开始向客户端发送上游响应头
 * ============================================================ */
function emit_response_start(&$state) {
    if (!empty($state['headers_sent'])) return;

    if (!headers_sent()) {
        http_response_code($state['status'] > 0 ? $state['status'] : 502);
    }

    /* 过滤 hop-by-hop 与会被我们覆盖的头 */
    static $drop = [
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade',
        'content-encoding', 'content-length',
    ];

    foreach ($state['headers'] as $h) {
        $kl = strtolower($h[0]);
        if (in_array($kl, $drop, true)) continue;
        if (!headers_sent()) {
            header($h[0] . ': ' . $h[1], true);
        }
    }
    $state['headers_sent'] = true;
}

/* ============================================================
 * 核心：向 $url 发起请求，边收边转发
 * ============================================================ */
function curl_fetch_stream($url, $cookie, $method, $body,
                           $resolve_entries, $extra_headers, &$state) {
    $ch = curl_init();

    $state = [
        'status'       => 0,
        'headers'      => [],
        'type'         => '',
        'is_html'      => false,
        'is_challenge' => false,
        'buffered'     => '',
        'headers_sent' => false,
        'streaming'    => false,
    ];

    /* ---- 响应头回调 ---- */
    $header_fn = function($ch, $line) use (&$state) {
        $len = strlen($line);
        $trimmed = rtrim($line, "\r\n");
        if ($trimmed === '') return $len;

        if (preg_match('#^HTTP/\S+\s+(\d+)#i', $trimmed, $m)) {
            $state['status']  = (int)$m[1];
            $state['headers'] = [];
            return $len;
        }

        $pos = strpos($trimmed, ':');
        if ($pos === false) return $len;
        $name  = trim(substr($trimmed, 0, $pos));
        $value = trim(substr($trimmed, $pos + 1));
        $state['headers'][] = [$name, $value];

        if (strcasecmp($name, 'Content-Type') === 0) {
            $state['type'] = $value;
            if (stripos($value, 'text/html') !== false) {
                $state['is_html'] = true;
            }
        }
        return $len;
    };

    /* ---- 响应体回调：决定缓冲还是流式 ---- */
    $write_fn = function($ch, $data) use (&$state) {
        $len = strlen($data);
        if ($len === 0) return 0;

        if ($state['is_challenge']) {
            $state['buffered'] .= $data;
            return $len;
        }

        if ($state['streaming']) {
            echo $data;
            flush();
            return $len;
        }

        $state['buffered'] .= $data;

        if ($state['is_html'] && strpos($state['buffered'], 'slowAES.decrypt') !== false) {
            $state['is_challenge'] = true;
            return $len;
        }

        $threshold = $state['is_html'] ? CHALLENGE_HTML_MAX : 0;
        if (strlen($state['buffered']) >= $threshold) {
            emit_response_start($state);
            echo $state['buffered'];
            flush();
            $state['buffered']  = '';
            $state['streaming'] = true;
        }
        return $len;
    };

    /* ---- 组装 curl 选项 ---- */
    $opts = [
        CURLOPT_URL             => $url,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 5,
        CURLOPT_CONNECTTIMEOUT  => CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT         => TIMEOUT,               /* ★ 3600 */
        CURLOPT_LOW_SPEED_LIMIT => LOW_SPEED_LIMIT,       /* ★ 1024 */
        CURLOPT_LOW_SPEED_TIME  => LOW_SPEED_TIME,        /* ★ 60 */
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_ENCODING        => '',
        CURLOPT_HEADERFUNCTION  => $header_fn,
        CURLOPT_WRITEFUNCTION   => $write_fn,
        CURLOPT_RESOLVE         => $resolve_entries,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        /* ★ C2: 性能相关 */
        CURLOPT_BUFFERSIZE      => 65536,
        CURLOPT_TCP_NODELAY     => true,
        CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_1_1,
        CURLOPT_USERAGENT       =>
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
          . 'AppleWebKit/537.36 (KHTML, like Gecko) '
          . 'Chrome/120.0.0.0 Safari/537.36',
    ];

    /* 请求头：默认 Accept，附加 Cookie 和客户端透传头 */
    $hdrs = ['Accept: */*'];
    if ($cookie) $hdrs[] = 'Cookie: ' . $cookie;
    foreach ($extra_headers as $h) {
        $hdrs[] = $h[0] . ': ' . $h[1];
    }
    $opts[CURLOPT_HTTPHEADER] = $hdrs;

    /* 方法 */
    if ($method === 'HEAD') {
        $opts[CURLOPT_NOBODY] = true;
    } elseif ($method === 'GET') {
        $opts[CURLOPT_HTTPGET] = true;
    } elseif ($method === 'POST') {
        $opts[CURLOPT_POST]       = true;
        $opts[CURLOPT_POSTFIELDS] = $body;
    } else {
        $opts[CURLOPT_CUSTOMREQUEST] = $method;
        if ($body !== '') $opts[CURLOPT_POSTFIELDS] = $body;
    }

    curl_setopt_array($ch, $opts);
    $ok    = curl_exec($ch);
    $errno = curl_errno($ch);
    $err   = curl_error($ch);
    curl_close($ch);

    return [$ok, $errno, $err];
}

/* ============================================================
 * 收尾
 * ============================================================ */
function finish_stream_response(&$state, $errno, $err) {
    if ($errno && empty($state['headers_sent']) && empty($state['streaming'])) {
        relay_error(502, 'upstream error: ' . $err);
    }
    if (empty($state['headers_sent'])) {
        emit_response_start($state);
    }
    if ($state['buffered'] !== '') {
        echo $state['buffered'];
        flush();
        $state['buffered'] = '';
    }
}

/* ============================================================
 * 请求校验
 * ============================================================ */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    relay_error(405, 'method not allowed');
}

$sign = isset($_POST['sign']) && is_string($_POST['sign']) ? $_POST['sign'] : '';
if (!hash_equals(RELAY_SECRET, $sign)) {
    relay_error(403, 'bad sign');
}

$url = isset($_POST['url']) ? trim((string)$_POST['url']) : '';
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    relay_error(400, 'invalid url');
}

$parts = parse_url($url);
if (empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https') {
    relay_error(400, 'only https allowed');
}
if (empty($parts['host'])) {
    relay_error(400, 'no host');
}
$port = isset($parts['port']) ? (int)$parts['port'] : 443;

$ips = gethostbynamel($parts['host']);
if ($ips === false || count($ips) === 0) {
    relay_error(400, 'dns resolve failed');
}
foreach ($ips as $ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP,
                   FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        relay_error(403, 'private address blocked');
    }
}

/* ============================================================
 * 可选字段
 * ============================================================ */
$method = isset($_POST['method']) && is_string($_POST['method'])
        ? strtoupper(trim($_POST['method'])) : 'GET';
if (!in_array($method, ['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS'], true)) {
    $method = 'GET';
}

$req_body = '';
if (isset($_POST['body_b64']) && is_string($_POST['body_b64'])) {
    $decoded = base64_decode($_POST['body_b64'], true);
    if ($decoded === false) relay_error(400, 'invalid body_b64');
    $req_body = $decoded;
}
if (strlen($req_body) > 2 * 1024 * 1024) {
    relay_error(413, 'request body too large');
}

$extra_headers = [];
if (isset($_POST['headers']) && is_string($_POST['headers'])) {
    $parsed = json_decode($_POST['headers'], true);
    if (is_array($parsed)) {
        foreach ($parsed as $item) {
            if (!is_array($item) || count($item) !== 2) continue;
            if (!is_string($item[0]) || !is_string($item[1])) continue;
            $name  = str_replace(["\r", "\n"], '', $item[0]);
            $value = str_replace(["\r", "\n"], '', $item[1]);
            if ($name === '') continue;
            $extra_headers[] = [$name, $value];
            if (count($extra_headers) >= 32) break;
        }
    }
}

/* ============================================================
 * 主流程
 * ============================================================ */
$host            = strtolower($parts['host']);
$resolve_entries = [$host . ':' . $port . ':' . implode(',', $ips)];

/* ---------- 第一次尝试：用缓存 cookie（如果有） ---------- */
$cookie = challenge_cache_get($host);
$state  = null;

if ($cookie !== null) {
    list($ok, $errno, $err) =
        curl_fetch_stream($url, $cookie, $method, $req_body,
                          $resolve_entries, $extra_headers, $state);

    if ($state['is_challenge']) {
        challenge_cache_del($host);
        $cookie = null;
        $state  = null;
    } else {
        finish_stream_response($state, $errno, $err);
        exit;
    }
}

/* ---------- 全新请求 ---------- */
list($ok, $errno, $err) =
    curl_fetch_stream($url, null, $method, $req_body,
                      $resolve_entries, $extra_headers, $state);

/* 触发了挑战：解 cookie、缓存、重试 */
if ($state['is_challenge']) {
    $new_cookie = solve_challenge($state['buffered']);
    if ($new_cookie === null) {
        relay_error(502, 'challenge detected but failed to solve');
    }
    challenge_cache_set($host, $new_cookie);

    $state = null;
    list($ok, $errno, $err) =
        curl_fetch_stream($url, $new_cookie, $method, $req_body,
                          $resolve_entries, $extra_headers, $state);

    if ($state['is_challenge']) {
        relay_error(502, 'challenge persists after cookie');
    }
}

/* 收尾 */
finish_stream_response($state, $errno, $err);
