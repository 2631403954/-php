<?php
/**
 * relay.php —— 流式中继端 (v7)
 *
 * v7 变更摘要：
 *   - 密钥改为从环境变量 RELAY_SECRET 或 ./relay_secret.php 读取，兼容旧值
 *   - DNS 解析支持 IPv4 + IPv6 (dns_get_record)
 *   - 关闭上游压缩 (Accept-Encoding: identity)，避免 curl 透明解压
 *   - 挑战页缓冲阈值 16KB → 64KB
 *   - 挑战检测同时匹配 slowAES.decrypt / toNumbers+decrypt
 *   - 重定向目标私网地址拦截 (CURLOPT_PREREQFUNCTION)
 *   - 临时缓存文件 chmod 0600，避免同主机其他用户读取
 *   - CURLOPT_RESOLVE 正确处理 IPv6 地址（方括号形式）
 */

/* ============================================================
 * 关闭所有输出缓冲
 * ============================================================ */
@ini_set('output_buffering', '0');
@ini_set('zlib.output_compression', '0');
@ini_set('implicit_flush', '1');
while (ob_get_level() > 0) { @ob_end_clean(); }
@ob_implicit_flush(true);
if (function_exists('ini_set')) {
    @ini_set('zlib.output_compression', '0');
    @ini_set('zlib.output_compression_level', '-1');
}

/* ============================================================
 * 配置
 * ============================================================ */
$relay_secret = getenv('RELAY_SECRET');
if ($relay_secret === false || $relay_secret === '') {
    $cfg_file = __DIR__ . '/relay_secret.php';
    if (is_file($cfg_file)) {
        $relay_secret = @include $cfg_file;
    }
}
if (!is_string($relay_secret) || $relay_secret === '') {
    // 兼容 v6 的硬编码回退；生产环境请使用环境变量或 relay_secret.php
    $relay_secret = '314159265358979**//**';
}

define('RELAY_SECRET',       $relay_secret);
define('TIMEOUT',            3600);
define('CONNECT_TIMEOUT',      10);
define('CHALLENGE_TTL',       300);
define('CHALLENGE_HTML_MAX', 64 * 1024);
define('LOW_SPEED_LIMIT',    1024);
define('LOW_SPEED_TIME',       60);

/* ============================================================
 * 工具：私网 / 保留地址判断（IPv4 + IPv6）
 * ============================================================ */
function is_private_ip($ip) {
    if (!is_string($ip) || $ip === '') return true;
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

/* ============================================================
 * 错误输出
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
function challenge_cache_path($host) {
    return sys_get_temp_dir() . '/' . challenge_cache_key($host) . '.cache';
}
function challenge_cache_get($host) {
    $key = challenge_cache_key($host);
    if (function_exists('apcu_fetch')) {
        $v = apcu_fetch($key);
        if ($v !== false && is_string($v) && $v !== '') return $v;
    }
    $path = challenge_cache_path($host);
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
    $path = challenge_cache_path($host);
    @file_put_contents($path, time() . '|' . $cookie, LOCK_EX);
    @chmod($path, 0600);   /* 仅属主可读 */
}
function challenge_cache_del($host) {
    $key = challenge_cache_key($host);
    if (function_exists('apcu_delete')) @apcu_delete($key);
    @unlink(challenge_cache_path($host));
}

/* ============================================================
 * 挑战页识别 & 求解
 * ============================================================ */
function looks_like_challenge($html) {
    if (!is_string($html) || $html === '') return false;
    if (strpos($html, 'slowAES.decrypt') !== false) return true;
    /* 后备标记：某些变体不出现 slowAES.decrypt 字样 */
    if (strpos($html, 'toNumbers(') !== false &&
        strpos($html, 'decrypt(')   !== false) {
        return true;
    }
    return false;
}

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
 * 向客户端发送上游响应头
 * ============================================================ */
function emit_response_start(&$state) {
    if (!empty($state['headers_sent'])) return;

    if (!headers_sent()) {
        http_response_code($state['status'] > 0 ? $state['status'] : 502);
    }

    /* hop-by-hop 头 + 我们无法保证一致的头一律丢弃 */
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

        /* 只有 HTML 响应才需要做挑战检测 */
        if ($state['is_html'] && looks_like_challenge($state['buffered'])) {
            $state['is_challenge'] = true;
            return $len;
        }

        /* 非 HTML：1 字节即流；HTML：缓冲到阈值 */
        $threshold = $state['is_html'] ? CHALLENGE_HTML_MAX : 1;
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
        CURLOPT_TIMEOUT         => TIMEOUT,
        CURLOPT_LOW_SPEED_LIMIT => LOW_SPEED_LIMIT,
        CURLOPT_LOW_SPEED_TIME  => LOW_SPEED_TIME,
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,
        CURLOPT_ENCODING        => 'identity',   /* 不接受上游压缩 */
        CURLOPT_HEADERFUNCTION  => $header_fn,
        CURLOPT_WRITEFUNCTION   => $write_fn,
        CURLOPT_RESOLVE         => $resolve_entries,
        CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_BUFFERSIZE      => 65536,
        CURLOPT_TCP_NODELAY     => true,
        CURLOPT_HTTP_VERSION    => CURL_HTTP_VERSION_1_1,
        CURLOPT_USERAGENT       =>
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
          . 'AppleWebKit/537.36 (KHTML, like Gecko) '
          . 'Chrome/120.0.0.0 Safari/537.36',
    ];

    /* 重定向目标私网地址拦截（libcurl >= 7.80 / PHP >= 8.2） */
    if (defined('CURLOPT_PREREQFUNCTION') && defined('CURL_PREREQFUNC_OK')) {
        $opts[CURLOPT_PREREQFUNCTION] = function($ch, $primary_ip, $primary_port) {
            if (is_string($primary_ip) && $primary_ip !== '' && is_private_ip($primary_ip)) {
                return CURL_PREREQFUNC_ABORT;
            }
            return CURL_PREREQFUNC_OK;
        };
    }

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

/* ============================================================
 * DNS 解析（支持 IPv4 + IPv6）
 * ============================================================ */
$host = $parts['host'];
$ips  = [];
$recs = @dns_get_record($host, DNS_A | DNS_AAAA);
if (is_array($recs)) {
    foreach ($recs as $r) {
        if (!empty($r['ip']))   $ips[] = $r['ip'];
        if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    }
}
if (empty($ips)) {
    /* 回退到系统 IPv4 解析 */
    $v4 = @gethostbynamel($host);
    if (is_array($v4)) $ips = $v4;
}
if (empty($ips)) {
    relay_error(400, 'dns resolve failed');
}
foreach ($ips as $ip) {
    if (is_private_ip($ip)) {
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
$host_lc = strtolower($host);

/* 构造 CURLOPT_RESOLVE 条目：IPv6 需要方括号 */
$addr_list = [];
foreach ($ips as $ip) {
    $addr_list[] = (strpos($ip, ':') !== false) ? '[' . $ip . ']' : $ip;
}
$resolve_entries = [$host_lc . ':' . $port . ':' . implode(',', $addr_list)];

/* ---------- 第一次尝试：用缓存 cookie（如果有） ---------- */
$cookie = challenge_cache_get($host_lc);
$state  = null;

if ($cookie !== null) {
    list($ok, $errno, $err) =
        curl_fetch_stream($url, $cookie, $method, $req_body,
                          $resolve_entries, $extra_headers, $state);

    if ($state['is_challenge']) {
        challenge_cache_del($host_lc);
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
    challenge_cache_set($host_lc, $new_cookie);

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
