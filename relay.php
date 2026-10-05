<?php
/**
 * relay.php —— 流式中继端 (v10)
 *
 * v10 变更（人机验证参数双向传递）：
 *   - [🔴] 新增 challenge_cookie（别名 cookie）：调用方把已解出的验证 cookie
 *          （如 __test=xxx）交给本端，本端原样发给上游。
 *   - [🔴] Cookie 归一化：challenge_cookie + 服务端缓存 + headers 里的 Cookie
 *          全部合并到一个 Cookie: 头，一次请求只发一个 Cookie 头。
 *   - [🔴] 新增 challenge=auto|client
 *   - [🟠] challenge=client 时挑战检测不再要求 Content-Type 是 text/html
 *   - [🟡] 新增 cache_cookie=1
 *
 * 请求字段：
 *   sign            必填
 *   url             必填，仅 https
 *   method          可选
 *   headers         可选，JSON [["Name","Value"], ...]，最多 32 条
 *   body_b64        可选
 *   challenge_cookie 可选，要发给上游的 Cookie 值（如 __test=xxx）
 *   challenge       可选，auto（默认）| client
 *   cache_cookie    可选，1 表示把 challenge_cookie 整串按 host 缓存
 */

@ini_set('output_buffering', '0');
@ini_set('zlib.output_compression', '0');
@ini_set('implicit_flush', '1');
while (ob_get_level() > 0) { @ob_end_clean(); }
@ob_implicit_flush(true);
if (function_exists('ini_set')) {
    @ini_set('zlib.output_compression', '0');
    @ini_set('zlib.output_compression_level', '-1');
}

function relay_error($http_code, $msg) {
    if (!headers_sent()) {
        http_response_code($http_code);
        header('X-Relay-Error: 1');
        header('Content-Type: text/plain; charset=utf-8');
    }
    echo $msg;
    exit;
}

$relay_secret = getenv('RELAY_SECRET');
if ($relay_secret === false || $relay_secret === '') {
    $cfg_file = __DIR__ . '/relay_secret.php';
    if (is_file($cfg_file)) {
        $loaded = @include $cfg_file;
        if (is_string($loaded) && $loaded !== '') {
            $relay_secret = $loaded;
        } else {
            relay_error(500, 'relay_secret.php must return a non-empty string');
        }
    }
}
if (!is_string($relay_secret) || $relay_secret === '') {
    if (getenv('RELAY_ALLOW_LEGACY') === '1') {
        $relay_secret = '314159265358979**//**';
        error_log('relay: using legacy hardcoded secret (RELAY_ALLOW_LEGACY=1)');
    } else {
        relay_error(500, 'relay secret not configured');
    }
}

define('RELAY_SECRET',       $relay_secret);
define('TIMEOUT',            3600);
define('CONNECT_TIMEOUT',      10);
define('CHALLENGE_TTL',       300);
define('CHALLENGE_HTML_MAX', 64 * 1024);
define('CHALLENGE_MAX_LEN',   1024 * 1024);
define('COOKIE_MAX_LEN',      8 * 1024);
define('LOW_SPEED_LIMIT',    1024);
define('LOW_SPEED_TIME',       60);
define('MAX_URL_LEN',        8192);
define('MAX_RESP_HEADERS',    200);

function is_private_ip($ip) {
    if (!is_string($ip) || $ip === '') return true;
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

function challenge_cache_dir() {
    static $dir = null;
    if ($dir !== null) return $dir;
    $env = getenv('RELAY_CACHE_DIR');
    if (is_string($env) && $env !== '' && is_dir($env) && is_writable($env)) {
        $dir = rtrim($env, '/\\');
        return $dir;
    }
    $dir = sys_get_temp_dir();
    return $dir;
}
function challenge_cache_key($host) {
    return 'relay_test_' . md5(strtolower($host));
}
function challenge_cache_path($host) {
    return challenge_cache_dir() . '/' . challenge_cache_key($host) . '.cache';
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
    @chmod($path, 0600);
}
function challenge_cache_del($host) {
    $key = challenge_cache_key($host);
    if (function_exists('apcu_delete')) @apcu_delete($key);
    @unlink(challenge_cache_path($host));
}

function looks_like_challenge($html) {
    if (!is_string($html) || $html === '') return false;
    if (strpos($html, 'slowAES.decrypt') !== false) return true;
    if (strpos($html, 'slowAES') !== false &&
        substr_count($html, 'toNumbers(') >= 3) {
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

function relay_clean_header_value($v, $max) {
    if (!is_string($v)) return '';
    $v = str_replace(["\r", "\n", "\0"], '', $v);
    $v = trim($v);
    if ($max > 0 && strlen($v) > $max) $v = substr($v, 0, $max);
    return $v;
}
function relay_extract_test_cookie($cookie) {
    if (!is_string($cookie) || $cookie === '') return '';
    if (preg_match('/(?:^|;)\s*__test=([0-9a-fA-F]+)/', $cookie, $m)) {
        return '__test=' . $m[1];
    }
    if (preg_match('/^[0-9a-fA-F]{16,64}$/', $cookie, $m)) {
        return '__test=' . $m[0];
    }
    return '';
}
function relay_cache_client_cookie($host, $cookie, $cache_all) {
    if (!is_string($cookie) || $cookie === '') return;
    if ($cache_all) { challenge_cache_set($host, $cookie); return; }
    $t = relay_extract_test_cookie($cookie);
    if ($t !== '') challenge_cache_set($host, $t);
}
function relay_emit_challenge(&$state) {
    if (empty($state['headers_sent'])) {
        $state['headers'][] = ['X-Relay-Challenge', '1'];
        $state['headers'][] = ['Cache-Control',      'no-store'];
        emit_response_start($state);
    }
    if (!empty($state['buffered'])) {
        echo $state['buffered'];
        $state['buffered'] = '';
    }
    @flush();
    exit;
}

function emit_response_start(&$state) {
    if (!empty($state['headers_sent'])) return;

    if (!headers_sent()) {
        http_response_code($state['status'] > 0 ? $state['status'] : 502);
    }

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

function curl_fetch_stream($url, $cookie, $method, $body,
                           $resolve_entries, $extra_headers, &$state,
                           $client_cookie = '', $challenge_mode = 'auto') {
    $ch = curl_init();

    $state = [
        'status'         => 0,
        'headers'        => [],
        'type'           => '',
        'is_html'        => false,
        'is_challenge'   => false,
        'buffered'       => '',
        'headers_sent'   => false,
        'streaming'      => false,
        'challenge_mode' => ($challenge_mode === 'client' ? 'client' : 'auto'),
    ];

    $header_fn = function($ch, $line) use (&$state) {
        $len = strlen($line);
        $trimmed = rtrim($line, "\r\n");
        if ($trimmed === '') return $len;

        if (preg_match('#^HTTP/\S+\s+(\d+)#i', $trimmed, $m)) {
            $state['status']  = (int)$m[1];
            $state['headers'] = [];
            $state['type']    = '';
            $state['is_html'] = false;
            return $len;
        }

        $pos = strpos($trimmed, ':');
        if ($pos === false) return $len;
        $name  = trim(substr($trimmed, 0, $pos));
        $value = trim(substr($trimmed, $pos + 1));

        if (strcasecmp($name, 'Content-Type') === 0) {
            $state['type'] = $value;
            if (stripos($value, 'text/html') !== false) {
                $state['is_html'] = true;
            }
        }
        if (count($state['headers']) < MAX_RESP_HEADERS) {
            $state['headers'][] = [$name, $value];
        }
        return $len;
    };

    $write_fn = function($ch, $data) use (&$state) {
        $len = strlen($data);
        if ($len === 0) return 0;

        if ($state['is_challenge']) {
            if (strlen($state['buffered']) >= CHALLENGE_MAX_LEN) {
                return 0;
            }
            $state['buffered'] .= $data;
            return $len;
        }

        if ($state['streaming']) {
            echo $data;
            flush();
            return $len;
        }

        $state['buffered'] .= $data;

        $client_mode = ($state['challenge_mode'] === 'client');
        $detected = $client_mode
                  ? looks_like_challenge($state['buffered'])
                  : ($state['is_html'] && looks_like_challenge($state['buffered']));
        if ($detected) {
            $state['is_challenge'] = true;
            return $len;
        }

        $threshold = $state['is_html'] ? CHALLENGE_HTML_MAX
                                       : ($client_mode ? 8192 : 1);
        if (strlen($state['buffered']) >= $threshold) {
            emit_response_start($state);
            echo $state['buffered'];
            flush();
            $state['buffered']  = '';
            $state['streaming'] = true;
        }
        return $len;
    };

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
        CURLOPT_ENCODING        => '',
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

    if (defined('CURLOPT_PREREQFUNCTION') && defined('CURL_PREREQFUNC_OK')) {
        $opts[CURLOPT_PREREQFUNCTION] = function(
            $ch, $primary_ip, $primary_port, $local_ip, $local_port
        ) {
            if (is_string($primary_ip) && $primary_ip !== '' && is_private_ip($primary_ip)) {
                return CURL_PREREQFUNC_ABORT;
            }
            return CURL_PREREQFUNC_OK;
        };
    }

    /* ★ Cookie 归一化：challenge_cookie + 服务端缓存 + headers 里的 Cookie
       全部合并到一个 Cookie: 头（v9 是二选一，会丢浏览器 cookie）。 */
    $cookie_parts = [];
    if (is_string($client_cookie) && $client_cookie !== '') {
        $cookie_parts[] = $client_cookie;
    } elseif (is_string($cookie) && $cookie !== '') {
        $cookie_parts[] = $cookie;
    }

    $hdrs = ['Accept: */*', 'Expect:'];
    foreach ($extra_headers as $h) {
        if (strcasecmp($h[0], 'Cookie') === 0) {
            if ($h[1] !== '') $cookie_parts[] = $h[1];
            continue;
        }
        $hdrs[] = $h[0] . ': ' . $h[1];
    }
    if (!empty($cookie_parts)) {
        $hdrs[] = 'Cookie: ' . implode('; ', $cookie_parts);
    }
    $opts[CURLOPT_HTTPHEADER] = $hdrs;

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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    relay_error(405, 'method not allowed');
}

$sign = isset($_POST['sign']) && is_string($_POST['sign']) ? $_POST['sign'] : '';
if (!hash_equals(RELAY_SECRET, $sign)) {
    relay_error(403, 'bad sign');
}

$url = isset($_POST['url']) ? trim((string)$_POST['url']) : '';
if (strlen($url) > MAX_URL_LEN) {
    relay_error(400, 'url too long');
}
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

$host = $parts['host'];
$is_ip_literal = false;
$hlen = strlen($host);
if ($hlen >= 2 && $host[0] === '[' && $host[$hlen - 1] === ']') {
    $host = substr($host, 1, $hlen - 2);
    $is_ip_literal = true;
}

$ips = [];
if ($is_ip_literal) {
    if (!filter_var($host, FILTER_VALIDATE_IP)) {
        relay_error(400, 'invalid ip literal');
    }
    $ips = [$host];
} else {
    $v4 = @gethostbynamel($host);
    if (is_array($v4)) $ips = $v4;

    $recs = @dns_get_record($host, DNS_AAAA);
    if (is_array($recs)) {
        foreach ($recs as $r) {
            if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
        }
    }
}
if (empty($ips)) {
    relay_error(400, 'dns resolve failed');
}
foreach ($ips as $ip) {
    if (is_private_ip($ip)) {
        relay_error(403, 'private address blocked');
    }
}

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

$client_cookie = '';
if (isset($_POST['challenge_cookie']) && is_string($_POST['challenge_cookie'])) {
    $client_cookie = relay_clean_header_value($_POST['challenge_cookie'], COOKIE_MAX_LEN);
} elseif (isset($_POST['cookie']) && is_string($_POST['cookie'])) {
    $client_cookie = relay_clean_header_value($_POST['cookie'], COOKIE_MAX_LEN);
}

$cookie_in_headers = false;
foreach ($extra_headers as $h) {
    if (strcasecmp($h[0], 'Cookie') === 0 && $h[1] !== '') { $cookie_in_headers = true; break; }
}

$challenge_mode = 'auto';
if (isset($_POST['challenge']) && is_string($_POST['challenge'])) {
    $mode_in = strtolower(trim($_POST['challenge']));
    if ($mode_in === 'client' || $mode_in === 'auto') $challenge_mode = $mode_in;
}

$cache_client_cookie = false;
if (isset($_POST['cache_cookie']) && is_string($_POST['cache_cookie'])) {
    $v = strtolower(trim($_POST['cache_cookie']));
    $cache_client_cookie = ($v === '1' || $v === 'true' || $v === 'yes');
}

$host_lc = strtolower($host);

$resolve_entries = [];
if (!$is_ip_literal) {
    $addr_list = [];
    foreach ($ips as $ip) {
        $addr_list[] = (strpos($ip, ':') !== false) ? '[' . $ip . ']' : $ip;
    }
    $resolve_entries = [$host_lc . ':' . $port . ':' . implode(',', $addr_list)];
}

$cookie = ($client_cookie !== '' || $cookie_in_headers)
        ? null
        : challenge_cache_get($host_lc);
$state  = null;

if ($cookie !== null || $client_cookie !== '' || $cookie_in_headers) {
    list($ok, $errno, $err) =
        curl_fetch_stream($url, $cookie, $method, $req_body,
                          $resolve_entries, $extra_headers, $state,
                          $client_cookie, $challenge_mode);

    if ($state['is_challenge']) {
        if ($challenge_mode === 'client') {
            if ($cookie !== null) challenge_cache_del($host_lc);
            relay_emit_challenge($state);
        }
        if ($client_cookie !== '') {
            $client_cookie = '';
        } else {
            challenge_cache_del($host_lc);
            if ($cookie_in_headers) {
                $kept = [];
                foreach ($extra_headers as $h) {
                    if (strcasecmp($h[0], 'Cookie') !== 0) $kept[] = $h;
                }
                $extra_headers    = $kept;
                $cookie_in_headers = false;
            }
        }
        $cookie = null;
        $state  = null;
    } else {
        relay_cache_client_cookie($host_lc, $client_cookie, $cache_client_cookie);
        finish_stream_response($state, $errno, $err);
        exit;
    }
}

list($ok, $errno, $err) =
    curl_fetch_stream($url, null, $method, $req_body,
                      $resolve_entries, $extra_headers, $state,
                      '', $challenge_mode);

if ($state['is_challenge']) {
    if ($challenge_mode === 'client') {
        relay_emit_challenge($state);
    }

    $new_cookie = solve_challenge($state['buffered']);
    if ($new_cookie === null) {
        relay_emit_challenge($state);
    }
    challenge_cache_set($host_lc, $new_cookie);

    if (!headers_sent()) {
        header('X-Relay-Cookie: ' . $new_cookie);
    }

    $state = null;
    list($ok, $errno, $err) =
        curl_fetch_stream($url, $new_cookie, $method, $req_body,
                          $resolve_entries, $extra_headers, $state,
                          '', $challenge_mode);

    if ($state['is_challenge']) {
        relay_emit_challenge($state);
    }
}

finish_stream_response($state, $errno, $err);
