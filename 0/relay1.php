<?php
/**
 * relay.php —— PHP 中继端（v4）
 *
 * 协议：
 *   POST 本脚本
 *   body:
 *     sign     = <RELAY_SECRET>                必填
 *     url      = <urlencoded 绝对 URL>          必填，必须 https
 *     method   = <GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS>  可选，默认 GET
 *     body_b64 = <urlencoded base64(请求体)>     可选
 *
 * 返回 JSON:
 *   成功: HTTP 200 + {
 *       "code": 0, "msg": "ok",
 *       "status": <int>, "url": "...", "len": <int>,
 *       "body_b64": "...",
 *       "headers": [["Content-Type","text/html"], ...]
 *   }
 *   失败: HTTP 4xx/5xx + {"code": <int>, "msg": "..."}
 *
 * 变更（v4）：
 *   - 透传上游响应头（过滤 hop-by-hop + Content-Length/Content-Encoding）
 *   - CURLOPT_RESOLVE 固定 DNS，防 rebinding
 *   - 挑战 cookie 缓存（APCu / 文件，5 分钟）
 *   - 首请求带缓存 cookie，省一次往返
 *   - CURLOPT_PROTOCOLS 双保险
 *   - 连接/总超时分离
 */

header('Content-Type: application/json; charset=utf-8');

define('RELAY_SECRET',    '314159265358979**//**'); // 务必修改，与 C 端一致
define('MAX_BODY',        2 * 1024 * 1024);
define('MAX_REQ_BODY',    2 * 1024 * 1024);
define('TIMEOUT',         15);
define('CONNECT_TIMEOUT', 8);
define('CHALLENGE_TTL',   300);

/* ============================================================
 * 通用输出
 * ============================================================ */
function out($code, $msg, $extra = []) {
    if ($code !== 0) http_response_code($code);
    echo json_encode(array_merge(['code' => $code, 'msg' => $msg], $extra),
                     JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

/* ============================================================
 * 请求校验
 * ============================================================ */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    out(405, 'method not allowed');
}

$sign = isset($_POST['sign']) && is_string($_POST['sign']) ? $_POST['sign'] : '';
if (!hash_equals(RELAY_SECRET, $sign)) {
    out(403, 'bad sign');
}

$url = isset($_POST['url']) ? trim((string)$_POST['url']) : '';
if (!filter_var($url, FILTER_VALIDATE_URL)) {
    out(400, 'invalid url');
}

$parts = parse_url($url);
if (empty($parts['scheme']) || strtolower($parts['scheme']) !== 'https') {
    out(400, 'only https allowed');
}
if (empty($parts['host'])) {
    out(400, 'no host');
}

$port = isset($parts['port']) ? (int)$parts['port'] : 443;

$ips = gethostbynamel($parts['host']);
if ($ips === false || count($ips) === 0) {
    out(400, 'dns resolve failed');
}
foreach ($ips as $ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP,
                   FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        out(403, 'private address blocked');
    }
}

/* ============================================================
 * 可选字段
 * ============================================================ */
$method = isset($_POST['method']) && is_string($_POST['method'])
        ? strtoupper(trim($_POST['method'])) : 'GET';
$allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
if (!in_array($method, $allowed_methods, true)) {
    $method = 'GET';
}

$req_body = '';
if (isset($_POST['body_b64']) && is_string($_POST['body_b64'])) {
    $decoded = base64_decode($_POST['body_b64'], true);
    if ($decoded === false) {
        out(400, 'invalid body_b64');
    }
    $req_body = $decoded;
} elseif (isset($_POST['body']) && is_string($_POST['body'])) {
    $req_body = $_POST['body'];
}
if (strlen($req_body) > MAX_REQ_BODY) {
    out(413, 'request body too large (>' . MAX_REQ_BODY . ' bytes)');
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
    if (time() - $ts > CHALLENGE_TTL) {
        @unlink($path);
        return null;
    }
    return $cookie;
}

function challenge_cache_set($host, $cookie) {
    if ($cookie === '') return;
    $key = challenge_cache_key($host);

    if (function_exists('apcu_store')) {
        apcu_store($key, $cookie, CHALLENGE_TTL);
        return;
    }

    $path = sys_get_temp_dir() . '/' . $key . '.cache';
    @file_put_contents($path, time() . '|' . $cookie, LOCK_EX);
}

/* ============================================================
 * 上游请求
 * ============================================================ */
function fetch_url($url, $cookie, $method, $body, $resolve_entries) {
    $ch = curl_init();

    /* 收集最终那组响应头（重定向时丢弃中间的） */
    $resp_headers = [];
    $header_fn = function($ch, $line) use (&$resp_headers) {
        $len = strlen($line);
        $trimmed = rtrim($line, "\r\n");
        if ($trimmed === '') return $len;
        if (preg_match('#^HTTP/#i', $trimmed)) {
            /* 新的响应开始，丢弃之前累积的头 */
            $resp_headers = [];
            return $len;
        }
        $pos = strpos($trimmed, ':');
        if ($pos === false) return $len;
        $resp_headers[] = [
            trim(substr($trimmed, 0, $pos)),
            trim(substr($trimmed, $pos + 1)),
        ];
        return $len;
    };

    $opts = [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_TIMEOUT        => TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_ENCODING       => '',
        CURLOPT_HEADERFUNCTION => $header_fn,
        CURLOPT_USERAGENT      =>
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
          . 'AppleWebKit/537.36 (KHTML, like Gecko) '
          . 'Chrome/120.0.0.0 Safari/537.36',
        CURLOPT_HTTPHEADER     => ['Accept: */*'],
        /* DNS rebinding 防护：把 host 固定到已校验过的 IP */
        CURLOPT_RESOLVE        => $resolve_entries,
        /* 只允许 https（含重定向） */
        CURLOPT_PROTOCOLS        => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS  => CURLPROTO_HTTPS,
    ];

    if ($cookie) {
        $opts[CURLOPT_COOKIE] = $cookie;
    }

    if ($method === 'HEAD') {
        $opts[CURLOPT_NOBODY] = true;
    } elseif ($method === 'GET') {
        $opts[CURLOPT_HTTPGET] = true;
    } elseif ($method === 'POST') {
        $opts[CURLOPT_POST]       = true;
        $opts[CURLOPT_POSTFIELDS] = $body;
    } else {
        $opts[CURLOPT_CUSTOMREQUEST] = $method;
        if ($body !== '') {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
    }

    curl_setopt_array($ch, $opts);
    $resp  = curl_exec($ch);
    $errno = curl_errno($ch);
    $err   = curl_error($ch);
    $info  = curl_getinfo($ch);
    curl_close($ch);

    return [$resp, $errno, $err, $info, $resp_headers];
}

function is_text_content_type($ct) {
    if (!is_string($ct) || $ct === '') return false;
    return (bool)preg_match('#^(text/|application/(json|javascript|xml|xhtml))#i', $ct);
}

/* hop-by-hop + 会被我们覆盖的头 */
function filter_response_headers($headers) {
    $drop = [
        'connection', 'keep-alive', 'proxy-authenticate',
        'proxy-authorization', 'te', 'trailers',
        'transfer-encoding', 'upgrade',
        'content-length',      // 我们自己按最终 body 长度算
        'content-encoding',    // curl 已解压
    ];
    $out = [];
    foreach ($headers as $h) {
        $kl = strtolower($h[0]);
        if (in_array($kl, $drop, true)) continue;
        $out[] = [$h[0], $h[1]];
    }
    return $out;
}

/* ============================================================
 * 主流程
 * ============================================================ */
$host           = strtolower($parts['host']);
$resolve_entries = [$host . ':' . $port . ':' . implode(',', $ips)];

/* 先尝试用缓存 cookie 直接请求（省一次往返） */
$cached_cookie = challenge_cache_get($host);
$used_cached   = false;

if ($cached_cookie !== null) {
    list($body, $errno, $err, $info, $resp_headers) =
        fetch_url($url, $cached_cookie, $method, $req_body, $resolve_entries);

    $content_type = $info['content_type'] ?? '';
    $is_text_type = is_text_content_type($content_type);

    /* 缓存 cookie 失效，又回到挑战页 */
    if ($errno || ($is_text_type && strpos((string)$body, 'slowAES.decrypt') !== false)) {
        $cached_cookie = null;
        @apcu_delete(challenge_cache_key($host));
        @unlink(sys_get_temp_dir() . '/' . challenge_cache_key($host) . '.cache');
    } else {
        $used_cached = true;
    }
}

/* 无缓存或缓存失效 → 正常请求一次 */
if (!$used_cached) {
    list($body, $errno, $err, $info, $resp_headers) =
        fetch_url($url, null, $method, $req_body, $resolve_entries);
    if ($errno) {
        out(502, 'upstream error: ' . $err);
    }

    $content_type = $info['content_type'] ?? '';
    $is_text_type = is_text_content_type($content_type);

    /* ========== slowAES 挑战 ========== */
    if ($is_text_type && strpos((string)$body, 'slowAES.decrypt') !== false) {
        preg_match('/a\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $body, $ma);
        preg_match('/b\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $body, $mb);
        preg_match('/c\s*=\s*toNumbers\("([0-9a-f]+)"\)/i', $body, $mc);

        if (empty($ma[1]) || empty($mb[1]) || empty($mc[1])) {
            out(500, 'challenge detected but regex failed', [
                'debug_a' => $ma, 'debug_b' => $mb, 'debug_c' => $mc,
            ]);
        }

        $key    = hex2bin($ma[1]);
        $iv     = hex2bin($mb[1]);
        $cipher = hex2bin($mc[1]);

        $decrypted = openssl_decrypt($cipher, 'aes-128-cbc', $key,
                                     OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false || $decrypted === '') {
            $decrypted = openssl_decrypt($cipher, 'aes-128-cbc', $key,
                                         OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
            if ($decrypted !== false && $decrypted !== '') {
                $decrypted = rtrim($decrypted, "\0");
            }
        }
        if ($decrypted === false || $decrypted === '') {
            out(500, 'AES decryption failed: ' . openssl_error_string());
        }

        $cookie_str = '__test=' . bin2hex($decrypted);
        list($body, $errno, $err, $info, $resp_headers) =
            fetch_url($url, $cookie_str, $method, $req_body, $resolve_entries);
        if ($errno) {
            out(502, 'upstream error after cookie: ' . $err);
        }

        $content_type = $info['content_type'] ?? '';
        $is_text_type = is_text_content_type($content_type);

        /* 记入缓存，下次同域名直接命中 */
        challenge_cache_set($host, $cookie_str);
    }
}

/* ============================================================
 * 编码统一（仅文本类型）
 * ============================================================ */
if ($is_text_type && !mb_check_encoding($body, 'UTF-8')) {
    $charset = '';
    if (!empty($info['content_type']) &&
        preg_match('/charset\s*=\s*["\']?([\w\-]+)/i', $info['content_type'], $m)) {
        $charset = strtoupper($m[1]);
    }
    if (!$charset &&
        preg_match('/charset\s*=\s*["\']?([\w\-]+)/i', substr($body, 0, 4096), $m)) {
        $charset = strtoupper($m[1]);
    }
    $alias = [
        'GB2312'  => 'GBK',
        'GBK'     => 'GBK',
        'GB18030' => 'GB18030',
        'BIG5'    => 'BIG-5',
        'BIG-5'   => 'BIG-5',
    ];
    if (isset($alias[$charset])) $charset = $alias[$charset];

    if ($charset !== '' && $charset !== 'UTF-8') {
        $converted = false;
        if (function_exists('mb_convert_encoding')) {
            $converted = @mb_convert_encoding($body, 'UTF-8', $charset);
        }
        if ($converted === false && function_exists('iconv')) {
            $converted = @iconv($charset, 'UTF-8//IGNORE', $body);
        }
        if ($converted !== false && $converted !== null) {
            $body = $converted;
            $body = preg_replace(
                '/(<meta[^>]*charset\s*=\s*["\']?)[\w\-]+/i',
                '${1}UTF-8',
                $body
            );
        }
    }
}

/* ============================================================
 * 大小检查 + 输出
 * ============================================================ */
if (strlen($body) > MAX_BODY) {
    out(502, 'response too large (>' . MAX_BODY . ' bytes)');
}

$clean_headers = filter_response_headers($resp_headers);

out(0, 'ok', [
    'status'   => $info['http_code'],
    'url'      => $info['url'],
    'len'      => strlen($body),
    'body_b64' => base64_encode($body),
    'headers'  => $clean_headers,
]);
