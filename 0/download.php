<?php
// batch_download.php - 批量下载 Pixiv 图片（通过 PHProxy）
// 修复逻辑：兼容字符串 "false"、增加文件头校验、杜绝写入 JSON 文本
// 修改：压缩包内文件名使用原始 ID 前缀，如 147689870_p0.jpg

session_start();
set_time_limit(0);
ini_set('memory_limit', '512M');

// 处理删除请求
if (isset($_GET['delete']) && preg_match('/^pixiv_\d+_[a-f0-9]+\.zip$/', $_GET['delete'])) {
    $zip_name = $_GET['delete'];
    $zip_path = __DIR__ . '/pixiv/' . $zip_name;
    if (file_exists($zip_path) && unlink($zip_path)) {
        die('success');
    } else {
        die('failed');
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['base_url'], $_POST['count'])) {
    $base_url = trim($_POST['base_url']);
    $count    = (int) $_POST['count'];
    if ($count < 1) $count = 1;
    if ($count > 50) $count = 50;

    $_SESSION['last_base_url'] = $base_url;
    $_SESSION['last_count']    = $count;

    if (!preg_match('/_p\d+\.\w+$/i', $base_url)) {
        die('基础 URL 必须包含 _p0.扩展名（如 _p0.png）');
    }

    $base_path = preg_replace('/_p\d+\.\w+$/i', '', $base_url);
    $ext = pathinfo(parse_url($base_url, PHP_URL_PATH), PATHINFO_EXTENSION);
    if (!$ext) $ext = 'png';

    // 替换为 pixiv.cat 代理域名
    $base_path = preg_replace('#^https?://i\.pximg\.net/#', 'https://i.pixiv.cat/', $base_path);

    $temp_dir = __DIR__ . '/downloads';
    $save_dir = __DIR__ . '/pixiv';
    if (!is_dir($temp_dir)) mkdir($temp_dir, 0755, true);
    if (!is_dir($save_dir)) mkdir($save_dir, 0755, true);

    $proxy_api = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
               . '://' . $_SERVER['HTTP_HOST']
               . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/')
               . '/index.php?api=fetch';

    $files = [];
    $errors = [];

    // ---------- 修改开始：提取基础文件名（不含 _p数字.扩展名） ----------
    $base_name = basename($base_path);   // 例如 "147689870"
    // -----------------------------------------------------------------

    for ($i = 0; $i < $count; $i++) {
        $img_url = $base_path . '_p' . $i . '.' . $ext;

        // ---------- 修改：文件名使用 $base_name 作为前缀 ----------
        $filename = $base_name . '_p' . $i . '.' . $ext;   // 例如 "147689870_p0.jpg"
        // ---------------------------------------------------------

        $save_path = $temp_dir . '/' . $filename;

        $success = false;
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $payload = json_encode([
                'url'      => $img_url,
                'method'   => 'GET',
                'return'   => 'raw',
                'verify_ssl' => false,
                'timeout'  => 30,
            ]);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => $proxy_api,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Referer: https://www.pixiv.net/'
                ],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_TIMEOUT => 300,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_ENCODING => '',
                CURLOPT_HEADER => false,
            ]);
            $response = curl_exec($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $content_type = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
            $downloaded_size = curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD);
            $err = curl_error($ch);
            curl_close($ch);

            if ($http_code === 200 && $response !== false && strlen($response) > 0) {
                
                // 1. 解析 JSON 响应
                $decoded = json_decode($response, true);
                $is_json = is_array($decoded);
                $is_img_binary = (strpos($content_type, 'image/') === 0 || strpos($content_type, 'application/octet-stream') === 0);
                $is_html = strpos($content_type, 'text/html') !== false;

                // 2. 明确检测 API 返回的 JSON 错误（兼容字符串 "false"）
                if ($is_json && isset($decoded['ok']) && !$decoded['ok']) {
                    $errors[] = "第 {$i} 张图片 API 返回错误：" . ($decoded['error'] ?? 'unknown');
                    continue;
                }

                // 3. 提取真实图片二进制数据
                if ($is_json && isset($decoded['body_raw'])) {
                    $image_data = $decoded['body_raw'];
                    // 检测并解码 Base64 (PHProxy 有时会返回 Base64)
                    if (preg_match('/^[a-zA-Z0-9+\/=]+$/', $image_data) && base64_decode($image_data, true) !== false) {
                        $image_data = base64_decode($image_data);
                    }
                } else {
                    // 非 JSON 响应，尝试作为原始二进制
                    if ($is_html && !$is_img_binary) {
                        $errors[] = "第 {$i} 张图片请求返回了 HTML 页面（可能是 403/404 错误）";
                        continue;
                    }
                    $image_data = $response;
                }

                // 4. 校验文件是否有效（过滤错误 HTML 文本或 JSON 文本）
                if (strlen($image_data) > 12) {
                    $header = substr($image_data, 0, 12);
                    $is_valid_file = false;
                    // 校验常见图片头
                    if (str_starts_with($header, "\x89PNG") || str_starts_with($header, "\xFF\xD8") || str_starts_with($header, "GIF8")) {
                        $is_valid_file = true;
                    }
                    // 如果是 WebP 或 BMP
                    if (!$is_valid_file && (str_starts_with($header, "RIFF") && substr($image_data, 8, 4) === "WEBP")) {
                        $is_valid_file = true;
                    }
                    if (!$is_valid_file) {
                        $errors[] = "第 {$i} 张图片文件头校验失败，可能为错误页面内容";
                        continue;
                    }
                }

                // 5. 保存文件
                if (file_put_contents($save_path, $image_data) !== false) {
                    $actual_size = filesize($save_path);
                    // 根据来源判断预期文件大小（如果是 Base64 解码的，则使用解码后的长度作为预期）
                    $expected_size = ($is_json && isset($decoded['body_raw'])) ? strlen($image_data) : $downloaded_size;

                    if ($expected_size > 0 && $actual_size < $expected_size * 0.9) {
                        $errors[] = "第 {$i} 张图片下载不完整（预期约 {$expected_size}，实际 {$actual_size}）";
                        unlink($save_path);
                        continue;
                    }

                    $files[] = $filename;
                    $success = true;
                    break;
                } else {
                    $errors[] = "保存文件 $filename 失败";
                    continue;
                }
            } else {
                $errors[] = "第 {$i} 张图片尝试 {$attempt} 失败：HTTP {$http_code}，错误：$err";
                if ($attempt < 3) sleep(2);
            }
        }
        if (!$success) {
            $errors[] = "第 {$i} 张图片最终下载失败。";
        }
    }

    if (!empty($files)) {
        $zip_name = 'pixiv_' . date('YmdHis') . '_' . substr(md5(uniqid()), 0, 8) . '.zip';
        $zip_path = $save_dir . '/' . $zip_name;

        $zip = new ZipArchive();
        if ($zip->open($zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
            foreach ($files as $f) {
                $zip->addFile($temp_dir . '/' . $f, $f);
            }
            $zip->close();

            foreach ($files as $f) unlink($temp_dir . '/' . $f);

            $zip_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                     . '://' . $_SERVER['HTTP_HOST']
                     . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/')
                     . '/pixiv/' . $zip_name;
            $delete_url = $_SERVER['SCRIPT_NAME'] . '?delete=' . urlencode($zip_name);
            $return_url = $_SERVER['SCRIPT_NAME'];
            ?>
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>下载准备就绪</title>
                <style>
                    body { font-family: system-ui; max-width: 600px; margin: 40px auto; padding: 20px; background: #f1f5f9; }
                    .card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
                    .btn { display: inline-block; padding: 10px 20px; margin: 8px 8px 8px 0; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; border: none; cursor: pointer; }
                    .btn-danger { background: #dc2626; }
                    .btn-success { background: #16a34a; }
                    .btn-secondary { background: #6b7280; }
                    .btn:hover { opacity: 0.85; }
                    .info { color: #475569; font-size: 14px; margin-top: 16px; }
                    .error { color: #b91c1c; background: #fee2e2; padding: 12px; border-radius: 6px; margin-top: 10px; }
                </style>
            </head>
            <body>
                <div class="card">
                    <h2>✅ 下载打包完成</h2>
                    <p>共 <?= count($files) ?> 张图片已打包成 ZIP 文件：</p>
                    <p><strong><?= htmlspecialchars($zip_name) ?></strong></p>
                    <p><a href="<?= htmlspecialchars($zip_url) ?>" class="btn" id="downloadLink" download>📥 点击下载 ZIP</a></p>
                    <div class="info">
                        ⏳ 下载完成后，请点击下方按钮删除服务器上的临时文件。
                    </div>
                    <button class="btn btn-success" id="deleteBtn">✅ 下载完成，删除文件</button>
                    <button class="btn btn-danger" id="keepBtn">❌ 保留文件（不删除）</button>
                    <a href="<?= htmlspecialchars($return_url) ?>" class="btn btn-secondary">↩️ 返回输入页面</a>
                    <div id="status" style="margin-top:12px;"></div>
                    <?php if (!empty($errors)): ?>
                        <div class="error"><strong>部分错误：</strong><br><?= nl2br(htmlspecialchars(implode("\n", array_slice($errors, 0, 5)))) ?></div>
                    <?php endif; ?>
                </div>
                <script>
                    (function() {
                        var deleteUrl = '<?= $delete_url ?>';
                        var zipName = '<?= htmlspecialchars($zip_name, ENT_QUOTES) ?>';

                        function deleteFile(callback) {
                            fetch(deleteUrl, { method: 'GET' })
                                .then(response => response.text())
                                .then(text => {
                                    if (text.trim() === 'success') {
                                        document.getElementById('status').innerHTML = '<span style="color:#16a34a;">✅ 文件已删除。</span>';
                                        if (callback) callback(true);
                                    } else {
                                        document.getElementById('status').innerHTML = '<span style="color:#b91c1c;">❌ 删除失败，请手动删除文件：' + zipName + '</span>';
                                        if (callback) callback(false);
                                    }
                                })
                                .catch(() => {
                                    document.getElementById('status').innerHTML = '<span style="color:#b91c1c;">❌ 网络错误，删除失败，请手动删除文件。</span>';
                                    if (callback) callback(false);
                                });
                        }

                        document.getElementById('deleteBtn').addEventListener('click', function() {
                            if (confirm('确认已下载完成？点击“确定”将删除服务器上的 ZIP 文件。')) {
                                this.disabled = true;
                                this.textContent = '删除中...';
                                deleteFile(function(success) {
                                    document.getElementById('deleteBtn').disabled = false;
                                    document.getElementById('deleteBtn').textContent = '✅ 下载完成，删除文件';
                                    if (success) {
                                        document.getElementById('deleteBtn').style.display = 'none';
                                        document.getElementById('keepBtn').style.display = 'none';
                                    }
                                });
                            }
                        });

                        document.getElementById('keepBtn').addEventListener('click', function() {
                            if (confirm('保留文件，您可以在服务器目录 pixiv/ 中找到它。')) {
                                document.getElementById('status').innerHTML = '<span style="color:#475569;">📁 文件已保留，路径：pixiv/' + zipName + '</span>';
                                this.disabled = true;
                                document.getElementById('deleteBtn').disabled = true;
                            }
                        });
                    })();
                </script>
            </body>
            </html>
            <?php
            exit;
        } else {
            die('创建 ZIP 文件失败，请检查 pixiv/ 目录权限。');
        }
    } else {
        $error_msg = "没有成功下载任何图片。错误：\n" . implode("\n", $errors);
        if (strpos($error_msg, 'Could not connect') !== false) {
            $error_msg .= "\n\n提示：请确认 index.php 位于同一目录，且服务器允许对外请求。";
        }
        die(nl2br(htmlspecialchars($error_msg)));
    }
}

// 显示表单
$last_url = isset($_SESSION['last_base_url']) ? $_SESSION['last_base_url'] : '';
$last_count = isset($_SESSION['last_count']) ? $_SESSION['last_count'] : 5;
?>
<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>批量下载 Pixiv 图片（通过 PHProxy）</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; background: #f1f5f9; }
        .card { background: #ffffff; padding: 24px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
        label { display: block; margin: 14px 0 6px; font-weight: 600; font-size: 14px; }
        input[type="text"], input[type="number"] { width: 100%; padding: 10px; border: 1px solid #d1d5db; border-radius: 8px; font-size: 15px; }
        button[type="submit"] { margin-top: 18px; padding: 12px 24px; background: #2563eb; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
        button[type="submit"]:hover { background: #1d4ed8; }
        .hint { color: #475569; font-size: 14px; margin-top: 16px; line-height: 1.6; }
        .hint code { background: #e2e8f0; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>🖼️ 批量下载 Pixiv 系列图片</h1>
    <div class="card">
        <form method="post">
            <label for="base_url">基础 URL（包含 _p0.扩展名）</label>
            <input type="text" id="base_url" name="base_url" placeholder="https://i.pximg.net/.../141681439_p0.png" value="<?= htmlspecialchars($last_url) ?>" required>
            <label for="count">页数（1-50）</label>
            <input type="number" id="count" name="count" value="<?= (int) $last_count ?>" min="1" max="50" required>
            <button type="submit">开始下载并打包</button>
        </form>
        <div class="hint">
            💡 例如输入 <code>https://i.pximg.net/img-original/img/2026/02/27/09/25/24/141681439_p0.png</code> 和页数 3，将下载 <code>_p0</code> 到 <code>_p2</code>。<br>
            ⚙️ 所有请求通过 PHProxy（<code>index.php?api=fetch</code>）代理。<br>
            📦 下载后打包为 ZIP，保存至 <code>pixiv/</code> 目录，并提供删除选项。<br>
            ↩️ 完成后可返回本页继续下载其他系列。<br>
            🔁 每张图片自动重试最多 3 次，确保完整性。
        </div>
    </div>
</body>
</html>