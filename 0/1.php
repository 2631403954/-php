<?php
// 1.php - Pixiv 图片链接转换器（通过 PHProxy，不强制 flags）
?><!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pixiv 图片代理转换 (通过 PHProxy)</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
            max-width: 720px;
            margin: 60px auto;
            padding: 20px;
            background: #f7f9fc;
            color: #1e293b;
        }
        .card {
            background: white;
            border-radius: 16px;
            padding: 30px 28px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.06);
            border: 1px solid #e9edf4;
        }
        h1 {
            font-size: 22px;
            font-weight: 600;
            margin-top: 0;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .sub {
            color: #64748b;
            font-size: 14px;
            margin-bottom: 22px;
        }
        .example {
            background: #f1f5f9;
            padding: 10px 14px;
            border-radius: 8px;
            font-family: 'SF Mono', 'Fira Code', monospace;
            font-size: 13px;
            word-break: break-all;
            color: #0f172a;
            margin: 12px 0 20px;
        }
        .example .arrow { color: #94a3b8; margin: 0 8px; }
        .example .to { color: #2563eb; }
        .form-group {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        input[type="text"] {
            flex: 1;
            padding: 12px 16px;
            border: 1px solid #d1d9e6;
            border-radius: 10px;
            font-size: 15px;
            background: white;
            transition: 0.15s;
            min-width: 200px;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
        }
        button {
            padding: 12px 28px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.15s;
            white-space: nowrap;
        }
        button:hover {
            background: #1d4ed8;
        }
        .footnote {
            margin-top: 20px;
            font-size: 13px;
            color: #94a3b8;
        }
        .footnote code {
            background: #eef2f6;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
        }
        .footnote a {
            color: #2563eb;
            text-decoration: none;
        }
        .footnote a:hover { text-decoration: underline; }
    </style>
</head>
<body>
<div class="card">
    <h1>🖼️ Pixiv 图片代理转换</h1>
    <div class="sub">将 <code>i.pximg.net</code> 链接通过 <a href="index.php" target="_blank">PHProxy</a> 代理打开 <code>i.pixiv.cat</code></div>

    <div class="example">
        📎 示例：<br>
        <span>https://i.pximg.net/img-original/img/2026/02/27/09/25/24/141681439_p0.png</span>
        <span class="arrow">→</span>
        <span class="to">https://i.pixiv.cat/img-original/img/2026/02/27/09/25/24/141681439_p0.png</span>
        <br>
        <span style="font-size:12px; color:#64748b;">（通过 PHProxy 代理，使用您当前的 PHProxy 设置）</span>
    </div>

    <form id="convertForm" onsubmit="return false;">
        <div class="form-group">
            <input type="text" id="urlInput" placeholder="粘贴 i.pximg.net 的图片链接 …" spellcheck="false" autofocus>
            <button type="button" id="openBtn">在新窗口打开</button>
        </div>
    </form>

    <div class="footnote">
        💡 只替换域名，路径不变。若输入无效链接会提示。<br>
        ⚙️ 使用您浏览器中现有的 PHProxy 设置（Cookie），无需额外参数。
    </div>
</div>

<script>
    (function() {
        const input = document.getElementById('urlInput');
        const btn = document.getElementById('openBtn');

        function convertAndOpen() {
            let raw = input.value.trim();
            if (!raw) {
                alert('请输入一个链接');
                return;
            }

            // 自动补全协议
            if (!raw.match(/^https?:\/\//i)) {
                raw = 'https://' + raw;
            }

            // 必须包含 i.pximg.net
            if (!raw.includes('i.pximg.net')) {
                alert('链接中未包含 "i.pximg.net"，请检查');
                return;
            }

            // 替换域名
            const converted = raw.replace(/^https?:\/\/i\.pximg\.net\//i, 'https://i.pixiv.cat/');

            // 构造 PHProxy 的 URL（不传递 _proxfl，依赖 Cookie）
            const proxyUrl = 'index.php?_proxurl=' + encodeURIComponent(converted);

            // 新窗口打开
            window.open(proxyUrl, '_blank');
        }

        btn.addEventListener('click', convertAndOpen);

        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                convertAndOpen();
            }
        });

        input.focus();
    })();
</script>
</body>
</html>