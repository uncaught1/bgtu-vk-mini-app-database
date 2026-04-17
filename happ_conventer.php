<?php
ob_start();

$headers = [
    'User-Agent: Happ/3.17.0',
    'X-Device-Os: Android',
    'X-Device-Locale: ru',
    'X-Device-Model: ELP-NX1',
    'X-Ver-Os: 15',
    'Connection: close',
    'X-Hwid: 74jf74nf8f4jr5je',
    'X-Real-Ip: 101.202.303.404',
    'X-Forwarded-For: 101.202.303.404',
];

$timeout = 30;

$url = $_GET['url'] ?? '';
if (!$url) {
    die('Чтобы раскурить подписку Happ построчно в vless:// формат, введите:<br>http://ip роутера/happ_conventer.php?url=ССЫЛКА НА ПОДПИСКУ');
}

// ===== запрос =====
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url, // htmlspecialchars УБРАЛ (он ломает URL)
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 5,

    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT        => $timeout,

    CURLOPT_ENCODING       => '',

    // ❗ КРИТИЧНО для OpenWrt
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,

    // ❗ чтобы Cloudflare меньше ругался
    CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,

    // ❗ иногда помогает
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
]);

$response = curl_exec($ch);
$error    = curl_error($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

curl_close($ch);

if ($error || $httpCode !== 200 || !$response) {
    http_response_code(502);
    die("fetch error: " . ($error ?: "HTTP $httpCode"));
}

// ===== decode =====
$decoded = base64_decode($response, true);
$data = $decoded ?: $response;

// ===== json =====
$json = json_decode($data, true);
if (!$json) {
    die('bad json');
}

$result = [];

// ===== обработка =====
foreach ($json as $item) {

    if (!isset($item['outbounds'])) continue;

    $remark = $item['remarks'] ?? 'node';

    foreach ($item['outbounds'] as $out) {

        $protocol = $out['protocol'] ?? '';

        // ================= VLESS =================
        if ($protocol === 'vless') {

            $v = $out['settings']['vnext'][0] ?? null;
            if (!$v) continue;

            $user = $v['users'][0] ?? null;
            if (!$user) continue;

            $addr = $v['address'];
            $port = $v['port'];
            $id   = $user['id'];
            $flow = $user['flow'] ?? '';

            $stream = $out['streamSettings'] ?? [];

            $type = $stream['network'] ?? 'tcp';
            $security = $stream['security'] ?? 'none';

            $params = [];

            $params['type'] = $type;

            // ===== network =====
            if ($type === 'ws') {
                $params['path'] = $stream['wsSettings']['path'] ?? '';
                $params['host'] = $stream['wsSettings']['headers']['Host'] ?? '';
            }

            if ($type === 'xhttp') {
                $params['path'] = $stream['xhttpSettings']['path'] ?? '/';
                $params['mode'] = $stream['xhttpSettings']['mode'] ?? 'auto';
            }

            if ($type === 'grpc') {
                $params['serviceName'] = 'grpc';
                $params['mode'] = 'gun';
            }

            // ===== security =====
            $params['security'] = $security;

            if ($security === 'tls') {
                $tls = $stream['tlsSettings'] ?? [];
                $params['sni'] = $tls['serverName'] ?? $addr;
                $params['fp']  = $tls['fingerprint'] ?? '';
                if (!empty($tls['alpn'])) {
                    $params['alpn'] = implode(',', $tls['alpn']);
                }
            }

            if ($security === 'reality') {
                $r = $stream['realitySettings'] ?? [];
                $params['sni'] = $r['serverName'] ?? '';
                $params['fp']  = $r['fingerprint'] ?? '';
                $params['pbk'] = $r['publicKey'] ?? '';
                $params['sid'] = $r['shortId'] ?? '';
            }

            if (!empty($flow)) {
                $params['flow'] = $flow;
            }

            // ===== сборка query =====
            $query = http_build_query($params);

            $link = "vless://{$id}@{$addr}:{$port}?{$query}#" . rawurlencode($remark);
            $result[] = $link;
        }

        // ================= TROJAN =================
        if ($protocol === 'trojan') {

            $srv = $out['settings']['servers'][0] ?? null;
            if (!$srv) continue;

            $addr = $srv['address'];
            $port = $srv['port'];
            $pass = $srv['password'];

            $stream = $out['streamSettings'] ?? [];

            $type = $stream['network'] ?? 'tcp';
            $security = $stream['security'] ?? 'tls';

            $params = [
                'type' => $type,
                'security' => $security
            ];

            if ($security === 'tls') {
                $tls = $stream['tlsSettings'] ?? [];
                $params['sni'] = $tls['serverName'] ?? $addr;
                $params['fp']  = $tls['fingerprint'] ?? '';
                if (!empty($tls['alpn'])) {
                    $params['alpn'] = implode(',', $tls['alpn']);
                }
            }

            $query = http_build_query($params);

            $link = "trojan://{$pass}@{$addr}:{$port}?{$query}#" . rawurlencode($remark);
            $result[] = $link;
        }
    }
}

// ===== очистка результата =====
$result = array_filter($result, function($v) {
    return is_string($v) && strpos($v, '://') !== false;
});

// убираем дубликаты (иногда ломает клиентов)
$result = array_values(array_unique($result));

// формируем список
$output = implode("\n", $result);

// убираем лишние пробелы/переносы
$encoded = trim($output);

// ===== чистый вывод =====
if (ob_get_length()) {
    ob_clean(); // убираем BOM/мусор
}

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-cache, max-age=0');
echo $encoded;
exit;
