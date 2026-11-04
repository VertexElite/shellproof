<?php
// shellproof local test target — exercises the real PHP code paths the probes
// care about: session handling (115560), JSON body decode (109618 OOM pressure),
// and FPM-style request globals (109619 stale state).
session_start();

$raw = file_get_contents('php://input');
$decoded = null;
if ($raw !== '' && $raw !== false) {
    // json_decode is the allocator-pressure path CVE-2026-109618 probes.
    $decoded = json_decode($raw, true);
}

header('X-Powered-By: PHP/' . PHP_VERSION);
header('Content-Type: text/plain');

echo "shellproof php test target\n";
echo "php=" . PHP_VERSION . "\n";
echo "session_id=" . session_id() . "\n";
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "body_bytes=" . strlen((string) $raw) . "\n";
echo "json_ok=" . (is_array($decoded) ? '1' : '0') . "\n";
