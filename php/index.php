<?php
// Copy the secret from your webhook endpoint settings:
// https://app.bigmailer.io/console/accounts/api
$secret = '';

$sig_header = $_SERVER["HTTP_X_BIGMAILER_SIGNATURE"] ?? "";

$t = null;
$signature = null;

foreach (explode(",", $sig_header) as $element) {
    $pair = explode("=", $element);

    if (count($pair) !== 2) {
        continue;
    }

    switch ($pair[0]) {
    case "t":
        $t = intval($pair[1]);
        break;
    case "v1":
        $signature = $pair[1];
        break;
    }
}

if (!$t || !$signature) {
    // Invalid header, don't process the event.
    http_response_code(400);
    return;
}

$payload = file_get_contents("php://input");
$signed_payload = $t . "." . $payload;

$expected_signature = hash_hmac('sha256', $signed_payload, $secret);

if (!hash_equals($expected_signature, $signature) || abs($t - time()) > 300) {
    // Request is not from BigMailer, don't process the event.
    http_response_code(400);
    return;
}

// The signature is verified! Decode the event json.
$data = json_decode($payload);

// Do something with the decoded event $data.
