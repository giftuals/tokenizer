<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

include 'vendor/autoload.php';

$config = new Tokenizer\Config\Config([
    Tokenizer\Tokenizer::HASH_HMAC_KEY => 'some-uber-secret-key',
    Tokenizer\Tokenizer::CLAIM_ISSUER => 'Giftuals',
    Tokenizer\Tokenizer::CLAIM_SUBJECT => 'Example token',
    Tokenizer\Tokenizer::CLAIM_AUDIENCE => 'https://backend.giftuals.com',
]);
try {
    $tokenizer = new Tokenizer\Tokenizer($config);
} catch (Tokenizer\Exception\ConfigurationException $e) {
    d($e->getMessage());
}
$jwt = $tokenizer->createToken([
    'my_own_claim' => 'some random value',
]);
try {
    $tokenizer->isValidToken($jwt);
    $payload = $tokenizer->getTokenPayload($jwt);
} catch (Tokenizer\Exception\InvalidTokenException $e) {
    d($e->getMessage());
}
d($payload);