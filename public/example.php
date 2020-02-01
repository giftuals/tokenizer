<?php
error_reporting(E_ALL);
ini_set('display_errors', '1');

include 'vendor/autoload.php';

try {
    $config = new Tokenizer\Config\Config();
    $tokenizer = new Tokenizer\Tokenizer($config);
    $jwt = $tokenizer->createToken([
        'my_own_claim' => 'some random value',
    ]);
    $tokenizer->isValidToken($jwt);
    $payload = $tokenizer->getTokenPayload($jwt);
} catch (Tokenizer\Exception\ConfigurationException | \Tokenizer\Exception\InvalidTokenException $e) {
    d($e->getMessage());
}
