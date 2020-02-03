# Tokenizer
PHP JWT library that allows you to create trustworthy links from and to your website or webapp

## Requirements
* PHP >= 7.2.0

## Installation
```bash
composer require giftuals/tokenizer --dev
```

## Usage
```php
$config = new Tokenizer\Config\Config([
    Tokenizer\Tokenizer::HASH_HMAC_KEY => 'some-uber-secret-key',
    Tokenizer\Tokenizer::CLAIM_ISSUER => 'Giftuals',
    Tokenizer\Tokenizer::CLAIM_SUBJECT => 'Example token',
    Tokenizer\Tokenizer::CLAIM_AUDIENCE => 'https://backend.giftuals.com',
]);
$tokenizer = new Tokenizer\Tokenizer($config);
$jwt = $tokenizer->createToken([
    'my_own_claim' => 'some random value',
]);
try {
    $tokenizer->isValidToken($jwt);
    $payload = $tokenizer->getTokenPayload($jwt);
} catch (Tokenizer\Exception\InvalidTokenException $e) {
    // Something went wrong
}
```

## Authors
Coen Coppens ([giftuals](https://github.com/giftuals))

## License
Licensed under the MIT License
