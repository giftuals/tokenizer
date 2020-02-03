<?php
declare(strict_types=1);

use Tokenizer\Tokenizer;
use Tokenizer\Config\Config;
use PHPUnit\Framework\TestCase;
use Tokenizer\Exception\ConfigurationException;

final class TokenizerTest extends TestCase
{
    /**
     *
     * @dataProvider requiredSettingsProvider
     */
    public function testInvalidatesMissingConfigSettings($config_settings)
    {
        $config = new Config($config_settings);
        $this->expectException(ConfigurationException::class);
        $tokenizer = new Tokenizer($config);
    }

    public function requiredSettingsProvider() : array
    {
        return [
            'Hash HMAC key' => [
                [],
                ConfigurationException::class,
            ],
            'Issuer claim' => [
                [Tokenizer::CLAIM_ISSUER => 'foo'],
                ConfigurationException::class,
            ],
            'Subject claim' => [
                [Tokenizer::CLAIM_SUBJECT => 'foo'],
                ConfigurationException::class,
            ],
            'Audience claim' => [
                [Tokenizer::CLAIM_AUDIENCE => 'foo'],
                ConfigurationException::class,
            ],
            'Combination' => [
                [
                    Tokenizer::CLAIM_ISSUER => 'foo',
                    Tokenizer::CLAIM_AUDIENCE => 'foo',
                ],
                ConfigurationException::class,
            ],
        ];
    }

    public function testValidatesMinimumConfigSettings()
    {
        $config = new Config([
            Tokenizer::HASH_HMAC_KEY => 'foo',
            Tokenizer::CLAIM_ISSUER => 'foo',
            Tokenizer::CLAIM_SUBJECT => 'foo',
            Tokenizer::CLAIM_AUDIENCE => 'foo',
        ]);
        $tokenizer = new Tokenizer($config);
        $this->assertInstanceOf(Tokenizer::class, $tokenizer);
    }

    public function testCanCreateToken()
    {
        $config = new Config([
            Tokenizer::HASH_HMAC_KEY => 'foo',
            Tokenizer::CLAIM_ISSUER => 'foo',
            Tokenizer::CLAIM_SUBJECT => 'foo',
            Tokenizer::CLAIM_AUDIENCE => 'foo',
        ]);
        $tokenizer = new Tokenizer($config);
        $result = $tokenizer->createToken([
            'foo' => 'bar',
        ]);
        $this->assertIsString($result);
    }

    /**
     *
     * @dataProvider exampleTokensProvider
     */
    public function testCanValidateToken($settings, $token, $must_match)
    {
        
        $config = new Config($settings);
        $tokenizer = new Tokenizer($config);
        $result = $tokenizer->createToken();
        if (true === $must_match) {
            $this->assertEquals($token, $result);
        } else {
            $this->assertNotEquals($token, $result);
        }
    }

    public function exampleTokensProvider()
    {
        return [
            'Fixed issued at' => [
                [
                    Tokenizer::HASH_HMAC_KEY => 'foo',
                    Tokenizer::CLAIM_ISSUER => 'foo',
                    Tokenizer::CLAIM_SUBJECT => 'foo',
                    Tokenizer::CLAIM_AUDIENCE => 'foo',
                    Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
                    Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
                ],
                'eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJpYXQiOiIwMy0wMi0yMDIwIDIxOjM1OjMwIiwiem9uZWluZm8iOiJFdXJvcGVcL0Ftc3RlcmRhbSJ9.MDY1M2RlZDkwYmU1NDVhZGY4ZDVhMWMxOWU3MzNjZjE1YzYwMjExZmViYjcwMTIyMjY1YmE1YWI4ZTI0NDNlNg',
                true
            ],
            'Dynamic issued at' => [
                [
                    Tokenizer::HASH_HMAC_KEY => 'foo',
                    Tokenizer::CLAIM_ISSUER => 'foo',
                    Tokenizer::CLAIM_SUBJECT => 'foo',
                    Tokenizer::CLAIM_AUDIENCE => 'foo',
                ],
                'eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJpYXQiOiIwMy0wMi0yMDIwIDIxOjM1OjMwIiwiem9uZWluZm8iOiJFdXJvcGVcL0Ftc3RlcmRhbSJ9.MDY1M2RlZDkwYmU1NDVhZGY4ZDVhMWMxOWU3MzNjZjE1YzYwMjExZmViYjcwMTIyMjY1YmE1YWI4ZTI0NDNlNg',
                false
            ],
            'Changed key' => [
                [
                    Tokenizer::HASH_HMAC_KEY => 'bar',
                    Tokenizer::CLAIM_ISSUER => 'foo',
                    Tokenizer::CLAIM_SUBJECT => 'foo',
                    Tokenizer::CLAIM_AUDIENCE => 'foo',
                    Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
                    Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
                ],
                'eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJpYXQiOiIwMy0wMi0yMDIwIDIxOjM1OjMwIiwiem9uZWluZm8iOiJFdXJvcGVcL0Ftc3RlcmRhbSJ9.MDY1M2RlZDkwYmU1NDVhZGY4ZDVhMWMxOWU3MzNjZjE1YzYwMjExZmViYjcwMTIyMjY1YmE1YWI4ZTI0NDNlNg',
                false
            ],
        ];
    }

    public function testCanReadPayloadWithoutRequiredClaims()
    {
        $config = new Config([
            Tokenizer::HASH_HMAC_KEY => 'foo',
            Tokenizer::CLAIM_ISSUER => 'foo',
            Tokenizer::CLAIM_SUBJECT => 'foo',
            Tokenizer::CLAIM_AUDIENCE => 'foo',
            Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
            Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
        ]);
        $tokenizer = new Tokenizer($config);
        $token = $tokenizer->createToken([
            'foo' => 'bar',
            'baz' => 'qux',
        ]);
        $result = $tokenizer->getTokenPayload($token);
        $expected = ['foo' => 'bar', 'baz' => 'qux'];
        $this->assertEquals($expected, $result);
    }

    public function testCanReadPayloadWithRequiredClaims()
    {
        $config = new Config([
            Tokenizer::HASH_HMAC_KEY => 'foo',
            Tokenizer::CLAIM_ISSUER => 'foo',
            Tokenizer::CLAIM_SUBJECT => 'foo',
            Tokenizer::CLAIM_AUDIENCE => 'foo',
            Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
            Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
        ]);
        $tokenizer = new Tokenizer($config);
        $token = $tokenizer->createToken([
            Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
            Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
            'foo' => 'bar',
            'baz' => 'qux',
        ]);
        $result = $tokenizer->getTokenPayload($token, true);
        ksort($result);
        $expected = [
            'foo' => 'bar',
            'baz' => 'qux',
            Tokenizer::CLAIM_ISSUED_AT => '03-02-2020 21:35:30',
            Tokenizer::CLAIM_TIMEZONE => 'Europe/Amsterdam',
        ];
        ksort($expected);
        $this->assertEquals($expected, $result);
    }
}
