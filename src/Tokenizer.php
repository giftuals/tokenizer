<?php

namespace Tokenizer;

use DateTime;
use Tokenizer\Config\Config;
use InvalidArgumentException;
use Tokenizer\Exception\InvalidTokenException;
use Tokenizer\Exception\ConfigurationException;

/**
 * Tokenizer
 * 
 * PHP version 7.2
 * 
 * @category  PHP
 * @package   Tokenizer
 * @author    Coen Coppens <coen.coppens@giftuals.com>
 * @copyright 2020 Giftuals
 * @license   https://giftuals.com No License
 * @version   1.0
 * @link      https://giftuals.com
 * @since     31-01-2020
 */
class Tokenizer
{
    const CLAIM_ALGORITHM = 'alg';
    const CLAIM_TYPE = 'typ';
    const CLAIM_ISSUER = 'iss';
    const CLAIM_SUBJECT = 'sub';
    const CLAIM_AUDIENCE = 'aud';
    const CLAIM_ISSUED_AT = 'iat';
    const CLAIM_TIMEZONE = 'zoneinfo';
    const CLAIM_WEBSITE = 'website';
    const CLAIM_SUB_ID = 'sub_id';

    const HASH_HMAC_KEY = 'hash_hmac_key';

    /**
     *
     * @var Config
     */
    private $config;

    /**
     *
     * @throws ConfigurationException
     */
    public function __construct(Config $config)
    {
        if ($this->isValidConfig($config)) {
            $this->config = $config;
        }
    }

    /**
     *
     * @throws ConfigurationException
     */
    private function isValidConfig(Config $config) : bool
    {
        if (false === $config->offsetExists(self::HASH_HMAC_KEY)) {
            throw new ConfigurationException('Setting "' . self::HASH_HMAC_KEY . '" is not specified');
        }

        $configurable_claims = [
            self::CLAIM_ISSUER,
            self::CLAIM_SUBJECT,
            self::CLAIM_AUDIENCE,
        ];
        foreach ($configurable_claims as $claim) {
            if (false === $config->offsetExists($claim)) {
                throw new ConfigurationException('Setting "' . $claim . '" is not specified');
            }
            $required_payload[$claim] = $config->offsetGet($claim);
        }
        return true;
    }

    public function createToken(array $payload = []) : string
    {
        $header = array(
            self::CLAIM_ALGORITHM => 'HS256',
            self::CLAIM_TYPE => 'jwt',
        );
        $jwt_header = $this->base64EncodeUrl(json_encode($header));
        $required_payload = $this->getRequiredPayload($this->config);
        $full_payload = array_merge($required_payload, $payload);
        $jwt_payload = $this->base64EncodeUrl(json_encode($full_payload));
        $jwt_signature = $this->createSignature($jwt_header, $jwt_payload, $this->config);
        return sprintf('%s.%s.%s', $jwt_header, $jwt_payload, $jwt_signature);
    }

    public function getTokenPayload($jwt, $include_required_payload = false) : array
    {
        if ($this->isValidToken($jwt)) {
            $shrapnel = explode('.', $jwt);
            $payload = json_decode($this->base64DecodeUrl($shrapnel[1]), true);
            if ($include_required_payload) {
                return $payload;
            }
            $required_payload_claims = $this->getRequiredPayloadClaims();
            return array_diff_key($payload, array_flip($required_payload_claims));
        }
    }

    /**
     *
     * @throws InvalidTokenException
     */
    public function isValidToken($jwt) : bool
    {
        $shrapnel = explode('.', $jwt);
        if (3 !== count($shrapnel)) {
            throw new InvalidTokenException('Invalid token provided');
        }

        $header = $shrapnel[0];
        $payload = $shrapnel[1];
        $actual = $shrapnel[2];
        $expected = $this->createSignature($header, $payload, $this->config);
        if ($actual !== $expected) {
            throw new InvalidTokenException('Invalid signature provided');
        }
        return true;
    }

    private function getRequiredPayloadClaims() : array
    {
        return [
            self::CLAIM_ISSUER,
            self::CLAIM_SUBJECT,
            self::CLAIM_AUDIENCE,
            self::CLAIM_ISSUED_AT,
            self::CLAIM_TIMEZONE,
        ];
    }

    private function getRequiredPayload(Config $config) : array
    {
        if ($config->offsetExists(self::CLAIM_ISSUED_AT)) {
            $issued_at = $config->offsetGet(self::CLAIM_ISSUED_AT);
        } else {
            $issued_at = date('d-m-Y H:i:s');
        }
        if ($config->offsetExists(self::CLAIM_TIMEZONE)) {
            $timezone_name = $config->offsetGet(self::CLAIM_TIMEZONE);
        } else {
            $date = new DateTime();
            $timezone = $date->getTimezone();
            $timezone_name = $timezone->getName();
        }
        $required_payload = [
            self::CLAIM_ISSUED_AT => $issued_at,
            self::CLAIM_TIMEZONE => $timezone_name,
        ];
        return $required_payload;
    }

    private function createSignature($header, $payload, Config $config) : string
    {
        $signature = hash_hmac(
            'sha256',
            $header . $payload,
            $config->offsetGet(self::HASH_HMAC_KEY)
        );
        $jwt_signature = $this->base64EncodeUrl($signature);
        return $jwt_signature;
    }

    /**
     * 
     * @link https://www.php.net/manual/en/function.base64-encode.php
     */
    private function base64EncodeUrl($string)
    {
        return str_replace(array('+','/','='), array('-','_',''), base64_encode($string));
    }
    
    /**
     * 
     * @link https://www.php.net/manual/en/function.base64-decode.php
     */
    private function base64DecodeUrl($string)
    {
        return base64_decode(str_replace(array('-','_'), array('+','/'), $string));
    }
}
