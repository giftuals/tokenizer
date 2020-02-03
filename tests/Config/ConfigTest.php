<?php
declare(strict_types=1);

use Tokenizer\Config\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testCanAddSettings()
    {
        $custom_settings = ['foo' => 'bar'];
        $config = new Config($custom_settings);
        $expected = 'bar';
        $result = $config->offsetGet('foo');
        $this->assertEquals($expected, $result);
    }
}
