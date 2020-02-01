<?php

namespace Tokenizer\Config;

use ArrayObject;
use Tokenizer\Exception\ConfigurationException;

class Config extends ArrayObject
{
    public function __construct()
    {
        $this->config = new ArrayObject();
        if (!\file_exists(__DIR__ . '/settings.php')) {
            throw new ConfigurationException('Your settings.php file missing.');
        }
        $settings = require_once(__DIR__ . '/settings.php');
        if (!is_array($settings)) {
            throw new ConfigurationException('Your settings.php doesn\'t contain a settings array.');
        }
        foreach ($settings as $setting => $value) {
            $this->offsetSet($setting, $value);
        }
    }
}
