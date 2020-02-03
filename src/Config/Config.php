<?php

namespace Tokenizer\Config;

use ArrayObject;
use Tokenizer\Exception\ConfigurationException;

class Config extends ArrayObject
{
    public function __construct(array $settings = [])
    {
        if (0 < count($settings)) {
            foreach ($settings as $setting => $value) {
                $this->offsetSet($setting, $value);
            }
        }
    }
}
