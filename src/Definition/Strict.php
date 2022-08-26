<?php

/**
 * @package Sanctum
 * @license http://opensource.org/licenses/MIT
 */

declare(strict_types=1);

namespace DecodeLabs\Sanctum\Definition;

use DecodeLabs\Sanctum\Definition;

/**
 * Strict policy as defined at https://csp.withgoogle.com/docs/strict-csp.html
 */
class Strict extends Definition
{
    public const SCRIPT_SRC = [
        '@nonce',
        '@unsafe-inline',

        '@strict-dynamic',
        '@https',
        '@http'
    ];

    public const OBJECT_SRC = [
        '@none'
    ];

    public const BASE_URI = [
        '@self'
    ];
}
