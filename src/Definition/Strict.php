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
    public const array ScriptSrc = [
        '@nonce',
        '@unsafe-inline',

        '@strict-dynamic',
        '@https',
        '@http'
    ];

    public const array ObjectSrc = [
        '@none'
    ];

    public const array BaseUri = [
        '@self'
    ];
}
