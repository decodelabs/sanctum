# Pandora

[![PHP from Packagist](https://img.shields.io/packagist/php-v/decodelabs/sanctum?style=flat)](https://packagist.org/packages/decodelabs/sanctum)
[![Latest Version](https://img.shields.io/packagist/v/decodelabs/sanctum.svg?style=flat)](https://packagist.org/packages/decodelabs/sanctum)
[![Total Downloads](https://img.shields.io/packagist/dt/decodelabs/sanctum.svg?style=flat)](https://packagist.org/packages/decodelabs/sanctum)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/decodelabs/sanctum/Integrate)](https://github.com/decodelabs/sanctum/actions/workflows/integrate.yml)
[![PHPStan](https://img.shields.io/badge/PHPStan-enabled-44CC11.svg?longCache=true&style=flat)](https://github.com/phpstan/phpstan)
[![License](https://img.shields.io/packagist/l/decodelabs/sanctum?style=flat)](https://packagist.org/packages/decodelabs/sanctum)

Define and deploy Content Security Policies in your PHP application.


## Installation

```bash
composer require decodelabs/sanctum
```

## Usage

Sanctum allows you to create Content Security Policies with ease.
Please see https://content-security-policy.com/ for a full list of directives.

Create your definition:

```php
use DecodeLabs\Sanctum\Definition;

class MyCsp extends Definition {

    // These items can be reused in other directives
    const SHARED_SRC = [
        '@self', // Resolves to 'self'
        '*.myotherdomain.com'
    ];

    // These items create the default-src directive
    const DEFAULT_SRC = [
        '@shared-src', // Import items from SHARED_SRC
    ];

    // These define script sources
    const SCRIPT_SRC = [
        '@nonce', // Creates a unique nonce to be used in markup
        '@unsafe-inline', // Resolves to 'unsafe-inline'

        '@strict-dynamic',
        '@https',
        '@http'
    ];

    // These define image sources
    const IMG_SRC = [
        '@shared', // Import items from SHARED_SRC
        '@data', // Resolves to data: for data URLs
        '*.myimagecdn.net',
        '!*.myotherdomain.com' // Exclude importing from SHARED_SRC
    ];


    // Report endpoint
    const REPORT_URI = 'https://mydomain.com/report';
}
```


Then in your HTTP handler:

```php
$csp = new MyCsp();

foreach($csp->exportHeaders() as $header => $value) {
    $response->setHeader($header, $value);
}

/*
Reporting-Endpoints => sanctum-csp-report="https://mydomain.com/report"
Content-Security-Policy =>
    default-src 'self' *.myotherdomain.com;
    script-src nonce-98b88fa48f23911d6fc1f5092efb2e36d76423ce4f5d7ef42765a2c2501d57c9' 'unsafe-inline' 'strict-dynamic' https: http:;
    img-src 'self' data: *.myimagecdn.net;
    report-uri https://mydomain.com/report;
    report-to sanctum-csp-report
*/
```

### Hashes

Make use of the hash feature for scripts - see https://content-security-policy.com/hash/ for explanation

```php
/*
HTML:
<script>doSomething();</script>
*/
$script = 'doSomething();'; // Your JS


// Adds sha256-xxx hash to CSP directive
$hash = $csp->hashContent($script, 'script-src');
```

## Archetype loader

Sanctum also provides an optional [Archetype](https://github.com/decodelabs/archetype) loader:

```php
namespace DecodeLabs\Sanctum\Definition;

use DecodeLabs\Sanctum\Definition;

class MyCsp extends Definition {}

$csp = Definition::load('MyCsp');
$csp->exportHeaders();
```

Archetype will look for implementations in the root namespace (<code>DecodeLabs\Sanctum\Definition</code>) by default. If you want to host your implementations in a different namespace, you should create and register a new [Archetype resolver](https://github.com/decodelabs/archetype) to find them.


## Licensing
Sanctum is licensed under the MIT License. See [LICENSE](./LICENSE) for the full license text.
