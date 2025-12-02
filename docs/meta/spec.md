# Sanctum — Package Specification

> **Cluster:** `logic`
> **Language:** `php`
> **Milestone:** `m5`
> **Repo:** `https://github.com/decodelabs/sanctum`
> **Role:** Content security policies

## Overview

### Purpose

Sanctum allows you to create and deploy Content Security Policies (CSP) with ease. It provides a declarative, class-based approach to defining CSP policies, taking the guesswork out of this important security feature.

Key features:
- **Declarative definitions**: Define policies using class constants
- **Macro system**: Reusable source lists and convenient shortcuts (`@self`, `@nonce`, `@https`, etc.)
- **Hash support**: Generate and include content hashes for inline scripts/styles
- **Report-only mode**: Test policies before enforcing them
- **PSR-7 integration**: Apply headers directly to HTTP responses
- **Archetype loader**: Optional class resolution for policy definitions

### Non-Goals

- Sanctum does not provide CSP violation reporting endpoints or handlers.
- It does not parse or validate CSP violation reports.
- It does not provide CSP testing or validation tools.
- It does not handle CSP policy merging or inheritance.
- It does not provide CSP policy versioning or migration tools.

## Role in the Ecosystem

### Cluster & Positioning

Sanctum belongs to the **logic** cluster, focusing on security and policy enforcement. It complements other logic packages like `lucid` (validation) and `scrutiny` (captcha) by providing content security policy management.

### Usage Contexts

- **Web application security**: Defining and enforcing CSP headers for web applications
- **HTTP middleware**: Integrating CSP headers into HTTP request/response cycles
- **Policy management**: Managing different CSP policies for different environments or routes
- **Security compliance**: Meeting security requirements for CSP implementation
- **Development and testing**: Using report-only mode to test policies before enforcement

## Public Surface

### Key Types

- **`Definition`** (abstract class): Base class for defining CSP policies. Provides compilation, macro expansion, directive management, and header export functionality. Implements `Stringable` and `Dumpable` interfaces.

- **`Definition\Strict`** (class): Pre-configured strict CSP policy following Google's strict CSP guidelines. Example implementation showing best practices.

- **`Harvest\Middleware\ContentSecurityPolicy`** (class): PSR-15 middleware for Harvest framework that applies CSP headers to responses.

### Main Entry Points

**Definition Creation:**
- `Definition::load(string $name): Definition` — Load definition using Archetype resolver
- `new Definition()` — Direct instantiation (abstract, must be subclassed)

**Policy Configuration (via class constants):**
- `const bool Active = true` — Enable/disable policy enforcement
- `const bool Report = true` — Enable/disable reporting
- `const array SharedSrc = []` — Shared sources reusable across directives
- `const array DefaultSrc = []` — Default source directive
- `const array ScriptSrc = []` — Script source directive
- `const array StyleSrc = []` — Style source directive
- `const array ImgSrc = []` — Image source directive
- `const array ConnectSrc = []` — Connect source directive
- `const array FontSrc = []` — Font source directive
- `const array ObjectSrc = []` — Object source directive
- `const array MediaSrc = []` — Media source directive
- `const array FrameSrc = []` — Frame source directive
- `const array ChildSrc = []` — Child source directive
- `const array FormAction = []` — Form action directive
- `const array FrameAncestors = []` — Frame ancestors directive
- `const array BaseUri = []` — Base URI directive
- `const array WorkerSrc = []` — Worker source directive
- `const array ManifestSrc = []` — Manifest source directive
- `const array PrefetchSrc = []` — Prefetch source directive
- `const array NavigateTo = []` — Navigate to directive
- `const ?string ReportUri = null` — Report URI
- `const ?string ReportTo = null` — Report endpoint name
- `const array|bool|null Sandbox = null` — Sandbox directive
- `const array PluginTypes = []` — Plugin types directive

**Policy Methods:**
- `$definition->setup(): void` — Override for runtime setup (called after compilation)
- `$definition->setActive(bool $active): void` — Enable/disable policy
- `$definition->isActive(): bool` — Check if policy is active
- `$definition->setReportingActive(bool $report): void` — Enable/disable reporting
- `$definition->isReportingActive(): bool` — Check if reporting is active
- `$definition->setReportUri(?string $uri): void` — Set report URI
- `$definition->getReportUri(): ?string` — Get report URI
- `$definition->setReportEndpointName(?string $name): void` — Set report endpoint name
- `$definition->getReportEndpointName(): ?string` — Get report endpoint name
- `$definition->setReportEndpoint(string $name, ?string $uri = null): void` — Set both endpoint name and URI
- `$definition->getReportEndpoint(): ?array` — Get endpoint as array
- `$definition->getNonce(): string` — Get or generate nonce value
- `$definition->addHash(string $hash, ?string $directive = null, ?string $algorithm = null): void` — Add content hash to directive
- `$definition->hashContent(string|Stringable $content, ?string $directive = null, ?string $algorithm = null): string` — Hash content and add to directive
- `$definition->getDirective(string $directive): ?array` — Get directive sources
- `$definition->getDirectiveString(string $directive): ?string` — Get directive as string

**Directive Getters:**
- `$definition->getSharedSources(): array`
- `$definition->getDefaultSources(): array`
- `$definition->getScriptSources(): array`
- `$definition->getImageSources(): array`
- `$definition->getConnectSources(): array`
- `$definition->getFontSources(): array`
- `$definition->getObjectSources(): array`
- `$definition->getMediaSources(): array`
- `$definition->getFrameSources(): array`
- `$definition->getChildSources(): array`
- `$definition->getFormActions(): array`
- `$definition->getFrameAncestors(): array`
- `$definition->getBaseUris(): array`
- `$definition->getWorkerSources(): array`
- `$definition->getManifestSources(): array`
- `$definition->getPrefetchSources(): array`
- `$definition->getNavigateToUrls(): array`
- `$definition->getSandboxAllowed(): ?array`
- `$definition->getPluginTypes(): array`

**Header Export:**
- `$definition->exportHeaders(): array<string, string>` — Export headers as array
- `$definition->exportDirectives(): array<string, string>` — Export directives as array
- `$definition->applyHeaders(ResponseInterface $response): ResponseInterface` — Apply headers to PSR-7 response
- `(string)$definition` — String conversion returns CSP header value

**Macros:**
- `@shared-src` — Import from `SharedSrc` constant
- `@nonce` — Generate nonce value
- `@self` — Resolves to `'self'`
- `@none` — Resolves to `'none'`
- `@unsafe-inline` — Resolves to `'unsafe-inline'`
- `@unsafe-eval` — Resolves to `'unsafe-eval'`
- `@strict-dynamic` — Resolves to `'strict-dynamic'`
- `@unsafe-hashes` — Resolves to `'unsafe-hashes'`
- `@data` — Resolves to `data:`
- `@http` — Resolves to `http:`
- `@https` — Resolves to `https:`
- `@directive-name` — Import from another directive (e.g., `@script-src`)

**Exclusions:**
- Prefix with `!` to exclude a value from a directive (e.g., `'!*.example.com'`)

## Dependencies

### Decode Labs

- **`decodelabs/archetype`**: Used for class resolution in `Definition::load()`.
- **`decodelabs/exceptional`**: Used for exception handling throughout the package.
- **`decodelabs/monarch`**: Used for service location (Archetype) in `Definition::load()`.
- **`decodelabs/nuance`**: Used for `Dumpable` interface support, enabling debugging and inspection capabilities.

### External

- **PHP**: See `composer.json` for supported PHP versions.
- **`psr/http-message`**: PSR-7 interfaces for HTTP message handling.

## Behaviour & Contracts

### Invariants

- A `Definition` instance is compiled during construction (constants are processed into directives).
- Nonce values are generated once per instance and reused.
- Directives are normalized and deduplicated during compilation.
- Macro expansion happens during compilation, not at runtime.
- Exclusions are processed after macro expansion.

### Input & Output Contracts

**Definition Constants:**
- Array constants accept strings or macro references (prefixed with `@`).
- Exclusions are prefixed with `!`.
- `Sandbox` can be `true` (allows all), `false`/`null` (disabled), or array of allowed values.
- `ReportUri` and `ReportTo` are optional strings.

**Macro Expansion:**
- Macros are expanded recursively (macros can reference other macros).
- Circular references are detected and handled.
- Unknown macros throw `UnexpectedValue` exceptions.

**Hash Generation:**
- Default algorithm is `sha256`.
- Supported algorithms: `sha256`, `sha384`, `sha512`.
- Invalid algorithms throw `InvalidArgument` exceptions.
- Default directive for hashes is `script-src`.

**Header Export:**
- Active policies export `content-security-policy` header.
- Inactive policies export `content-security-policy-report-only` header.
- Report endpoints are included in `reporting-endpoints` header when reporting is enabled.
- Headers follow CSP specification format.

**Directive Formatting:**
- Directives are space-separated lists of sources.
- Source values are quoted when necessary (e.g., `'self'`, `'nonce-xxx'`).
- Empty directives are omitted from output.

## Error Handling

- **Unknown macro**: `applyMacro()` throws `UnexpectedValue` exceptions for unrecognized macros.
- **Invalid directive**: `addHash()` throws `InvalidArgument` exceptions for unrecognized directive names.
- **Invalid algorithm**: `normalizeAlgorithm()` throws `InvalidArgument` exceptions for unsupported hash algorithms.
- **Invalid sandbox value**: Sandbox compilation throws `UnexpectedValue` exceptions for unrecognized sandbox allow values.

## Configuration & Extensibility

### Creating Custom Definitions

Extend the `Definition` class and define constants:

```php
class MyCsp extends Definition
{
    public const array SharedSrc = [
        '@self',
        '*.example.com'
    ];

    public const array DefaultSrc = [
        '@shared-src'
    ];

    public const array ScriptSrc = [
        '@nonce',
        '@strict-dynamic'
    ];

    public const ?string ReportUri = 'https://example.com/report';
}
```

### Runtime Configuration

Override `setup()` method for runtime configuration:

```php
class MyCsp extends Definition
{
    public function setup(): void
    {
        // Add dynamic sources
        $this->directives['script-src'][] = 'https://cdn.example.com';
    }
}
```

### Custom Macros

Macros are resolved in `applyMacro()`. To add custom macros, override this method (though the built-in macros cover most use cases).

### Harvest Middleware

Use the provided middleware for automatic header application:

```php
use DecodeLabs\Sanctum\Definition;
use DecodeLabs\Harvest\Middleware\ContentSecurityPolicy;

$csp = new MyCsp();
$middleware = new ContentSecurityPolicy($csp);
```

## Interactions with Other Packages

- **Archetype**: Used for class resolution in `Definition::load()`. Definitions can be loaded by name if registered with Archetype.
- **Monarch**: Used for service location (Archetype) in `Definition::load()`.
- **Exceptional**: Used for all exception handling.
- **Nuance**: Used for `Dumpable` interface support, enabling debugging and inspection.
- **Harvest**: Provides PSR-15 middleware for automatic header application.

## Usage Examples

### Basic Definition

```php
use DecodeLabs\Sanctum\Definition;

class MyCsp extends Definition
{
    public const array SharedSrc = [
        '@self',
        '*.myotherdomain.com'
    ];

    public const array DefaultSrc = [
        '@shared-src'
    ];

    public const array ScriptSrc = [
        '@nonce',
        '@unsafe-inline',
        '@strict-dynamic',
        '@https',
        '@http'
    ];

    public const array ImgSrc = [
        '@shared-src',
        '@data',
        '*.myimagecdn.net',
        '!*.myotherdomain.com' // Exclude from shared
    ];

    public const ?string ReportUri = 'https://mydomain.com/report';
}

$csp = new MyCsp();
foreach ($csp->exportHeaders() as $header => $value) {
    $response->setHeader($header, $value);
}
```

### Using Nonces

```php
$csp = new MyCsp();
$nonce = $csp->getNonce();

// Use in HTML
echo '<script nonce="' . $nonce . '">...</script>';
```

### Content Hashing

```php
$csp = new MyCsp();
$script = 'doSomething();';

// Hash content and add to CSP
$hash = $csp->hashContent($script, 'script-src');
// Hash is automatically added to script-src directive
```

### Report-Only Mode

```php
class MyCsp extends Definition
{
    public const bool Active = false; // Report-only mode
    public const bool Report = true;
    // ...
}
```

### Using Archetype Loader

```php
use DecodeLabs\Sanctum\Definition;

// Definition must be in DecodeLabs\Sanctum\Definition namespace
namespace DecodeLabs\Sanctum\Definition;

class MyCsp extends Definition {}

// Load by name
$csp = Definition::load('MyCsp');
$headers = $csp->exportHeaders();
```

### Harvest Middleware

```php
use DecodeLabs\Sanctum\Definition;
use DecodeLabs\Harvest\Middleware\ContentSecurityPolicy;

$csp = new MyCsp();
$middleware = new ContentSecurityPolicy($csp);

// Add to Harvest middleware stack
```

### Strict Policy

```php
use DecodeLabs\Sanctum\Definition\Strict;

$csp = new Strict();
// Uses Google's strict CSP guidelines
```

### Runtime Modification

```php
$csp = new MyCsp();

// Disable for specific requests
$csp->setActive(false);

// Add dynamic hash
$csp->hashContent($dynamicScript, 'script-src');

// Change report endpoint
$csp->setReportEndpoint('custom-endpoint', 'https://example.com/report');
```

## Implementation Notes (for Contributors)

### Compilation Process

1. Constants are read from the class.
2. Values are processed for macros and exclusions.
3. Macros are expanded recursively.
4. Exclusions are applied after macro expansion.
5. Directives are deduplicated and normalized.
6. Special directives (sandbox, plugin-types) are processed separately.

### Macro System

- Macros are prefixed with `@`.
- Macro expansion happens during compilation.
- Circular references are prevented by tracking expansion state.
- Source keys (`self`, `none`, etc.) are automatically quoted.
- Scheme macros (`data:`, `http:`, `https:`) include the colon.

### Nonce Generation

- Nonces are generated using `random_bytes(32)` and hex-encoded (64 characters).
- Nonce is generated once per instance and reused.
- Nonce format: `'nonce-{hex}'` in CSP directive.

### Hash Algorithms

- Default algorithm is `sha256`.
- Supported algorithms match CSP specification.
- Hash format: `'{algorithm}-{hash}'` in CSP directive.
- Hashes are added to directives at runtime (not during compilation).

### Header Formatting

- Headers follow CSP specification format.
- Directives are semicolon-separated.
- Sources within directives are space-separated.
- Empty directives are omitted.
- Report endpoints use `reporting-endpoints` header format.

### Sandbox Directive

- `true` enables sandbox with no restrictions.
- Array of strings enables specific sandbox allows.
- Values are normalized (prefixed with `allow-` if needed).
- Invalid values throw exceptions.

## Testing & Quality

**Current Status:**
- Code quality: 4/5
- README quality: 3/5
- Documentation: 0/5 (no formal docs yet)
- Tests: 0/5 (no test suite yet)

**Testing Considerations:**
- Definition compilation should be tested for:
  - Macro expansion (including recursive macros)
  - Exclusion handling
  - Directive normalization
  - Sandbox processing
  - Report endpoint configuration

- Header export should be tested for:
  - Active vs report-only mode
  - Header format compliance
  - Directive ordering
  - Empty directive handling

- Hash generation should be tested for:
  - Algorithm support
  - Hash format
  - Default directive assignment
  - Invalid algorithm handling

- Macro system should be tested for:
  - All built-in macros
  - Circular reference detection
  - Unknown macro handling
  - Directive imports

- Edge cases should be tested for:
  - Empty definitions
  - All directives defined
  - Complex macro chains
  - Exclusion edge cases

## Roadmap & Future Ideas

- **CSP violation reporting**: Built-in handlers for processing violation reports
- **Policy testing**: Tools for testing policies against real content
- **Policy validation**: Validation of policy definitions before deployment
- **Policy merging**: Utilities for merging multiple policies
- **Policy versioning**: Support for policy versioning and migration
- **Performance optimization**: Caching of compiled policies
- **IDE support**: Better IDE integration and autocomplete for directives
- **Documentation generation**: Automatic documentation generation from definitions

## References

- Package repository: https://github.com/decodelabs/sanctum
- Composer package: https://packagist.org/packages/decodelabs/sanctum
- CSP specification: https://www.w3.org/TR/CSP3/
- CSP reference: https://content-security-policy.com/
- Google Strict CSP: https://csp.withgoogle.com/docs/strict-csp.html
- Related packages:
  - `decodelabs/archetype` — Class resolution
  - `decodelabs/exceptional` — Exception handling
  - `decodelabs/monarch` — Service location
  - `decodelabs/nuance` — Debugging and inspection
  - `decodelabs/harvest` — HTTP stack (for middleware)

