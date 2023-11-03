<?php

/**
 * @package Sanctum
 * @license http://opensource.org/licenses/MIT
 */

declare(strict_types=1);

namespace DecodeLabs\Sanctum;

use DecodeLabs\Archetype;
use DecodeLabs\Exceptional;
use DecodeLabs\Glitch\Dumpable;
use Psr\Http\Message\ResponseInterface;
use Stringable;

abstract class Definition implements
    Stringable,
    Dumpable
{
    /**
     * @var bool
     */
    public const ACTIVE = true;

    /**
     * @var bool
     */
    public const REPORT = true;

    /**
     * @var array<string>
     */
    public const SHARED_SRC = [];

    # Level 1

    /**
     * @var array<string>
     */
    public const DEFAULT_SRC = ['@shared-src'];

    /**
     * @var array<string>
     */
    public const SCRIPT_SRC = [];

    /**
     * @var array<string>
     */
    public const STYLE_SRC = [];

    /**
     * @var array<string>
     */
    public const IMG_SRC = [];

    /**
     * @var array<string>
     */
    public const CONNECT_SRC = [];

    /**
     * @var array<string>
     */
    public const FONT_SRC = [];

    /**
     * @var array<string>
     */
    public const OBJECT_SRC = [];

    /**
     * @var array<string>
     */
    public const MEDIA_SRC = [];

    /**
     * @var array<string>
     */
    public const FRAME_SRC = [];

    # Level 2

    /**
     * @var array<string>
     */
    public const CHILD_SRC = [];

    /**
     * @var array<string>
     */
    public const FORM_ACTION = [];

    /**
     * @var array<string>
     */
    public const FRAME_ANCESTORS = [];

    /**
     * @var array<string>
     */
    public const BASE_URI = [];


    # Level 3

    /**
     * @var array<string>
     */
    public const WORKER_SRC = [];

    /**
     * @var array<string>
     */
    public const MANIFEST_SRC = [];

    /**
     * @var array<string>
     */
    public const PREFETCH_SRC = [];

    /**
     * @var array<string>
     */
    public const NAVIGATE_TO = [];



    # Specials

    /**
     * @var string|null
     */
    public const REPORT_URI = null;

    /**
     * @var string|null
     */
    public const REPORT_TO = null;


    /**
     * @var array<string>|bool|null
     */
    public const SANDBOX = null;

    /**
     * @var array<string>
     */
    public const PLUGIN_TYPES = [];


    private const DIRECTIVES = [
        'shared-src',

        'default-src', 'script-src', 'style-src', 'img-src',
        'connect-src', 'font-src', 'object-src', 'media-src',
        'frame-src',

        'child-src', 'form-action', 'frame-ancestors', 'base-uri',

        'worker-src', 'manifest-src', 'prefetch-src', 'navigate-to',

        'sandbox', 'plugin-types'
    ];

    private const SOURCE_KEYS = [
        'none', 'self', 'unsafe-inline', 'unsafe-eval',
        'strict-dynamic', 'unsafe-hashes'
    ];

    protected bool $active = true;
    protected bool $report = true;

    protected ?string $nonce = null;
    protected ?string $reportUri = null;
    protected ?string $reportTo = null;

    /**
     * @var array<string, array<string>>
     */
    protected array $directives = [];

    /**
     * @var array<string, array<string>>
     */
    protected array $exclude = [];


    /**
     * Load Definition via Archetype
     */
    public static function load(
        string $name
    ): Definition {
        $class = Archetype::resolve(Definition::class, ucfirst($name));
        return new $class();
    }


    final public function __construct()
    {
        $this->compile();
        $this->setup();
    }

    /**
     *
     */
    public function setup(): void
    {
    }

    protected function compile(): void
    {
        // Active
        if (is_bool(static::ACTIVE)) {
            $this->active = static::ACTIVE;
        }

        // Report
        if (is_bool(static::REPORT)) {
            $this->report = static::REPORT;
        }


        $this->directives = $this->exclude = $macros = [];
        $class = get_class($this);

        // Process static
        foreach (self::DIRECTIVES as $directive) {
            if (
                $directive === 'sandbox' ||
                $directive === 'plugin-types'
            ) {
                continue;
            }

            $constName = str_replace('-', '_', strtoupper($directive));
            $set = constant($class . '::' . $constName);

            if (!is_array($set)) {
                continue;
            }

            foreach ($set as $value) {
                // Exlude
                if (substr($value, 0, 1) === '!') {
                    $this->exclude[$directive][] = substr($value, 1);
                    continue;
                }

                // Macro
                if (substr($value, 0, 1) === '@') {
                    $macros[$directive][$value] = false;
                }

                // Standard
                $this->directives[$directive][] = $value;
            }
        }


        // Expand / exclude
        foreach ($this->directives as $directive => $set) {
            $temp = [];

            foreach ($set as $value) {
                if (!$this->testExclude($directive, $value)) {
                    continue;
                }

                if (!isset($macros[$directive][$value])) {
                    $temp[] = $value;
                    continue;
                }

                if ($macros[$directive][$value] === true) {
                    continue;
                }

                $macros[$directive][$value] = true;

                foreach ($this->applyMacro($value) as $mValue) {
                    if ($this->testExclude($directive, $mValue)) {
                        $temp[] = $mValue;
                    }
                }
            }

            $this->directives[$directive] = array_unique($temp);

            if (empty($this->directives[$directive])) {
                unset($this->directives[$directive]);
            }
        }


        // Report URI
        if (static::REPORT_URI !== null) {
            $this->setReportUri(static::REPORT_URI);
        }


        // Report to
        if (static::REPORT_TO !== null) {
            $this->setReportEndpointName(static::REPORT_TO);
        }

        if (
            $this->reportUri !== null &&
            $this->reportTo === null
        ) {
            $this->reportTo = 'sanctum-csp-report';
        }


        // Sandbox
        $sandbox = null;

        if (static::SANDBOX === true) {
            $sandbox = [];
        } elseif (is_array(static::SANDBOX)) {
            $sandbox = static::SANDBOX;
        }

        if ($sandbox !== null) {
            $this->directives['sandbox'] = [];

            foreach ($sandbox as $key => $value) {
                if (!preg_match('/^allow-/', $value)) {
                    $value = 'allow-' . $value;
                }

                switch ($value) {
                    case 'allow-forms':
                    case 'allow-same-origin':
                    case 'allow-scripts':
                    case 'allow-popups':
                    case 'allow-modals':
                    case 'allow-orientation-lock':
                    case 'allow-pointer-lock':
                    case 'allow-presentation':
                    case 'allow-popups-to-escape-sandbox':
                    case 'allow-top-navigation':
                        break;

                    default:
                        throw Exceptional::UnexpectedValue(
                            'Sandbox allow not recognised: ' . $value
                        );
                }

                $this->directives['sandbox'][] = $value;
            }
        }


        // Plugin types
        if (!empty(static::PLUGIN_TYPES)) {
            $this->directives['plugin-types'] = static::PLUGIN_TYPES;
        }
    }

    protected function testExclude(
        string $directive,
        string $value
    ): bool {
        if (
            isset($this->exclude['*']) &&
            in_array($value, $this->exclude['*'])
        ) {
            return false;
        }

        if (!isset($this->exclude[$directive])) {
            return true;
        }

        return !in_array($value, $this->exclude[$directive]);
    }




    /**
     * @return array<string>
     */
    protected function applyMacro(
        string $macro
    ): array {
        $macro = ltrim($macro, '@');

        // Sources
        if (in_array($macro, self::DIRECTIVES)) {
            return $this->directives[$macro] ?? [];
        }

        // Nonce
        if ($macro === 'nonce') {
            return ["'nonce-{$this->getNonce()}'"];
        }

        // Source keys
        if (in_array($macro, self::SOURCE_KEYS)) {
            return ["'$macro'"];
        }

        // Schemes
        switch ($macro) {
            case 'data':
            case 'http':
            case 'https':
                return [$macro . ':'];
        }

        throw Exceptional::UnexpectedValue(
            'Macro @' . $macro . ' is not recognised'
        );
    }


    /**
     * Set active
     */
    public function setActive(
        bool $active
    ): void {
        $this->active = $active;
    }

    /**
     * Is active
     */
    public function isActive(): bool
    {
        return $this->active;
    }


    /**
     * Set reporting
     */
    public function setReportingActive(
        bool $report
    ): void {
        $this->report = $report;
    }

    /**
     * Is reporting active
     */
    public function isReportingActive(): bool
    {
        return $this->report;
    }


    /**
     * Set Report URI
     */
    public function setReportUri(
        ?string $uri
    ): void {
        // TODO: resolve URI
        $this->reportUri = $uri;
    }

    /**
     * Get Report URI
     */
    public function getReportUri(): ?string
    {
        return $this->reportUri;
    }

    /**
     * Set report endpoint name
     */
    public function setReportEndpointName(
        ?string $name
    ): void {
        $this->reportTo = $name;
    }

    /**
     * Get report endpoint name
     */
    public function getReportEndpointName(): ?string
    {
        return $this->reportTo;
    }

    /**
     * Set report endpoint
     */
    public function setReportEndpoint(
        string $name,
        ?string $uri = null
    ): void {
        $this->setReportEndpointName($name);
        $this->setReportUri($uri);
    }

    /**
     * Get report endpoint
     *
     * @return array<string, ?string>|null
     */
    public function getReportEndpoint(): ?array
    {
        if ($this->reportTo === null) {
            return null;
        }

        return [
            $this->reportTo => $this->reportUri
        ];
    }


    /**
     * Get random nonce
     */
    public function getNonce(): string
    {
        if ($this->nonce === null) {
            $this->nonce = bin2hex(random_bytes(32));
        }

        return $this->nonce;
    }

    /**
     * Add hash for content
     */
    public function addHash(
        string $hash,
        ?string $directive = null,
        ?string $algorithm = null
    ): void {
        $algorithm = $this->normalizeAlgorithm($algorithm);

        if ($directive === null) {
            $directive = 'script-src';
        }

        if (!in_array($directive, self::DIRECTIVES)) {
            throw Exceptional::InvalidArgument(
                'Directive not recognised: ' . $directive
            );
        }

        $this->directives[$directive][] = "'$algorithm-$hash'";
    }

    /**
     * Hash content
     */
    public function hashContent(
        string|Stringable $content,
        ?string $directive = null,
        ?string $algorithm = null
    ): string {
        $algorithm = $this->normalizeAlgorithm($algorithm);
        $hash = hash($algorithm, (string)$content);
        $this->addHash($hash, $directive, $algorithm);
        return $hash;
    }

    protected function normalizeAlgorithm(
        ?string $algorithm
    ): string {
        if ($algorithm === null) {
            $algorithm = 'sha256';
        }

        switch ($algorithm) {
            case 'sha256':
            case 'sha384':
            case 'sha512':
                return $algorithm;
        }

        throw Exceptional::InvalidArgument(
            'Unknown hash algorithm: ' . $algorithm
        );
    }


    /**
     * Get directive
     *
     * @return array<string>
     */
    public function getDirective(
        string $directive
    ): ?array {
        return $this->directives[$directive] ?? null;
    }

    /**
     * Get directive string
     */
    public function getDirectiveString(
        string $directive
    ): ?string {
        if (!isset($this->directives[$directive])) {
            return null;
        }

        return $directive . ' ' . implode(' ', $this->directives[$directive]);
    }



    /**
     * @return array<string>
     */
    public function getSharedSources(): array
    {
        return $this->directives['shared-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getDefaultSources(): array
    {
        return $this->directives['default-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getScriptSources(): array
    {
        return $this->directives['script-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getImageSources(): array
    {
        return $this->directives['image-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getConnectSources(): array
    {
        return $this->directives['connect-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getFontSources(): array
    {
        return $this->directives['font-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getObjectSources(): array
    {
        return $this->directives['object-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getMediaSources(): array
    {
        return $this->directives['media-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getFrameSources(): array
    {
        return $this->directives['frame-src'] ?? [];
    }




    /**
     * @return array<string>
     */
    public function getChildSources(): array
    {
        return $this->directives['child-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getFormActions(): array
    {
        return $this->directives['form-action'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getFrameAncestors(): array
    {
        return $this->directives['frame-ancestors'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getBaseUris(): array
    {
        return $this->directives['base-uri'] ?? [];
    }



    /**
     * @return array<string>
     */
    public function getWorkerSources(): array
    {
        return $this->directives['worker-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getManifestSources(): array
    {
        return $this->directives['manifest-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getPrefetchSources(): array
    {
        return $this->directives['prefetch-src'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getNavigateToUrls(): array
    {
        return $this->directives['navigate-to'] ?? [];
    }



    /**
     * @return array<string>
     */
    public function getSandboxAllowed(): ?array
    {
        return $this->directives['sandbox'] ?? [];
    }

    /**
     * @return array<string>
     */
    public function getPluginTypes(): array
    {
        return $this->directives['plugin-types'] ?? [];
    }




    /**
     * Convert to string
     */
    public function __toString(): string
    {
        return implode('; ', $this->exportDirectives());
    }


    /**
     * Export headers
     *
     * @return array<string, string>
     */
    public function exportHeaders(): array
    {
        $output = [];

        // Report endpoints
        if (
            $this->report &&
            $this->reportUri !== null &&
            $this->reportTo !== null
        ) {
            $output['reporting-endpoints'] = $this->reportTo . '="' . $this->reportUri . '"';
        }


        // CSP
        $header = $this->active ?
            'content-security-policy' :
            'content-security-policy-report-only';

        $output[$header] = implode('; ', $this->exportDirectives());

        return $output;
    }


    /**
     * Apply headers to response
     */
    public function applyHeaders(
        ResponseInterface $response
    ): ResponseInterface {
        foreach ($this->exportHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }


    /**
     * Export directives
     *
     * @return array<string, string>
     */
    public function exportDirectives(): array
    {
        $output = [];

        foreach ($this->directives as $name => $set) {
            if ($name === 'shared-src') {
                continue;
            }

            $output[$name] = $this->exportDirective($name, $set);
        }

        if ($this->report) {
            if ($this->reportUri !== null) {
                $output['report-uri'] = $this->exportDirective('report-uri', $this->reportUri);
            }

            if ($this->reportTo !== null) {
                $output['report-to'] = $this->exportDirective('report-to', $this->reportTo);
            }
        }

        return $output;
    }


    /**
     * @param string|array<string>|null $value
     */
    protected function exportDirective(
        string $name,
        string|array|null $value
    ): string {
        $directive = $name;

        if (!empty($value)) {
            $directive .= ' ';

            if (is_array($value)) {
                $directive .= implode(' ', $value);
            } else {
                $directive .= $value;
            }
        }

        return $directive;
    }



    /**
     * Export for dump inspection
     */
    public function glitchDump(): iterable
    {
        yield 'properties' => [
            '*active' => $this->active,
            '*report' => $this->report,
            'report-uri' => $this->reportUri,
            'report-to' => $this->reportTo
        ];

        $values = $this->directives;
        unset($values['shared-src']);

        yield 'values' => $values;
    }
}
