<?php

/**
 * @package Harvest
 * @license http://opensource.org/licenses/MIT
 */

declare(strict_types=1);

namespace DecodeLabs\Harvest\Middleware;

use DecodeLabs\Archetype;
use DecodeLabs\Harvest\Middleware as HarvestMiddleware;
use DecodeLabs\Harvest\MiddlewareGroup;
use DecodeLabs\Monarch;
use DecodeLabs\Sanctum\Definition as SanctumDefinition;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrRequest;
use Psr\Http\Server\RequestHandlerInterface as PsrHandler;

class ContentSecurityPolicy implements HarvestMiddleware
{
    public MiddlewareGroup $group {
        get => MiddlewareGroup::Outbound;
    }

    public int $priority {
        get => 1;
    }


    private ?SanctumDefinition $csp = null;

    /**
     * Process middleware
     */
    public function process(
        PsrRequest $request,
        PsrHandler $next
    ): PsrResponse {
        $response = $next->handle($request);

        if ($csp = $this->loadCsp()) {
            $response = $csp->applyHeaders($response);
        }

        return $response;
    }

    /**
     * Attempt to load policy
     */
    protected function loadCsp(): ?SanctumDefinition {
        if($this->csp) {
            return $this->csp;
        }

        if(
            Monarch::$container->has(SanctumDefinition::class) &&
            ($csp = Monarch::$container->get(SanctumDefinition::class)) &&
            $csp instanceof SanctumDefinition
        ) {
            return $this->csp = $csp;
        }

        if (!$class = Archetype::tryResolve(SanctumDefinition::class)) {
            return null;
        }

        return $this->csp = new $class();
    }
}
