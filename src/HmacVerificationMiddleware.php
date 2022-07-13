<?php

namespace Http\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use function hash_hmac;
use function hash_hmac_algos;
use function in_array;

/**
 * @author Manuel Dimmler
 */
class HmacVerificationMiddleware implements MiddlewareInterface
{

    public function __construct(
            private string $secretKey,
            private ResponseFactoryInterface $responseFactory,
            private string $algo = 'sha1',
            private string $header = 'x-signature',
    )
    {
        if (!in_array($algo, hash_hmac_algos())) {
            throw SignatureException::invalidAlgo($algo);
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $signature = hash_hmac($this->algo, $request->getBody()->getContents(), $this->secretKey);

        if ($signature !== $request->getHeaderLine($this->header)) {
            return $this->responseFactory->createResponse(401);
        }

        return $handler->handle($request);
    }

}
