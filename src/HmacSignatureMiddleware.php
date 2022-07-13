<?php

namespace Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use function hash_hmac;
use function hash_hmac_algos;
use function strlen;

/**
 * Authenticates the response being sent. You have to specify the HMAC 
 * algorithm, a secret key and a http header name. With the algorithm, the 
 * sectret key and the body of the response, a signature will be calculated and 
 * stored in the given http header.
 * 
 * @author Manuel Dimmler
 */
class HmacSignatureMiddleware implements MiddlewareInterface
{

    /**
     * @param string $secretKey your secret key
     * @param string $algo hashing algorithm
     * @param string $header http header key
     * @throws SignatureException
     */
    public function __construct(
            private string $secretKey,
            private string $algo = 'sha1',
            private string $header = 'x-signature'
    )
    {
        if (0 === strlen($secretKey)) {
            throw SignatureException::missingKey();
        }
        if (!in_array($algo, hash_hmac_algos())) {
            throw SignatureException::invalidAlgo($algo);
        }
        if (0 === strlen($header)) {
            throw SignatureException::missingHttpHeaderName();
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $handler->handle($request);
        $signature = hash_hmac($this->algo, $response->getBody()->getContents(), $this->secretKey);

        return $response->withHeader($this->header, $signature);
    }

}
