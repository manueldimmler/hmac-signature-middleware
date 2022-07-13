<?php

declare(strict_types=1);

namespace Http\Middleware;

use RuntimeException;
use function hash_hmac_algos;
use function implode;
use function sprintf;

/**
 * @author Manuel Dimmler
 */
class SignatureException extends RuntimeException
{

    const INVALID_ALGO = 1;
    const MISSING_SECRET_KEY = 2;
    const MISSING_HTTP_HEADER_NAME = 3;

    public static function invalidAlgo(string $algo): self
    {
        return new self(sprintf('invalid hashing algorithm: %s given, one of %s allowed', $algo, implode(', ', hash_hmac_algos())), self::INVALID_ALGO);
    }

    public static function missingKey(): self
    {
        return new self('no secret key given', self::MISSING_SECRET_KEY);
    }

    public static function missingHttpHeaderName(): self
    {
        return new self('no http header name given', self::MISSING_HTTP_HEADER_NAME);
    }

}
