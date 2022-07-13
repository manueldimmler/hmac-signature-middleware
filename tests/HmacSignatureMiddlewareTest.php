<?php

use Http\Middleware\HmacSignatureMiddleware;
use Http\Middleware\SignatureException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @author Manuel Dimmler
 */
class HmacSignatureMiddlewareTest extends TestCase
{

    public function testGivenInvalidAlgorithmShouldThrowException(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionCode(SignatureException::INVALID_ALGO);

        new HmacSignatureMiddleware('invalid', 'secret', 'x-signature');
    }

    public function testMissingSecretKeyShouldThrowException(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionCode(SignatureException::MISSING_SECRET_KEY);

        new HmacSignatureMiddleware('', 'sha1', 'x-signature');
    }

    public function testMissingHttpHeaderNameShouldThrowException(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionCode(SignatureException::MISSING_HTTP_HEADER_NAME);

        new HmacSignatureMiddleware('secret', 'sha1', '');
    }

    public function testShouldAddSignatureToHttpHeader(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $response
                ->expects($this->once())
                ->method('withHeader')
                ->with('x-signature', '8d16dd3bde28f97c366fe5318f3cbe6c9a4e2b36')
                ->willReturnSelf();

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())
                ->method('getContents')
                ->willReturn('http body');
        $response
                ->expects($this->once())
                ->method('getBody')
                ->willReturn($stream);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
                ->method('handle')
                ->with($request)
                ->willReturn($response);
        $middleware = new HmacSignatureMiddleware('secret', 'sha1', 'x-signature');
        $middleware->process($request, $handler);
    }

}
