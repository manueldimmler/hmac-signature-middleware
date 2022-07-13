<?php

use Http\Middleware\HmacVerificationMiddleware;
use Http\Middleware\SignatureException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @author Manuel Dimmler
 */
class HmacVerificationMiddlewareTest extends TestCase
{

    public function testGivenInvalidAlgorithmShouldThrowException(): void
    {
        $this->expectException(SignatureException::class);
        $this->expectExceptionCode(SignatureException::INVALID_ALGO);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        new HmacVerificationMiddleware('secret', $responseFactory, 'invalid', 'x-signature');
    }

    public function testGivenInvalidKeyShouldReturn401Response(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request
                ->expects($this->once())
                ->method('getHeaderLine')
                ->willReturn('invalidSignature');

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())
                ->method('getContents')
                ->willReturn('http body');
        $request
                ->expects($this->once())
                ->method('getBody')
                ->willReturn($stream);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);
        $responseFactory->expects($this->once())
                ->method('createResponse')
                ->with(401);
        $handler = $this->createMock(RequestHandlerInterface::class);
        $middleware = new HmacVerificationMiddleware('secret', $responseFactory, 'sha1', 'x-signature');
        $middleware->process($request, $handler);
    }

    public function testGivenValidKeyShouldCallRequestHandler(): void
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request
                ->expects($this->once())
                ->method('getHeaderLine')
                ->willReturn('8d16dd3bde28f97c366fe5318f3cbe6c9a4e2b36');

        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())
                ->method('getContents')
                ->willReturn('http body');
        $request
                ->expects($this->once())
                ->method('getBody')
                ->willReturn($stream);

        $responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
                ->method('handle')
                ->with($request);
        $middleware = new HmacVerificationMiddleware('secret', $responseFactory, 'sha1', 'x-signature');
        $middleware->process($request, $handler);
    }

}
