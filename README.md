# HMAC Signature Middleware

This package provides two [PSR-15 middlewares](https://www.php-fig.org/psr/psr-15/).

The first middleware creates a signature of the payload. A secret key has to be 
provided as first argument.
By default, SHA1 hashing algorithm is used and the HMAC signature will be added 
as x-signature header.

```php
$signatureMiddleware = new Http\Middleware\HmacSignatureMiddleware('secret key'):
```

To validate the signature, use the verification middleware.

```php
/** @var ResponseFactoryInterface $responseFactory */
$signatureMiddleware = new Http\Middleware\HmacVerificationMiddleware('secret key', $responseFactory):
```


## What's a HMAC

A HMAC is a hash-based message authentication code using a symmetric key.

If a user sees a message and a HMAC and knows the associated secret key, he can 
verify that the HMAC was produced by a principal that knows the key by doing the 
HMAC computation hisself. Therefore, if a message comes with a correct HMAC 
attached, it means this message was seen by a holder of the secret key at some 
point.

## Installation

```bash
composer require manueldimmler/hmac-signature-middleware
```
