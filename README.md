# Aufa Encryption
Another Encryption Helper

[![Build Status](https://travis-ci.org/aufa/Encryption.svg?branch=master)](https://travis-ci.org/aufa/Encryption)

Encrypt string or another type of value to encryption.
by default encryption use `mcrypt` with:
`MCRYPT_RIJNDAEL_256` + `MCRYPT_MODE_ECB`
and another encryption using alternative of `str_rot13` and encoded by `base64_encode`

## Encryption

```php
/**
 * Using default encryption mcrypt
 */
Aufa\Encryption\Encryption::encrypt('string to encrypt', 'saltkey');

/**
 * Using alternative type
 */
Aufa\Encryption\Encryption::altEncrypt('string to encrypt', 'saltkey');
```

## Decryption

```php
/**
 * Decrypt encrypted string with auto detect encryption use
 */
Aufa\Encryption\Encryption::decrypt('string to decrypt', 'saltkey');

// or can use
Aufa\Encryption\Encryption::altDecrypt('string to decrypt', 'saltkey');
```

## Install Using Composer

[Composer](https://getcomposer.org) is handy tool for adding library easily from packagist and another resource to your application.
Get Install on here : [https://getcomposer.org](https://getcomposer.org) and install on your OS.

```json
{
  "require": {
        "nwm/enproject" : "*"
  }
}
```

## Requirements

This library require php 5.3.2 or later. Suggest to enable `mcrypt` on your php configuration.

## License

GPLv3 or later [https://www.gnu.org/licenses/gpl-3.0.txt](https://www.gnu.org/licenses/gpl-3.0.txt)
