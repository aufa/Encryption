# Aufa Encryption
Another Encryption Helper

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

## License

GPLv3 or later [https://www.gnu.org/licenses/gpl-3.0.txt](https://www.gnu.org/licenses/gpl-3.0.txt)
