# Unified RSA interface for syncing cryptography
You can use this set of functions to work with RSA:
- Generating a public key using a passphrase
- Encryption using a public key
- Decryption using a passphrase

The [library](https://github.com/wwwtyro/cryptico) is used for working with RSA. For encoding text in [BASE64](https://github.com/dankogai/js-base64).
You can find a more detailed description on the repositories pages.

## Functions for importing

__Use the import from RsaInterface.ts for work__

`function generateRSAOpenKey(KeyPhrase: string, RsaKeyLength: number): object`

- Returns the public key and its hash for integrity. Use this to get the public key before encryption.

`function encryptRSA(OpenKeyValue: string, OpenKeyMD5Value:string, RsaKeyLength: number, PlainTextValue: string): object`

- Returns the ciphertext and related service information.

`function decryptRSA(CloseText: string, KeyPhrase: string, RsaKeyLength: number): object`

- Returns the decrypted message.

__The returned values of these functions should be represented as JSON and sent to the backend.__

## Example of use

```
OpenKeyObj = generateRSAOpenKey('mytestpassword', 1024);

EncrypObj = encryptRSA(OpenKeyObj['open_rsa_key'], OpenKeyObj['key_md5'], OpenKeyObj['RSA_len'], 'msg');

DecrypObj = decryptRSA(EncrypObj['encryption_result'], 'mytestpassword', EncrypObj['RSA_len']);
```
