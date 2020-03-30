<p align="center"> 
<img src="https://uploads-ssl.webflow.com/5d68f4898dfed907ad5a9edd/5d6e1673141661e4e8e99276_animat-lock-color.gif" width="200">
</p>

# Unified RSA interface for syncing cryptography</h1>

You can use set of functions from [RsaInterface.ts](https://github.com/GRISHNOV/Information_Security_Web_Service/blob/rsa_typescript_interface/RsaInterface.ts) to work with RSA:
- Generating a public key using a passphrase
- Encryption unicode text using a public key
- Decryption unicode text using a passphrase

This shell is based on the [library](https://github.com/wwwtyro/cryptico) for working with RSA. A single [BASE64](https://github.com/dankogai/js-base64) encoding is used before direct encryption.The encryption result is automatically represented using BASE64.

You can find more detailed descriptions of the libraries used in their official repositories.

## Functions for importing

__Use the import from RsaInterface.ts for work__

`function generateRSAOpenKey(KeyPhrase: string, RsaKeyLength: number): object`

- Returns the public key and its hash for integrity. Use this to get the public key before encryption. Use a key length of 512 or 1024 to avoid heavy CPU loads on frontend.

`function encryptRSA(OpenKeyValue: string, OpenKeyMD5Value:string, RsaKeyLength: number, PlainTextValue: string): object`

- Returns the ciphertext and related service information.

`function decryptRSA(CloseText: string, KeyPhrase: string, RsaKeyLength: number): object`

- Returns the decrypted message.

__The returned values of these functions should be represented as JSON and sent to the backend.__

## Example of use

```
let OpenKeyObj = generateRSAOpenKey('mytestpassword', 1024);

console.log(OpenKeyObj);

>>>   {
>>>     open_rsa_key: 'bFes/2YPE50zgxg6UkNbPg20mnAbJAAHOM0CQcqDDaMjSUm53AfyuwPdKtB3A18eiKPqJCm0aU4ewGmtZACuqBW4lk/j7zc1NobOIgemZyHivlQVTiCYG4NleasNxos6D9+pZLuWgTaVJSy3EulA9bbxhTdFjzkJhNs6IeMzdG8=',
>>>     key_md5: 'f36508963b58a183b1eca516765df82f',
>>>     RSA_len: 1024
>>>   }

let EncrypObj = encryptRSA(OpenKeyObj['open_rsa_key'], OpenKeyObj['key_md5'], OpenKeyObj['RSA_len'], 'msg');

console.log(EncrypObj);

>>>   {
>>>     encryption_result: 'ZdLlArKeJb9qxk6cH4WiZAPboJVBZFILxXA4YgJhGXuuF+MEmJVSugLEgNcUDsC1O59gJlOrY0mM53dugKgaZ4Roul9A3dkf/wK0Hto1zyllIM9G47W1TlmJSIb5wD5gxYhH7FWEOxehYi7wr48KE1C5K3qfMl2pp7HWaD9dulQ=?N5PzjIOwQm5uHt4/IF2LCDAXrQPLyZ8Cby1nwUgqXXI=',
>>>     cipher_algorithm: 'RSA',
>>>     RSA_len: 1024
>>>   }

let DecrypObj = decryptRSA(EncrypObj['encryption_result'], 'mytestpassword', EncrypObj['RSA_len']);

console.log(DecrypObj);

>>>   { 
>>>     decrypted_text: 'msg' 
>>>   }
```
Note that the library has a feature for automatically adding salt when encrypting, so encryption on the same key of the same text will give different values of the ciphertext.
