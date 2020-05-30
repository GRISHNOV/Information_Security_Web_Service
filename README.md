<p align="center"> 
<img src="https://uploads-ssl.webflow.com/5d68f4898dfed907ad5a9edd/5d6e1673141661e4e8e99276_animat-lock-color.gif" width="200">
</p>

<h1 align="center">Information_Security_Web_Service</h1>
Server part of Encryption/Decryption system for the Information Security course by Vladimirov at MIPT (student project).

The frontend version of the project is available in the [repository](https://github.com/denisstasyev/Information_Security_JS).

The main vector of the project presents a version on the Django framework, cryptographic libraries and checksums are implemented in Python. Some cryptographic js libraries are also used via nodejs.
    
## Creators
    
This project was created by: [Ilya Grishnov](https://github.com/GRISHNOV), [Roman Maslov](https://github.com/jokerety), [Maxim Morev](https://github.com/Highoc).

## Architecture

The server software organization has the structure described below:

<p align="center"> 
<img src="https://github.com/GRISHNOV/Information_Security_Web_Service/blob/master/doc/architecture.png" width="700">
</p>

For RSA and AES implementation, part of the service runs on nodejs. The local nodejs server runs on port 3000 and accepts requests from Django using the POST method. To deploy the app, run the django project and nodejs_runserver.js via nodejs.
    
## Available Ciphers

*All implemented ciphers can work with Unicode characters.*
    
- Cesar
- Monoalphabetic 
- Polyalphabetic (Vigenère)
- Bigram (Porta's with an additional shift)
- GOST-98
- RSA (512,1024,2048)
- AES (ECB, CBC, CTR, CFB,OFB)
    
## Available checksums and hash
    
- CRC16 (USB)
- CRC24
- CRC32
- Fletcher
- SHA224
- SHA384
- SHA512
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHA3-512-KECCAK
    
## Description of some realised cryptographic algorithms
### Ceaser cipher
    
The cipher is based on a shift in the order of characters by the key value. In this implementation, it is possible to encrypt/decrypt any Unicode characters (including hieroglyphs and emoticons). It shifts the serial number in the unicode table. The shift is performed in the ring modulo 1114112, since the Unicode space represents the values from 0 to 1,114,111 (0x10FFFF).
    
<p align="center"> 
<img src="https://cdncontribute.geeksforgeeks.org/wp-content/uploads/ceaserCipher-1.png" width="500">
</p>
    
### Monoalphabetic cipher
    
The idea of a cipher is similar to Caesar's cipher, however, as a key, it is possible to use not only integer values, but also strings. In this case, the key value is formed as the sum of the Unicode character numbers from the key string.
    
### Polyalphabetic (Vigenère) cipher

A detailed description can be found [here](https://en.wikipedia.org/wiki/Vigenère_cipher).

Where  n = 1114112  (power of Unicode space), m[i] - char of message, c[i] - char of ciphertext, k[i] - char of key material, obtained by cyclic repetition of the key line.

We operate with [unicode numbers](https://unicode-table.com).

### Bigram (Porta's with an additional shift) cipher

This cipher is based on the sequential replacement of pairs of characters from plaintext in accordance with the replacement table. Below is an example of a table for the Cyrillic alphabet, however, in this implementation, a table of size 1114112 x 1114112 is used. An additional shift of values is implemented as in the monoalphabetic cipher.

<p align="center"> 
<img src="https://sites.google.com/site/anisimovkhv/_/rsrc/1385774017706/learning/kripto/lecture/tema4/shifr_porta.png" width="700">
</p> 
