<p align="center"> 
<img src="https://uploads-ssl.webflow.com/5d68f4898dfed907ad5a9edd/5d6e1673141661e4e8e99276_animat-lock-color.gif" width="200">
</p>

# Information_Security_Web_Service
Server part of Encryption/Decryption system for the Information Security course by Vladimirov at MIPT
    
The frontend version of the project is available in the [repository](https://github.com/denisstasyev/Information_Security_JS).

The main vector of the project presents a version on the Django framework, cryptographic libraries and checksums are implemented in Python. 

___The version for testing will be updated as soon as possible on the [hosting](http://xan-mixan.fun)___

You can find source codes with the PHP version of the backend in the branch [php_backend_version](https://github.com/GRISHNOV/Information_Security_Web_Service/tree/php_backend_version)
    
## Creators
    
This project was created by: [Ilya Grishnov](https://github.com/GRISHNOV), [Roman Maslov](https://github.com/jokerety), [Maxim Morev](https://github.com/Highoc)

## Architecture

The server software organization has the structure described below:

![alt text][architecture]
    
## Available Ciphers

*All implemented ciphers can work with Unicode characters.*
    
- Cesar
- Monoalphabetic 
- Polyalphabetic (Vigenère)
- Bigram (Porta's with an additional shift)
    
## Available checksums
    
- CRC16 (USB)
- CRC24
- CRC32
- Fletcher 32
    
## Description of cryptographic algorithms
### Ceaser cipher
    
The cipher is based on a shift in the order of characters by the key value. In this implementation, it is possible to encrypt/decrypt any Unicode characters (including hieroglyphs and emoticons). It shifts the serial number in the unicode table. The shift is performed in the ring modulo 1114112, since the Unicode space represents the values from 0 to 1,114,111 (0x10FFFF).
    
![alt text][ceaserCipher_logo]
    
### Monoalphabetic cipher
    
The idea of a cipher is similar to Caesar's cipher, however, as a key, it is possible to use not only integer values, but also strings. In this case, the key value is formed as the sum of the Unicode character numbers from the key string.
    
### Polyalphabetic (Vigenère) cipher
    
For encryption (operate with [unicode numbers](https://unicode-table.com)): 

![alt text][BigramEncrypt]

Where  n = 1114112  (power of Unicode space), m[i] - char of message, c[i] - char of ciphertext, k[i] - char of key material, obtained by cyclic repetition of the key line. More detailed [description](https://en.wikipedia.org/wiki/Vigenère_cipher)

For decryption (operate with [unicode numbers](https://unicode-table.com)): 

![alt text][BigramDecrypt]

### Bigram (Porta's with an additional shift) cipher

This cipher is based on the sequential replacement of pairs of characters from plaintext in accordance with the replacement table. Below is an example of a table for the Cyrillic alphabet, however, in this implementation, a table of size 1114112 x 1114112 is used. An additional shift of values is implemented as in the monoalphabetic cipher.

![alt text][BigramCipher_logo]

[architecture]: https://github.com/GRISHNOV/Information_Security_Web_Service/blob/master/doc/architecture.png
[ceaserCipher_logo]: https://cdncontribute.geeksforgeeks.org/wp-content/uploads/ceaserCipher-1.png
[BigramCipher_logo]: https://sites.google.com/site/anisimovkhv/_/rsrc/1385774017706/learning/kripto/lecture/tema4/shifr_porta.png
[BigramEncrypt]: https://latex.codecogs.com/gif.latex?%24%24c%5Bi%5D%20%5Cequiv%20m%5Bi%5D%20&plus;%20k%5Bi%5D%20%5Cpmod%20n%24%24
[BigramDecrypt]: https://latex.codecogs.com/gif.latex?%24%24m%5Bi%5D%20%5Cequiv%20c%5Bi%5D%20&plus;%20n%20-%20k%5Bi%5D%20%5Cpmod%20n%24%24
