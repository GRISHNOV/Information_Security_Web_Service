from Crypto.Hash import SHA256
from Crypto.Cipher import AES as CryptoAES
from Crypto import Random
from base64 import b64decode, b64encode


class AES:
    MODES = {
        'ECB': CryptoAES.MODE_ECB,
        'CBC': CryptoAES.MODE_CBC,
        'GCM': CryptoAES.MODE_CTR,
    }

    @staticmethod
    def generate_key(secret):
        h = SHA256.new()
        h.update(secret.encode('utf-8'))
        return h.digest()

    @staticmethod
    def add_padding(data):
        length = 16 - (len(data) % 16)
        data += bytes([0x80] + [0x00] * (length - 1))
        return data

    @staticmethod
    def remove_padding(data):
        for i in range(16):
            if data[-1] == 0x00:
                data = data[:-1]
            elif data[-1] == 0x80:
                data = data[:-1]
                break
            else:
                break
        return data

    @staticmethod
    def encrypt(text, mode, key, iv=Random.new().read(CryptoAES.block_size)):
        aes = CryptoAES.new(key, mode, iv)
        encrypted_data = aes.encrypt(AES.add_padding(text.encode('utf-8')))
        return iv.hex(), b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_text, mode, key, iv):
        encrypted_data = b64decode(encrypted_text.encode('utf-8'))
        aes = CryptoAES.new(key, mode, iv)
        return AES.remove_padding(aes.decrypt(encrypted_data)).decode('utf-8')
