from base64 import b64decode, b64encode
from Crypto.Hash import SHA256
from Crypto import Random
from pygost.gost28147 import ecb_decrypt, ecb_encrypt, cbc_decrypt, cbc_encrypt, cfb_decrypt, cfb_encrypt, BLOCKSIZE


class GOST:
    @staticmethod
    def add_padding(data):
        length = 8 - (len(data) % 8)
        data += bytes([0x40] + [0x00] * (length - 1))
        return data

    @staticmethod
    def remove_padding(data):
        for i in range(8):
            if data[-1] == 0x00:
                data = data[:-1]
            elif data[-1] == 0x40:
                data = data[:-1]
                break
            else:
                break
        return data

    @staticmethod
    def generate_key(secret):
        h = SHA256.new()
        h.update(secret.encode('utf-8'))
        return h.digest()

    @staticmethod
    def encrypt(text, mode, key, iv=Random.new().read(BLOCKSIZE)):
        encrypted_data = None
        if mode == 'ECB':
            encrypted_data = ecb_encrypt(key, GOST.add_padding(text.encode('utf-8')))
            iv = b''
        elif mode == 'CBC':
            encrypted_data = cbc_encrypt(key,  GOST.add_padding(text.encode('utf-8')), iv)
        elif mode == 'CFB':
            encrypted_data = cfb_encrypt(key,  GOST.add_padding(text.encode('utf-8')), iv)
        return iv.hex(), b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_text, mode, key, iv):
        encrypted_data = b64decode(encrypted_text.encode('utf-8'))
        decrypted_data = None
        if mode == 'ECB':
            decrypted_data = GOST.remove_padding(ecb_decrypt(key, encrypted_data))
        elif mode == 'CBC':
            decrypted_data = GOST.remove_padding(cbc_decrypt(key, encrypted_data))
        elif mode == 'CFB':
            decrypted_data = GOST.remove_padding(cfb_decrypt(key, encrypted_data,  bytes.fromhex(iv)))
        return decrypted_data.decode('utf-8')
