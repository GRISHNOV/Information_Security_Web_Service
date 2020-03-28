from Crypto.Hash import SHA256
from Crypto.Cipher import AES as CryptoAES
from Crypto import Random
from base64 import b64decode, b64encode

import urllib.request, urllib.parse, http.client


class AES_nodejs:

    @staticmethod
    def get_aes256ecb_encryption_from_nodejs_server(data: str, key: str) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ecb_encrypt', params, headers)
        response = conn.getresponse()
        return {"encrypted_data": response.read()}

    @staticmethod
    def get_aes256ecb_decryption_from_nodejs_server(data: str, key: str) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ecb_decrypt', params, headers)
        response = conn.getresponse()
        return {"decrypted_data": response.read()}

    @staticmethod
    def get_aes256cbc_encryption_from_nodejs_server(data: str, key: str) -> bytes:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256cbc_encrypt', params, headers)
        response = conn.getresponse()
        return response.read()

    @staticmethod
    def get_aes256cbc_decryption_from_nodejs_server(data: str, key: str, iv: list) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
                'user_iv': iv,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256cbc_decrypt', params, headers)
        response = conn.getresponse()
        return {"decrypted_data": response.read()}

    @staticmethod
    def get_aes256ctr_encryption_from_nodejs_server(data: str, key: str) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ctr_encrypt', params, headers)
        response = conn.getresponse()
        return {"encrypted_data": response.read()}

    @staticmethod
    def get_aes256ctr_decryption_from_nodejs_server(data: str, key: str) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ctr_decrypt', params, headers)
        response = conn.getresponse()
        return {"decrypted_data": response.read()}

    @staticmethod
    def get_aes256cfb_encryption_from_nodejs_server(data: str, key: str) -> bytes:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256cfb_encrypt', params, headers)
        response = conn.getresponse()
        return response.read()

    @staticmethod
    def get_aes256cfb_decryption_from_nodejs_server(data: str, key: str, iv: list) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
                'user_iv': iv,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256cfb_decrypt', params, headers)
        response = conn.getresponse()
        return {"decrypted_data": response.read()}

    @staticmethod
    def get_aes256ofb_encryption_from_nodejs_server(data: str, key: str) -> bytes:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ofb_encrypt', params, headers)
        response = conn.getresponse()
        return response.read()

    @staticmethod
    def get_aes256ofb_decryption_from_nodejs_server(data: str, key: str, iv: list) -> dict:
        params = urllib.parse.urlencode(
            {
                'user_data': data,
                'user_key': key,
                'user_iv': iv,
            }
        )
        conn = http.client.HTTPConnection("127.0.0.1:3000")
        headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
        conn.request('POST', '/aes256ofb_decrypt', params, headers)
        response = conn.getresponse()
        return {"decrypted_data": response.read()}


class AES:

    MODES = {
        'ECB': CryptoAES.MODE_ECB,
        'CBC': CryptoAES.MODE_CBC,
        'GCM': CryptoAES.MODE_GCM,
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
        if mode == CryptoAES.MODE_ECB:
            aes = CryptoAES.new(key, mode)
            iv = b''
        else:
            aes = CryptoAES.new(key, mode, iv)
        encrypted_data = aes.encrypt(AES.add_padding(text.encode('utf-8')))
        return iv.hex(), b64encode(encrypted_data).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_text, mode, key, iv):
        encrypted_data = b64decode(encrypted_text.encode('utf-8'))
        if mode == CryptoAES.MODE_ECB:
            aes = CryptoAES.new(key, mode)
        else:
            aes = CryptoAES.new(key, mode, bytes.fromhex(iv))
        return AES.remove_padding(aes.decrypt(encrypted_data)).decode('utf-8')
