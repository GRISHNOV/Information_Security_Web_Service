from django.shortcuts import render
from django.views import View
from native_lib import crypto_lib, checksum_lib, hash_lib
import json

from native_lib.AES import AES, AES_nodejs
from native_lib.GOST import GOST
from native_lib.RSA import RSA_nodejs


class HashingView(View):
    def get(self, request):
        return render(request, "core/hashing.html")

    def post(self, request):
        form = request.POST
        check_sum_algorithm = form.get('check_sum_algorithm')
        msg = form.get('msg')
        context = {
            'text': 'Неверно заполнены поля',
        }
        if msg and check_sum_algorithm:
            result = hashing(msg, check_sum_algorithm)
            context = {
                'text': 'Ваше сообщение:',
                'msg': form.get('msg'),
                'jsonText': 'Контрольная сумма / Хеш сообщения в формате Json:',
                'json': result.get('json')
            }

        return render(request, "core/hashing.html", context)


class EncryptionView(View):
    def get(self, request):
        return render(request, "core/basic/encrypt.html")

    def post(self, request):
        form = request.POST
        cipher_algorithm = form.get('encryption_algorithm')
        user_password = form.get('user_password')
        check_sum_algorithm = form.get('check_sum_algorithm')
        msg = form.get('msg')
        context = {
            'text': 'Неверно заполнены поля',
        }
        if msg and user_password and cipher_algorithm:
            result = encrypt(msg, user_password, cipher_algorithm, check_sum_algorithm)
            context = {
                'text': 'Зашифрованное сообщение',
                'msg': result.get('msg'),
                'jsonText': 'JSON для отправки на сервер для расшифрования:',
                'json': result.get('json')
            }

        return render(request, "core/basic/encrypt.html", context)


class DecryptionView(View):
    def get(self, request):
        return render(request, "core/basic/decrypt.html")

    def post(self, request):
        form = request.POST
        user_password = form.get('user_password')
        msg = json.loads(form.get('msg'))
        print(msg)
        encrypted_data = msg.get('encrypted_data')
        cipher_algorithm = msg.get('cipher_algorithm')
        check_sum_algorithm = msg.get('check_sum_algorithm')
        check_sum_value = msg.get('check_sum_value')
        context = {
            'text': 'Неверный формат введенных данных',
        }

        if encrypted_data and cipher_algorithm and user_password:
            result = decrypt(encrypted_data, user_password, cipher_algorithm, check_sum_algorithm, check_sum_value)
            context = {
                "text": "Результат",
                "msg": result.get('msg'),
                "checked": result.get('checked')
            }

        return render(request, "core/basic/decrypt.html", context)


class IndexView(View):
    def get(self, request):
        return render(request, "core/index.html")


class EncryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_encryption.html")


class DecryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_decryption.html")


def hashing(msg, check_sum_algorithm):
    result, check_sum = dict(), dict()
    if check_sum_algorithm == "CRC16":
        check_sum = checksum_lib.get_crc16_modbus(msg)
    elif check_sum_algorithm == "CRC24":
        check_sum = checksum_lib.get_crc24(msg)
    elif check_sum_algorithm == "CRC32":
        check_sum = checksum_lib.get_crc32(msg)
    elif check_sum_algorithm == "FLETCHER":
        check_sum = checksum_lib.get_fletcher16(msg)
    elif check_sum_algorithm == "SHA224":
        check_sum = hash_lib.get_sha224(msg)
    elif check_sum_algorithm == "SHA256":
        check_sum = hash_lib.get_sha256(msg)
    elif check_sum_algorithm == "SHA384":
        check_sum = hash_lib.get_sha384(msg)
    elif check_sum_algorithm == "SHA512":
        check_sum = hash_lib.get_sha512(msg)
    elif check_sum_algorithm == "SHA3_224":
        check_sum = hash_lib.get_sha3_224(msg)
    elif check_sum_algorithm == "SHA3_256":
        check_sum = hash_lib.get_sha3_256(msg)
    elif check_sum_algorithm == "SHA3_384":
        check_sum = hash_lib.get_sha3_384(msg)
    elif check_sum_algorithm == "SHA3_512":
        check_sum = hash_lib.get_sha3_512(msg)
    elif check_sum_algorithm == "SHA3_512_KECCAK":
        check_sum = hash_lib.get_sha3_keccak_512(msg)
    result["check_sum_value"] = check_sum
    result["check_sum_algorithm"] = check_sum_algorithm
    result["message"] = msg

    return {"json": json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False,)}


def encrypt(msg, user_password, cipher_algorithm, check_sum_algorithm):
    encrypted = None
    check_sum = None
    if cipher_algorithm == "Цезарь":
        encrypted = crypto_lib.get_cesar_encryption(msg, user_password)
    elif cipher_algorithm == "Моноалфавитный шифр":
        encrypted = crypto_lib.get_monoalphabetic_encryption(msg, user_password)
    elif cipher_algorithm == "Полиалфавитный шифр":
        encrypted = crypto_lib.get_polyalphabetic_encryption(msg, user_password)
    elif cipher_algorithm == "Биграммный шифр":
        encrypted = crypto_lib.get_bigram_encryption(msg, user_password)

    result = {
        "encrypted_data_codes": encrypted.get('encrypted_character_codes'),
        "encrypted_data": encrypted.get('encrypted_string'),
        "cipher_algorithm": cipher_algorithm,
    }

    if check_sum_algorithm:
        if check_sum_algorithm == "CRC16":
            check_sum = checksum_lib.get_crc16_usb(msg)
        elif check_sum_algorithm == "CRC24":
            check_sum = checksum_lib.get_crc24(msg)
        elif check_sum_algorithm == "CRC32":
            check_sum = checksum_lib.get_crc32(msg)
        elif check_sum_algorithm == "FLETCHER":
            check_sum = checksum_lib.get_fletcher16(msg)
        result["check_sum_value"] = check_sum
        result["check_sum_algorithm"] = check_sum_algorithm

    return {"json": json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False,), "msg": encrypted.get('encrypted_string')}


def decrypt(msg, user_password, cipher_algorithm, check_sum_algorithm, check_sum_value):
    decoded = None
    check_sum_decoded = None

    if cipher_algorithm == "Цезарь":
        decoded = crypto_lib.get_cesar_decryption(msg, user_password).get('decrypted_string')
    elif cipher_algorithm == "Моноалфавитный шифр":
        decoded = crypto_lib.get_monoalphabetic_decryption(msg, user_password).get('decrypted_string')
    elif cipher_algorithm == "Полиалфавитный шифр":
        decoded = crypto_lib.get_polyalphabetic_decryption(msg, user_password).get('decrypted_string')
    elif cipher_algorithm == "Биграммный шифр":
        decoded = crypto_lib.get_bigram_decryption(msg, user_password).get('decrypted_string')
    result = {
        "msg": decoded
    }
    if check_sum_algorithm:
        if check_sum_algorithm == "CRC16":
            check_sum_decoded = checksum_lib.get_crc16_usb(decoded)
        elif check_sum_algorithm == "CRC24":
            check_sum_decoded = checksum_lib.get_crc24(decoded)
        elif check_sum_algorithm == "CRC32":
            check_sum_decoded = checksum_lib.get_crc32(decoded)
        elif check_sum_algorithm == "FLETCHER":
            check_sum_decoded = checksum_lib.get_fletcher16(decoded)
        result["checked"] = "Совпала" if check_sum_value == check_sum_decoded else "Не совпала"
    return result


class AESEncryptionView(View):
    def get(self, request):
        return render(request, "core/aes/encrypt.html")

    def post(self, request):
        data = request.POST

        secret = data.get('secret')
        mode = data.get('mode')
        text = data.get('text')

        if not secret or not mode or not text:
            context = {
                'error': 'Заполните все поля...'
            }
            return render(request, "core/aes/encrypt.html", context)

        if mode == "aes256ecb":
            encrypted_result = AES_nodejs.get_aes256ecb_encryption_from_nodejs_server(text, secret)
            result = {
                'encrypted_data': encrypted_result["encrypted_data"].decode("utf-8"),
                'cipher_algorithm': 'AES-256/ECB',
                'initialization_vector': "void for ECB",
            }

        if mode == "aes256cbc":
            encrypted_result = AES_nodejs.get_aes256cbc_encryption_from_nodejs_server(text, secret)
            result = {
                'encrypted_data': json.loads(encrypted_result)["encrypted_data"],
                'cipher_algorithm': 'AES-256/CBC',
                'initialization_vector': json.loads(encrypted_result)["user_iv"],
            }

        if mode == "aes256ctr":
            encrypted_result = AES_nodejs.get_aes256ctr_encryption_from_nodejs_server(text, secret)
            result = {
                'encrypted_data': encrypted_result["encrypted_data"].decode("utf-8"),
                'cipher_algorithm': 'AES-256/CTR',
                'initialization_vector': "void for CTR",
            }

        if mode == "aes256cfb":
            encrypted_result = AES_nodejs.get_aes256cfb_encryption_from_nodejs_server(text, secret)
            result = {
                'encrypted_data': json.loads(encrypted_result)["encrypted_data"],
                'cipher_algorithm': 'AES-256/CFB',
                'initialization_vector': json.loads(encrypted_result)["user_iv"],
            }

        if mode == "aes256ofb":
            encrypted_result = AES_nodejs.get_aes256ofb_encryption_from_nodejs_server(text, secret)
            result = {
                'encrypted_data': json.loads(encrypted_result)["encrypted_data"],
                'cipher_algorithm': 'AES-256/OFB',
                'initialization_vector': json.loads(encrypted_result)["user_iv"],
            }

        context = {
            'result': result,
            'json': json.dumps(result, indent=4),
        }
        return render(request, "core/aes/encrypt.html", context)


class AESDecryptionView(View):
    def get(self, request):
        return render(request, "core/aes/decrypt.html")

    def post(self, request):
        data = request.POST

        secret = data.get('secret')
        data = data.get('data')

        if not data or not secret:
            context = {
                'error': 'Заполните все поля...'
            }
            return render(request, "core/aes/decrypt.html", context)

        try:
            json_data = json.loads(data)
            if  not isinstance(json_data, dict) or\
                'encrypted_data' not in json_data or not json_data['encrypted_data'] or \
                'cipher_algorithm' not in json_data or not json_data['cipher_algorithm'] or \
                'initialization_vector' not in json_data:
                raise KeyError()
        except (json.JSONDecodeError, KeyError):
            context = {
                'error': 'Введите корректный json...'
            }
            return render(request, "core/aes/decrypt.html", context)

        if json_data["cipher_algorithm"] == "AES-256/ECB":
            decrypted_result = AES_nodejs.get_aes256ecb_decryption_from_nodejs_server(json_data['encrypted_data'],
                                                                                      secret)

        if json_data["cipher_algorithm"] == "AES-256/CBC":
            decrypted_result = AES_nodejs.get_aes256cbc_decryption_from_nodejs_server(json_data['encrypted_data'],
                                                                                      secret, json_data['initialization_vector'])

        if json_data["cipher_algorithm"] == "AES-256/CTR":
            decrypted_result = AES_nodejs.get_aes256ctr_decryption_from_nodejs_server(json_data['encrypted_data'],
                                                                                      secret)

        if json_data["cipher_algorithm"] == "AES-256/CFB":
            decrypted_result = AES_nodejs.get_aes256cfb_decryption_from_nodejs_server(json_data['encrypted_data'],
                                                                                      secret, json_data['initialization_vector'])

        if json_data["cipher_algorithm"] == "AES-256/OFB":
            decrypted_result = AES_nodejs.get_aes256ofb_decryption_from_nodejs_server(json_data['encrypted_data'],
                                                                                      secret, json_data['initialization_vector'])

        context = {
            'text': decrypted_result["decrypted_data"].decode("utf-8"),
        }

        return render(request, "core/aes/decrypt.html", context)


class GOSTEncryptionView(View):
    def get(self, request):
        return render(request, "core/gost/encrypt.html")

    def post(self, request):
        data = request.POST

        secret = data.get('secret')
        mode = data.get('mode')
        text = data.get('text')

        if not secret or not mode or not text:
            context = {
                'error': 'Заполните все поля...'
            }
            return render(request, "core/gost/encrypt.html", context)

        key = GOST.generate_key(secret)

        iv, encrypted_data = GOST.encrypt(text, mode, key)
        result = {
            'encrypted_data': encrypted_data,
            'cipher_algorithm': 'GOST',
            'cipher_mode': mode,
            'cipher_iv': iv,
        }
        context = {
            'result': result,
            'json': json.dumps(result, indent=4),
        }
        return render(request, "core/gost/encrypt.html", context)


class GOSTDecryptionView(View):
    def get(self, request):
        return render(request, "core/gost/decrypt.html")

    def post(self, request):
        data = request.POST

        secret = data.get('secret')
        data = data.get('data')

        if not data or not secret:
            context = {
                'error': 'Заполните все поля...'
            }
            return render(request, "core/gost/decrypt.html", context)

        try:
            json_data = json.loads(data)
            if not isinstance(json_data, dict) or \
                    'encrypted_data' not in json_data or not json_data['encrypted_data'] or \
                    'cipher_mode' not in json_data or not json_data['cipher_mode'] or \
                    'cipher_iv' not in json_data:
                raise KeyError()
        except (json.JSONDecodeError, KeyError):
            context = {
                'error': 'Введите корректный json...'
            }
            return render(request, "core/gost/decrypt.html", context)

        key = GOST.generate_key(secret)
        try:
            text = GOST.decrypt(json_data['encrypted_data'], json_data['cipher_mode'], key,
                               json_data['cipher_iv'])
        except UnicodeDecodeError:
            context = {
                'error': 'Введите корректный секрет...'
            }
            return render(request, "core/gost/decrypt.html", context)

        context = {
            'text': text,
        }

        return render(request, "core/gost/decrypt.html", context)


class RSAEncryptionView(View):
    def get(self, request):
        return render(request, "core/rsa/encrypt.html")

    def post(self, request):
        data = request.POST

        open_rsa_key_json = data.get('open_rsa_key_json')
        text = data.get('text')

        if not open_rsa_key_json or not text:
            context = {
                'error': 'Заполните все поля...'
            }
            return render(request, "core/rsa/encrypt.html", context)

        try:
            json_data = json.loads(data)
            if not isinstance(json_data, dict) or \
                    'open_rsa_key' not in json_data or not json_data['open_rsa_key'] or \
                    'key_md5' not in json_data or not json_data['key_md5']:
                raise KeyError()
        except (json.JSONDecodeError, KeyError):
            context = {
                'error': 'Введите корректный json...'
            }
            return render(request, "core/rsa/encrypt.html", context)

        #   ____TEMPORARY____

        # result = {
        #     'encrypted_data': encrypted_data,
        #     'cipher_algorithm': 'GOST',
        #     'cipher_mode': mode,
        #     'cipher_iv': iv,
        # }
        # context = {
        #     'result': result,
        #     'json': json.dumps(result, indent=4),
        # }
        # return render(request, "core/rsa/encrypt.html", context)