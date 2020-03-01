from django.shortcuts import render
from django.views import View
from django.http import HttpResponse
from native_lib import crypto_lib, checksum_lib
import json


class EncryptionView(View):
    def get(self, request):
        return render(request, "core/encryption.html")

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

        return render(request, "core/encryption.html", context)


class DecryptionView(View):
    def get(self, request):
        return render(request, "core/decryption.html")

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

        return render(request, "core/decryption.html", context)


class IndexView(View):
    def get(self, request):
        return render(request, "core/index.html")


class EncryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_encryption.html")


class DecryptionHelpView(View):
    def get(self, request):
        return render(request, "core/help_decryption.html")


class HashingView(View):
    def get(self, request):
        return render(request, "core/hashing.html")


def encrypt(msg, user_password, cipher_algorithm, check_sum_algorithm):
    encrypted = None
    check_sum = None
    if cipher_algorithm == "Шифр Цезаря":
        encrypted = crypto_lib.get_cesar_encryption(msg, int(user_password))
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
            check_sum = checksum_lib.get_fletcher32(msg)
        result["check_sum_value"] = check_sum
        result["check_sum_algorithm"] = check_sum_algorithm

    return {"json": json.dumps(result, indent=4, sort_keys=True, ensure_ascii=False,), "msg": encrypted.get('encrypted_string')}


def decrypt(msg, user_password, cipher_algorithm, check_sum_algorithm, check_sum_value):
    decoded = None
    check_sum_decoded = None

    if cipher_algorithm == "Шифр Цезаря":
        decoded = crypto_lib.get_cesar_decryption(msg, int(user_password)).get('decrypted_string')
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
            check_sum_decoded = checksum_lib.get_fletcher32(decoded)
        result["checked"] = "Совпала" if check_sum_value == check_sum_decoded else "Не совпала"
    return result