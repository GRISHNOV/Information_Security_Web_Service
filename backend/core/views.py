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
                'text': 'Зашифрованное сообщение, и для передачи в JSON формате',
                'msg': result.get('msg'),
                'json': result.get('json')
            }

        return render(request, "core/encryption.html", context)


class DecryptionView(View):
    def get(self, request):
        return render(request, "core/decryption.html")

    def post(self, request):
        form = request.POST
        user_password = form.get('user_password')
        msg = form.get('msg')
        encrypted_string = None
        context = {
            'text': 'Неверный формат введенных данных',
        }
        if msg:
            encrypted_string = msg.get('encrypted_string')
        if encrypted_string and user_password:
            context = {
                'text': 'Зашифрованное сообщение',
            }
        return render(request, "core/encryption.html", context)


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
    if cipher_algorithm == "Caesar":
        encrypted = crypto_lib.get_cesar_encryption(msg, int(user_password))
    elif cipher_algorithm == "Monoalphabetic":
        encrypted = crypto_lib.get_monoalphabetic_encryption(msg, user_password)
    elif cipher_algorithm == "Polyalphabetic":
        encrypted = crypto_lib.get_polyalphabetic_encryption(msg, user_password)
    elif cipher_algorithm == "Bigram":
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
        result["checksum_value"] = check_sum
        result["checksum_algorithm"] = check_sum_algorithm

    return {"json": json.dumps(result), "msg": encrypted.get('encrypted_string')}


def decrypt(encrypted_string, user_password):
    decrypted = None

