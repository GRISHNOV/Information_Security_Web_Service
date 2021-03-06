# -------------------------------------------------
#   _____Cryptographic Function Library_____
#
# Ciphers in the current version of the library:
#
#       CESAR: YES
#       POLYALPHABETIC[Vigenère]: YES
#       MONOALPHABETIC: YES
#       BIGRAM: YES
#
# MIPT cryptography course project, 2020
# -------------------------------------------------


from Crypto.Hash import SHA256
import urllib.request, urllib.parse, http.client


TEST_INPUT_STRING = """\
1234567890\n!№;%:?*()\nThe quick brown fox jumps over the lazy dog\n\
Съешь же ещё этих мягких французских булок да выпей чаю\n\
Η ισχύς εν τη ενώσει\n思い煩う事はない。人生に意味などあるわけがないのだ。\n☹😡🙀🚜©✘↷♥🎧👍\
"""


def get_key_material(data: str) -> str:
    """
    Returns the SHA256 value as key material.
    """
    sha256_call = SHA256.new()
    sha256_call.update(data.encode('utf-8'))
    return sha256_call.hexdigest()


def get_sha256_numerical_value_nodejs_server(key: str) -> dict:
    """
    Interface for interaction with NodeJs sha256 key numeric value generator scheme.
    """
    params = urllib.parse.urlencode(
        {
            'user_key': key,
        }
    )
    conn = http.client.HTTPConnection("127.0.0.1:3000")
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    conn.request('POST', '/sha256_numerical_value', params, headers)
    response = conn.getresponse()
    return {"sha256_numerical_value": response.read()}


def get_cesar_encryption(data: str, key: str) -> dict:
    """
    Caesar cipher. Part for encryption.
    Shifts all characters from the DATA string to the KEY value in the UNICODE table. UNICODE space from 0 to 1,114,111 (0x10FFFF).
    The KEY value is formed as from_hex_to_dec(SHA256(key)) mod 1114112
    Returns the encrypted string, as well as its corresponding list of unicode characters.
    """
    encrypted_data_unicode_list = list()
    encrypted_data_string = str()
    key = int(get_sha256_numerical_value_nodejs_server(key)['sha256_numerical_value']) % 1114112
    for char_iterator in data:  # add character code and key value
        encrypted_data_unicode_list.append((ord(char_iterator) + key) % 1114112)
        encrypted_data_string += chr((ord(char_iterator) + key) % 1114112)
    return {"encrypted_string": encrypted_data_string, "encrypted_character_codes": encrypted_data_unicode_list}


def get_cesar_decryption(data: str, key: str) -> dict:
    """
    Caesar cipher. Part for decryption.
    The structure of the function is similar to the encryption function described above.
    """
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    key = int(get_sha256_numerical_value_nodejs_server(key)['sha256_numerical_value']) % 1114112
    for char_iterator in data:  # sub character code and key value
        decrypted_data_unicode_list.append((ord(char_iterator) - key) % 1114112)
        decrypted_data_string += chr((ord(char_iterator) - key) % 1114112)
    return {"decrypted_string": decrypted_data_string, "decrypted_character_codes": decrypted_data_unicode_list}


def get_polyalphabetic_encryption(data: str, key: str) -> dict:
    """
    Vigenère cipher. Part for encryption.
    For encryption (operate with unicode code): с[i] = (m[i] + k[i]) mod n
    Where n = 1114112 (power of UNICODE space), m[i] - char of message, c[i] - char of ciphertext, k[i] - char of key_material (key != key_material)
    Returns the encrypted string, as well as its corresponding list of unicode characters.
    """
    key_material = str()
    while len(key_material) < len(data):
        key_material += key
    key_material = key_material[:len(data)]
    encrypted_data_unicode_list = list()
    encrypted_data_string = str()
    for i in range(len(data)):  # с[i] = (m[i] + k[i]) mod 1114112
        encrypted_data_unicode_list.append((ord(data[i]) + ord(key_material[i])) % 1114112)
        encrypted_data_string += chr((ord(data[i]) + ord(key_material[i])) % 1114112)
    return {"encrypted_string": encrypted_data_string, "encrypted_character_codes": encrypted_data_unicode_list}


def get_polyalphabetic_decryption(data: str, key: str) -> dict:
    """
    Vigenère cipher. Part for decryption.
    For decryption (operate with unicode code): m[i] = (c[i] + n - k[i]) mod n
    Where n = 1114112 (power of UNICODE space), m[i] - char of message, c[i] - char of ciphertext, k[i] - char of key_material (key != key_material)
    The structure of the function is similar to the encryption function described above.
    """
    key_material = str()
    while len(key_material) < len(data):
        key_material += key
    key_material = key_material[:len(data)]
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    for i in range(len(data)):  # m[i] = (c[i] + n - k[i]) mod 1114112
        decrypted_data_unicode_list.append((ord(data[i]) + 1114112 - ord(key_material[i])) % 1114112)
        decrypted_data_string += chr((ord(data[i]) + 1114112 - ord(key_material[i])) % 1114112)
    return {"decrypted_string": decrypted_data_string, "decrypted_character_codes": decrypted_data_unicode_list}


def get_monoalphabetic_encryption(data: str, key: str) -> dict:
    """
    Monoalphabetic cipher. Part for encryption.
    For encryption (operate with unicode code): c[i] = c[i] + key_code
    Where key_code = key[0] + key[1] + ... + key[len[key] - 1] (operate with unicode code)
    Returns the encrypted string, as well as its corresponding list of unicode characters.
    """
    key_code = int()
    for char_iterator in key:
        key_code += ord(char_iterator)
    encrypted_data_unicode_list = list()
    encrypted_data_string = str()
    for char_iterator in data:  # add character code and key_code value
        encrypted_data_unicode_list.append((ord(char_iterator) + key_code) % 1114112)
        encrypted_data_string += chr((ord(char_iterator) + key_code) % 1114112)
    return {"encrypted_string": encrypted_data_string, "encrypted_character_codes": encrypted_data_unicode_list}


def get_monoalphabetic_decryption(data: str, key: str) -> dict:
    """
    Monoalphabetic cipher. Part for decryption.
    For decryption (operate with unicode code): c[i] = c[i] - key_code
    Where key_code = key[0] + key[1] + ... + key[len[key] - 1] (operate with unicode code)
    The structure of the function is similar to the encryption function described above.
    """
    key_code = int()
    for char_iterator in key:
        key_code += ord(char_iterator)
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    for char_iterator in data:  # sub character code and key_code value
        decrypted_data_unicode_list.append((ord(char_iterator) - key_code) % 1114112)
        decrypted_data_string += chr((ord(char_iterator) - key_code) % 1114112)
    return {"decrypted_string": decrypted_data_string, "decrypted_character_codes": decrypted_data_unicode_list}


def get_bigram_encryption(data: str, key: str) -> dict:
    """
    Bigram cipher. Part for encryption.
    c[k] = s-box[k] = m[i]*1114112 + m[i+1] + key_code where m[i] - unicode code for m[i] in data, k = 0,1,2,...,len(data) / 2
    Where key_code = key[0] + key[1] + ... + key[len[key] - 1] (operate with unicode code)
    """
    key_code = int()
    for char_iterator in key:
        key_code += ord(char_iterator)
    if len(data) % 2 != 0:  # an even amount of text is needed
        data += ' '
    encrypted_data_sub_numbers_list = list()
    for i in range(0, len(data) - 1, 2):
        encrypted_data_sub_numbers_list.append(ord(data[i])*1114112 + ord(data[i+1]) + key_code)
    encrypted_data_string = str()
    for code_iterator in encrypted_data_sub_numbers_list:  # padding leading zeros
        code_iterator = str(code_iterator)
        while len(code_iterator) < 13:
            code_iterator = '0' + code_iterator
        encrypted_data_string += code_iterator
    return {"encrypted_string": encrypted_data_string, "encrypted_character_codes": encrypted_data_sub_numbers_list}


def get_bigram_decryption(data: str, key: str) -> dict:
    """
    Bigram cipher. Part for decryption.
    In order not to store a large s-box in memory, we will select each substitution value by enumerating a specific sector of the s-box.
    """
    parsed_data = list()
    data_codes = list()
    data_codes = [data[i:i + 13] for i in range(0, len(data), 13)]
    for code_iterator in data_codes:  # removing leading zeros
        for i in range(len(code_iterator)):
            if code_iterator[i] != '0':
                code_iterator = code_iterator[i:]
                parsed_data.append(int(code_iterator))
                break
    key_code = int()
    for char_iterator in key:
        key_code += ord(char_iterator)
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    stop_search_flag = False
    for code_iterator in parsed_data:
        for i in range(code_iterator // 1114112, 1114112):
            if not stop_search_flag:
                for j in range(1114112):
                    if i*1114112 + j + key_code == code_iterator:
                        decrypted_data_unicode_list.append(i)
                        decrypted_data_unicode_list.append(j)
                        decrypted_data_string += chr(i) + chr(j)
                        stop_search_flag = True
                        break
            else:
                stop_search_flag = False
                break
    return {"decrypted_string": decrypted_data_string, "decrypted_character_codes": decrypted_data_unicode_list}


if __name__ == "__main__":
    pass
