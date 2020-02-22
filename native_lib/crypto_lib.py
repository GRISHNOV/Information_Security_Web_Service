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


TEST_INPUT_STRING = """\
1234567890\n!№;%:?*()\nThe quick brown fox jumps over the lazy dog\n\
Съешь же ещё этих мягких французских булок да выпей чаю\n\
Η ισχύς εν τη ενώσει\n思い煩う事はない。人生に意味などあるわけがないのだ。\n☹😡🙀🚜©✘↷♥🎧👍\
"""


def get_cesar_encryption(data: str, key: int) -> dict:
    """
    Caesar cipher. Part for encryption.
    Shifts all characters from the DATA string to the KEY value in the UNICODE table. UNICODE space from 0 to 1,114,111 (0x10FFFF).
    Returns the encrypted string, as well as its corresponding list of unicode characters.
    """
    encrypted_data_unicode_list = list()
    encrypted_data_string = str()
    for char_iterator in data:  # add character code and key value
        encrypted_data_unicode_list.append((ord(char_iterator) + key) % 1114111)
        encrypted_data_string += chr((ord(char_iterator) + key) % 1114111)
    return {"encrypted_string": encrypted_data_string, "encrypted_character_codes": encrypted_data_unicode_list}


def get_cesar_decryption(data: str, key: int) -> dict:
    """
    Caesar cipher. Part for decryption.
    The structure of the function is similar to the encryption function described above.
    """
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    for char_iterator in data:  # sub character code and key value
        decrypted_data_unicode_list.append((ord(char_iterator) - key) % 1114111)
        decrypted_data_string += chr((ord(char_iterator) - key) % 1114111)
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
    Vigenère cipher. Part for encryption.
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
        encrypted_data_unicode_list.append((ord(char_iterator) + key_code) % 1114111)
        encrypted_data_string += chr((ord(char_iterator) + key_code) % 1114111)
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
        decrypted_data_unicode_list.append((ord(char_iterator) - key_code) % 1114111)
        decrypted_data_string += chr((ord(char_iterator) - key_code) % 1114111)
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
    encrypted_data_unicode_list = list()
    for i in range(0, len(data) - 1, 2):
        encrypted_data_unicode_list.append(ord(data[i])*1114112 + ord(data[i+1]) + key_code)
    return {"encrypted_character_codes": encrypted_data_unicode_list}


def get_bigram_decryption(data: list, key: str) -> dict:
    """
    Bigram cipher. Part for decryption.
    In order not to store a large s-box in memory, we will select each substitution value by enumerating a specific sector of the s-box.
    """
    key_code = int()
    for char_iterator in key:
        key_code += ord(char_iterator)
    decrypted_data_unicode_list = list()
    decrypted_data_string = str()
    stop_search_flag = False
    for code_iterator in data:
        for i in range(code_iterator // 1114112, 1114112):
            if not stop_search_flag:
                for j in range(1114112):
                    if i*1114112 + j + key_code == code_iterator:
                        decrypted_data_unicode_list.append(i)
                        decrypted_data_unicode_list.append(j)
                        decrypted_data_string += chr(i) + chr(j)
                        print(decrypted_data_string)
                        stop_search_flag = True
                        break
            else:
                stop_search_flag = False
                break
    return {"decrypted_string": decrypted_data_string, "decrypted_character_codes": decrypted_data_unicode_list}


if __name__ == "__main__":
    pass
