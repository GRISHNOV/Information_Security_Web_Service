# -------------------------------------------------
#   _____Hash Function Library_____
#
# Hash func in the current version of the library:
#
#       @@@ SHA-2 family @@@
#
#           SHA224: YES
#           SHA256: YES
#           SHA384: YES
#           SHA512: YES
#
#
#       @@@ SHA-3 family @@@
#
#           SHA3-224: YES
#           SHA3-256: YES
#           SHA3-384: YES
#           SHA3-512: YES
#           SHA3-keccak-512: YES
#
# MIPT cryptography course project, 2020
# -------------------------------------------------


from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.Hash import SHA3_224
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
from Crypto.Hash import keccak


TEST_INPUT_STRING = """\
1234567890\n!№;%:?*()\nThe quick brown fox jumps over the lazy dog\n\
Съешь же ещё этих мягких французских булок да выпей чаю\n\
Η ισχύς εν τη ενώσει\n思い煩う事はない。人生に意味などあるわけがないのだ。\n☹😡🙀🚜©✘↷♥🎧👍\
"""


def get_sha224(data: str) -> dict:
    """
    Returns the SHA224 hash value (hex).
    """
    sha224_call = SHA224.new()
    sha224_call.update(data.encode('utf-8'))
    return {"SHA224_hex": sha224_call.hexdigest()}


def get_sha256(data: str) -> dict:
    """
    Returns the SHA256 value (hex).
    """
    sha256_call = SHA256.new()
    sha256_call.update(data.encode('utf-8'))
    return {"SHA256_hex": sha256_call.hexdigest()}


def get_sha384(data: str) -> dict:
    """
    Returns the SHA384 value (hex).
    """
    sha384_call = SHA384.new()
    sha384_call.update(data.encode('utf-8'))
    return {"SHA384_hex": sha384_call.hexdigest()}


def get_sha512(data: str) -> dict:
    """
    Returns the SHA512 value (hex).
    """
    sha512_call = SHA512.new()
    sha512_call.update(data.encode('utf-8'))
    return {"SHA512_hex": sha512_call.hexdigest()}


def get_sha3_224(data: str) -> dict:
    """
    Returns the SHA3_224 hash value (hex).
    """
    sha3_224_call = SHA3_224.new()
    sha3_224_call.update(data.encode('utf-8'))
    return {"SHA3_224_hex": sha3_224_call.hexdigest()}


def get_sha3_256(data: str) -> dict:
    """
    Returns the SHA3_256 hash value (hex).
    """
    sha3_256_call = SHA3_256.new()
    sha3_256_call.update(data.encode('utf-8'))
    return {"SHA3_256_hex": sha3_256_call.hexdigest()}


def get_sha3_384(data: str) -> dict:
    """
    Returns the SHA3_384 hash value (hex).
    """
    sha3_384_call = SHA3_384.new()
    sha3_384_call.update(data.encode('utf-8'))
    return {"SHA3_384_hex": sha3_384_call.hexdigest()}


def get_sha3_512(data: str) -> dict:
    """
    Returns the SHA3_512 hash value (hex).
    """
    sha3_512_call = SHA3_512.new()
    sha3_512_call.update(data.encode('utf-8'))
    return {"SHA3_512_hex": sha3_512_call.hexdigest()}


def get_sha3_keccak_512(data: str) -> dict:
    sha3_keccak_512_call = keccak.new(digest_bits=512)
    sha3_keccak_512_call.update(data.encode('utf-8'))
    return {"SHA3_512_keccak_hex": sha3_keccak_512_call.hexdigest()}


if __name__ == "__main__":
    pass
