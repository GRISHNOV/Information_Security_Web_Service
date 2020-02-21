# -------------------------------------------------
#   _____Checksum Function Library_____
#
# Checksum in the current version of the library:
#
#       CRC16_usb: YES
#       CRC24: YES
#       CRC32: YES
#       FLETCHER32: YES
#
# MIPT cryptography course project, 2020
# -------------------------------------------------


import crcmod


TEST_INPUT_STRING = """\
1234567890\n!№;%:?*()\nThe quick brown fox jumps over the lazy dog\n\
Съешь же ещё этих мягких французских булок да выпей чаю\n\
Η ισχύς εν τη ενώσει\n思い煩う事はない。人生に意味などあるわけがないのだ。\n☹😡🙀🚜©✘↷♥🎧👍\
"""


def get_crc16_usb(data: str) -> dict:
    """
    Parameters:   Poly: 0x18005   Init-value: 0x0000	XOR-out: 0xFFFF
    Returns the CRC-16-USB checksum value in decimal and hexadecimal format.
    """
    crc16_call = crcmod.mkCrcFun(0x18005, initCrc=0x0000, xorOut=0xFFFF)
    return {"CRC16_usb_dec": crc16_call(data.encode()), "CRC16_usb_hex": hex(crc16_call(data.encode()))}


def get_crc24(data: str) -> dict:
    """
    Parameters:   Poly: 0x1864CFB   Init-value: 0xB704CE	XOR-out: 0x000000
    Returns the CRC-24 checksum value in decimal and hexadecimal format.
    """
    crc24_call = crcmod.mkCrcFun(0x1864CFB, initCrc=0xB704CE, xorOut=0x000000)
    return {"CRC24_dec": crc24_call(data.encode()), "CRC24_hex": hex(crc24_call(data.encode()))}


def get_crc32(data: str) -> dict:
    """
    Parameters:   Poly: 0x104C11DB7   Init-value: 0x00000000	XOR-out: 0xFFFFFFFF
    Returns the CRC-32 checksum value in decimal and hexadecimal format.
    """
    crc32_call = crcmod.mkCrcFun(0x104c11db7, initCrc=0, xorOut=0xFFFFFFFF)
    return {"CRC32_dec": crc32_call(data.encode()), "CRC32_hex": hex(crc32_call(data.encode()))}


def get_fletcher32(string):
    """
    Returns the Fletcher32 checksum value in decimal and hexadecimal format.
    """
    step_1 = list(map(ord, string))
    step_2 = [sum(step_1[:i]) % 65535 for i in range(len(step_1)+1)]
    fletcher_result = (sum(step_2) << 16) | max(step_2)
    return {"Fletcher32_dec": fletcher_result, "Fletcher32_hex": hex(fletcher_result)}


if __name__ == "__main__":
    pass
