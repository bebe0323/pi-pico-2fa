import time
import struct
from hashlib import sha1

def base32_decode(s):
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    decoded = bytearray()

    # converting into bytes
    bits = 0
    value = 0
    for char in s:
        value = (value << 5) | base32_chars.index(char)
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded.append((value >> bits) & 0xFF)
    
    return bytes(decoded)

def to_big_endian(counter):
    counter_bytes = bytearray(8)
    
    for i in range(8):
        # extracting the i-th byte from the back, shifted by (7 - i) * 8 bits
        counter_bytes[i] = (counter >> (7 - i) * 8) & 0xFF
    
    return bytes(counter_bytes)


# hmac_sha1 implementation
def hmac_sha1(key, message):
    # block size of the hash
    block_size = 64
    
    # added zeros at the end to make the length of the block size 64
    key += b'\x00' * (block_size - len(key))

    # each byte 
    o_key_pad = bytearray((b ^ 0x5C) for b in key) # 92 1011100
    i_key_pad = bytearray((b ^ 0x36) for b in key) # 54 110110

    # inner hash
    inner_hash = sha1(i_key_pad + message).digest()

    # outer hash
    return sha1(o_key_pad + inner_hash).digest()

def generate_totp(secret_key, interval=30, digits=6):
    current_time = int(time.time())
    # uncomment on pico / 39600 sec: 11 hours (pico time was on UTC +11)
    # current_time -= 39600


    # computing counter / (//) -> integer division
    counter = current_time // interval
    
    # Decode the Base32 secret key
    secret_key_bytes = base32_decode(secret_key)

    # 8-byte big-endian integer
    counter_bytes = to_big_endian(counter)

    # secret_key_bytes: 10 bytes, counter_bytes: 8 bytes
    hmac_hash = hmac_sha1(secret_key_bytes, counter_bytes)

    # dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    binary_code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF

    # get the last 6 digits
    totp = binary_code % (10 ** digits)

    # totp may have less than 6 digits, add 0's at the front to make it 6 digit number
    totp_str = str(totp)
    totp_str_6_digits = '0' * (6 - len(totp_str)) + totp_str

    return str(totp_str_6_digits)


secret_key = 'KMPB45IZDYHWYOLF' # sap@gmail.com
# print('secret key len: ', len(secret_key)) 16 
print("6 digit TOTP Code:", generate_totp(secret_key))
