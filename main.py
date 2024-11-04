import time
import struct
from hashlib import sha1

def base32_decode(s):
    base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    padding = '='
    s = s.rstrip(padding)
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

# custom hmac_sha1 implementatino
def hmac_sha1(key, message):
    # block size of teh hash
    block_size = 64
    if len(key) > block_size:
        key = sha1(key).digest()  # Hash the key if it's too long
    key += b'\x00' * (block_size - len(key))  # Pad key with zeros

    # paddings
    o_key_pad = bytearray((b ^ 0x5C) for b in key)
    i_key_pad = bytearray((b ^ 0x36) for b in key)

    # inner hash
    inner_hash = sha1(i_key_pad + message).digest()

    # outer hash
    return sha1(o_key_pad + inner_hash).digest()

# Generate TOTP function
def generate_totp(secret_key, interval=30, digits=6):
    # synchronized the current time as pico's time was ahead
    current_time = int(time.time()) - 39600
    print(current_time)
    # get the counter
    counter = current_time // interval
    
    # Decode the Base32 secret key
    secret_key_bytes = base32_decode(secret_key)

    # 8-byte big-endian integer
    counter_bytes = struct.pack(">Q", counter)

    hmac_hash = hmac_sha1(secret_key_bytes, counter_bytes)

    # dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    binary_code = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF

    # get the last 6 digits
    totp = binary_code % (10 ** digits)

    return str(totp)


secret_key = 'KMPB45IZDYHWYOLF' # sap@gmail.com
print("6 digit TOTP Code:", generate_totp(secret_key))
