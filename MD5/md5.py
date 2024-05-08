import struct
import math
import hashlib

def hashlib_md5(message):

    hash_object = hashlib.md5()

    if isinstance(message, str):
        message = message.encode()

    hash_object.update(message)

    return hash_object.hexdigest()

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def md5(message):
    # Перетворюємо рядок у байти, якщо це необхідно
    if isinstance(message, str):
        message = message.encode()

    # Ініціалізація змінних
    a0 = 0x67452301  # A
    b0 = 0xefcdab89  # B
    c0 = 0x98badcfe  # C
    d0 = 0x10325476  # D

    # Таблиця констант (K)
    K = [int(abs(math.sin(i+1)) * 2**32) & 0xffffffff for i in range(64)]

    # Доповнення повідомлення до довжини, кратної 512 бітам
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    message += b'\x80'
    padding = b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    message += padding
    message += struct.pack('<Q', original_bit_len)

    # Обробка блоків по 512 біт (64 байта)
    for offset in range(0, len(message), 64):
        a, b, c, d = a0, b0, c0, d0
        chunk = message[offset:offset+64]
        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7*i) % 16

            f = (f + a + K[i] + struct.unpack('<I', chunk[4*g:4*g+4])[0]) & 0xffffffff
            a, b, c, d = d, (b + left_rotate(f, (s := [7, 12, 17, 22]*4 + [5, 9, 14, 20]*4 + [4, 11, 16, 23]*4 + [6, 10, 15, 21]*4)[i])) & 0xffffffff, b, c

        # Оновлення значень для наступного блоку
        a0 = (a0 + a) & 0xffffffff
        b0 = (b0 + b) & 0xffffffff
        c0 = (c0 + c) & 0xffffffff
        d0 = (d0 + d) & 0xffffffff

    # Повертаємо отриманий хеш
    digest = struct.pack('<IIII', a0, b0, c0, d0)
    return ''.join(f'{x:02x}' for x in digest)

#Перевіряємо правильність реалізації через hashlib
print(md5("Hello world!"))
print("Hashlib MD5: ", hashlib_md5("Hello world!"))
