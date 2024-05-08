from Crypto.Cipher import ARC4
from Crypto.Hash import SHA

def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def encrypt(input_text, key):
    key_hash = SHA.new(key.encode()).digest()  # Генерація SHA-1 хеша з ключа
    key = [b for b in key_hash]
    keystream = RC4(key)
    encrypted_bytes = bytes(ord(char) ^ next(keystream) for char in input_text)
    return encrypted_bytes.hex()

def decrypt(ciphertext_hex, key):
    key_hash = SHA.new(key.encode()).digest()  # Генерація SHA-1 хеша з ключа
    key = [b for b in key_hash]
    keystream = RC4(key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_text = ''.join(chr(byte ^ next(keystream)) for byte in ciphertext)
    return decrypted_text

def encrypt_with_library(input_text, key):
    key_hash = SHA.new(key.encode()).digest()
    cipher = ARC4.new(key_hash)
    encrypted_text = cipher.encrypt(input_text.encode())
    return encrypted_text.hex()

def decrypt_with_library(ciphertext_hex, key):
    key_hash = SHA.new(key.encode()).digest()
    cipher = ARC4.new(key_hash)
    encrypted_text = bytes.fromhex(ciphertext_hex)
    decrypted_text = cipher.decrypt(encrypted_text).decode()
    return decrypted_text

# Тестування алгоритму для порівняння власної реалізації та бібліотечної
key = 'Hello'
plaintext = 'World'
ciphertext_hex = encrypt_with_library(plaintext, key)
print("Encrypted with library in HEX:", ciphertext_hex)

decrypted_text = decrypt_with_library(ciphertext_hex, key)
print("Decrypted with library:", decrypted_text)

ciphertext_hex_2 = encrypt(plaintext, key)
print("Encrypted with RC4 in HEX:", ciphertext_hex_2)

decrypted_text_2 = decrypt(ciphertext_hex_2, key)
print("Decrypted with RC4:", decrypted_text_2)
