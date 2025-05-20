"""
2 berichten met dezelfde Ksession en nonce
Dit leidt tot hergebruk van keystream
ciphertext1 + ciphertext2 = plaintext1 + plaintext2
"""

from Crypto.Cipher import AES

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

Ksession = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

nonce = bytes([0xaa])

plaintext1 = b"Attack at dawn"
plaintext2 = b"Attack at dusk"

cipher1 = AES.new(Ksession, AES.MODE_CTR, nonce=nonce)
cipher_text1 = cipher1.encrypt(plaintext1)

cipher2 = AES.new(Ksession, AES.MODE_CTR, nonce=nonce)
cipher_text2 = cipher2.encrypt(plaintext2)

xor_ct = xor_bytes(cipher_text1, cipher_text2)
xor_pt = xor_bytes(plaintext1, plaintext2)

print("Ciphertext 1: ", cipher_text1.hex())
print("Ciphertext 2: ", cipher_text2.hex())
print(f"XOR Ciphertexts: {xor_ct.hex()}")
print(f"XOR Plaintexts:  {xor_pt.hex()}")

recovered_plaintext2 = xor_bytes(plaintext1, xor_ct)
print(f"\nRecovered plaintext2: {recovered_plaintext2}")