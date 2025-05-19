import socket
import random
import os
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Signature import pkcs1_15

def encrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    ctr = int.from_bytes(nonce, "big")
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext)

def build_data_packet(plaintext: bytes, Ksession: bytes, privKey, pubKey: bytes) -> bytes:
    nonce = os.urandom(1)
    timestamp = int(time.time()).to_bytes(4, "big")

    ciphertext = encrypt_aes_ctr(plaintext, Ksession, nonce)

    length = (1 + 4 + len(ciphertext) + 4 + 512)
    length_bytes = length.to_bytes(2, "big")

    h = SHA3_256.new(ciphertext)
    signature = pkcs1_15.new(privKey).sign(h)

    if len(signature) != 512:
        signature = signature.ljust(512, b'\x00')
    elif len(signature) > 512:
        signature = signature[:512]

    packet = b''
    packet += length_bytes # 2 bytes
    packet += nonce # 1 byte
    packet += timestamp # 4 bytes
    packet += ciphertext # len(ciphertext) bytes
    packet += pubKey # 4 bytes
    packet += signature # 512 bytes
    return packet
    


g = 2
p = int("""
21894553314596771561196871363069090541066762948701574567164020109267136679658370486943743975837875551999724125675479713926610011157978943480748521006430553187436563793040135859147314200060834037476721054687020332554521482953307933279332569246540222644899052019734402578132147790321819673041697183485577751556671866087760112758069112215318623491422973743109959408989119853925061221424914969592119964092790966627078188061704838361168099808241706347071334601734718683912103883792713733499106500967971247312946335678666117988734426818897467285005428051841972129518278136019917483333422790215788404956414952116894714913327
""".replace('\n', '').replace(' ', ''))

UDP_IP = "127.0.0.1"
UDP_PORT = 1400

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

client_priv = random.randint(2, p - 2)
client_pub = pow(g, client_priv, p)
client_pub_bytes = client_pub.to_bytes(256, "big")

sock.sendto(client_pub_bytes, (UDP_IP, UDP_PORT))
print(f"[CLIENT] Stuurde eigen DH-pub naar server.")

data, _ = sock.recvfrom(4096)
server_pub = int.from_bytes(data, "big")
print(f"[CLIENT] Ontving server DH-pub: {server_pub}")

shared_secret = pow(server_pub, client_priv, p)
ksession = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")[:16]
print(f"[CLIENT] Gedeelde geheim: {shared_secret}")
print(f"[CLIENT] Ksession (eerste 16 bytes): {ksession.hex()}")

pubkey_id = os.urandom(4)
rsa_key = RSA.generate(2048)
n = rsa_key.n
e = rsa_key.e
n_bytes = n.to_bytes(512, "big")

hello_msg = pubkey_id + n_bytes

sock.sendto(hello_msg, (UDP_IP, UDP_PORT))
print(f"[CLIENT] Stuurde hello-bericht naar server.")

data, _ = sock.recvfrom(1024)
server_pubkey_id = data[:4]
server_n_bytes = data[4:516]
server_n = int.from_bytes(server_n_bytes, "big")

print(f"[CLIENT] Ontving hello-bericht van server.")
print(f"[CLIENT] Server modulus: {hex(server_n)[:64]}")

server_pubkey = RSA.construct((server_n, 65537))

payload = b"SEREENTJE WE ARE COOKING!!!!!"

data_packet = build_data_packet(
    payload,
    ksession,
    rsa_key,
    pubkey_id
)

sock.sendto(data_packet, (UDP_IP, UDP_PORT))
print(f"[CLIENT] Stuurde data-pakket naar server! ({len(data_packet)} bytes)")
