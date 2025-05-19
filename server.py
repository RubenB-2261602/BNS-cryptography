import socket
import random
import os
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Signature import pkcs1_15

def handle_data_packet(packet: bytes, Ksession: bytes, client_pubkey):
    length = int.from_bytes(packet[:2], "big")
    nonce = packet[2:3]
    timestamp = int.from_bytes(packet[3:7], "big")
    sig_start = -512
    pubkeyid_start = sig_start - 4
    ciphertext = packet[7:pubkeyid_start]
    pubkey_id = packet[pubkeyid_start:sig_start]
    signature = packet[sig_start:]

    now = int(time.time())
    if abs(now - timestamp) > 60:
        print(f"[SERVER] Tijdstempel is te oud: {now} - {timestamp}")
        return
    
    h = SHA3_256.new(ciphertext)
    try:
        pkcs1_15.new(client_pubkey).verify(h, signature.rstrip(b'\x00'))
        print(f"[SERVER] Handtekening is geldig.")
    except (ValueError, TypeError):
        print(f"[SERVER] Handtekening is ongeldig.")
        return
    
    cipher = AES.new(Ksession, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(f"[SERVER] Ontvangen plaintext: {plaintext.decode('utf-8')}")


g = 2
p = int("""
21894553314596771561196871363069090541066762948701574567164020109267136679658370486943743975837875551999724125675479713926610011157978943480748521006430553187436563793040135859147314200060834037476721054687020332554521482953307933279332569246540222644899052019734402578132147790321819673041697183485577751556671866087760112758069112215318623491422973743109959408989119853925061221424914969592119964092790966627078188061704838361168099808241706347071334601734718683912103883792713733499106500967971247312946335678666117988734426818897467285005428051841972129518278136019917483333422790215788404956414952116894714913327
""".replace('\n', '').replace(' ', ''))

UDP_IP = "127.0.0.1"
UDP_PORT = 1400

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))
print(f"[SERVER] Luistert op {UDP_IP}:{UDP_PORT}")

server_priv = random.randint(2, p - 2)
server_pub = pow(g, server_priv, p)

while True:
    data, addr = sock.recvfrom(4096)
    client_pub = int.from_bytes(data, "big")
    print(f"[SERVER] Ontving client DH-pub: {client_pub}")

    server_pub_bytes = server_pub.to_bytes(256, "big")
    sock.sendto(server_pub_bytes, addr)
    print(f"[SERVER] Stuurde eigen DH-pub naar client.")

    shared_secret = pow(client_pub, server_priv, p)
    ksession = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")[:16]
    print(f"[SERVER] Gedeelde geheim: {shared_secret}")
    print(f"[SERVER] Ksession (eerste 16 bytes): {ksession.hex()}")

    pubkey_id = os.urandom(4)
    rsa_key = RSA.generate(2048)
    n = rsa_key.n
    e = rsa_key.e
    n_bytes = n.to_bytes(512, "big")

    data, addr = sock.recvfrom(1024)
    client_pubkey_id = data[:4]
    client_n_bytes = data[4:516]
    client_n = int.from_bytes(client_n_bytes, "big")
    print(f"[SERVER] Ontving hello-bericht van client.")
    print(f"[SERVER] Client modulus: {hex(client_n)[:64]}")

    hello_msg = pubkey_id + n_bytes
    sock.sendto(hello_msg, addr)
    print(f"[SERVER] Stuurde hello-bericht naar client.")

    client_pubkey = RSA.construct((client_n, 65537))

    data, addr = sock.recvfrom(4096)
    if len(data) > 520:   # heuristiek: is DATA-pakket, niet HELLO
        handle_data_packet(data, ksession, client_pubkey)