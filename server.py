from murmurat import *

import socket, os

UDP_IP = "127.0.0.1"
UDP_PORT = 1400 #1401 voor MITM

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

# --- DH Key Exchange ---
server_priv, server_pub = dh_keygen()
client_pub_bytes, addr = sock.recvfrom(4096)
client_pub = int.from_bytes(client_pub_bytes, "big")
server_pub_bytes = server_pub.to_bytes(256, "big")
sock.sendto(server_pub_bytes, addr)
shared_secret = dh_shared_secret(client_pub, server_priv)
ksession = ksession_from_secret(shared_secret)

# --- HELLO ---
server_pubkey_id = os.urandom(4)
rsa_key = rsa_keygen()
client_hello, addr = sock.recvfrom(1024)
client_pubkey_id, client_pubkey = parse_hello(client_hello)
hello_msg = build_hello(server_pubkey_id, rsa_key)
sock.sendto(hello_msg, addr)

# --- DATA ontvangen ---
while True:
    data_pkt, addr = sock.recvfrom(4096)
    parsed = parse_data_packet(data_pkt)
    nonce = parsed["nonce"]
    ciphertext = parsed["ciphertext"]
    signature = parsed["signature"]
    h = SHA3_256.new(ciphertext)

    try:
        pkcs1_15.new(client_pubkey).verify(h, signature.rstrip(b"\x00"))
        print("[SERVER] Signature OK!")
    except Exception:
        print("[SERVER] Signature FAIL!")
    cipher = AES.new(ksession, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(f"[SERVER] Plaintext: {plaintext!r}")
