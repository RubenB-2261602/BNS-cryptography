# duplicate_nonce_poc.py
#
# Proof‐of‐concept for the 1‐byte nonce vulnerability:
# Sends two DATA packets with the same nonce, then shows
# how P2 can be recovered if P1 is known.

import socket
import os
import time

from murmurat import (
    dh_keygen,
    dh_shared_secret,
    ksession_from_secret,
    rsa_keygen,
    build_hello,
    parse_hello,
    build_data_packet
)

UDP_IP   = "127.0.0.1"
UDP_PORT = 1400

def duplicate_nonce_poc():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 1) Perform DH key exchange
    client_priv, client_pub = dh_keygen()
    sock.sendto(client_pub.to_bytes(256, "big"), (UDP_IP, UDP_PORT))
    server_pub = int.from_bytes(sock.recv(4096), "big")
    ksession = ksession_from_secret(dh_shared_secret(server_pub, client_priv))

    # 2) Perform HELLO exchange
    pubkey_id = os.urandom(4)
    rsa_key   = rsa_keygen()
    sock.sendto(build_hello(pubkey_id, rsa_key), (UDP_IP, UDP_PORT))
    srv_hello = sock.recv(1024)
    _, server_pubkey = parse_hello(srv_hello)

    # 3) Craft two messages with the same nonce
    fixed_nonce = b'\x42'  # fixed 1‐byte nonce
    P1 = b"TOP SECRET: AZURIA IS UNDER ATTACK!"
    P2 = b"FLAG = CTF{NONCE_FAIL_LEAK}"

    pkt1 = build_data_packet(P1, ksession, rsa_key, pubkey_id, forced_nonce=fixed_nonce)
    pkt2 = build_data_packet(P2, ksession, rsa_key, pubkey_id, forced_nonce=fixed_nonce)

    # 4) Send both packets in succession
    sock.sendto(pkt1, (UDP_IP, UDP_PORT))
    time.sleep(0.1)
    sock.sendto(pkt2, (UDP_IP, UDP_PORT))
    print("[POC] Twee berichten verstuurd met nonce=0x42")

    # 5) Extract ciphertexts and recover P2 from P1
    def extract_ct(pkt: bytes) -> bytes:
        # Packet layout: length(2) + nonce(1) + timestamp(4) + ciphertext + pubkey_id(4) + signature(512)
        # Ciphertext starts at offset 7, ends 516 bytes before the end
        return pkt[7:-516]

    c1 = extract_ct(pkt1)
    c2 = extract_ct(pkt2)

    # XOR the two ciphertexts gives P1 ⊕ P2
    xor_c = bytes(a ^ b for a, b in zip(c1, c2))
    # Knowing P1, recover P2:
    recovered_P2 = bytes(a ^ b for a, b in zip(xor_c, P1))
    print("[POC] Recovered P2:", recovered_P2)

if __name__ == "__main__":
    duplicate_nonce_poc()
