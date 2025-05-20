# no_sequence_poc.py

import socket, os, time
from murmurat import *

UDP_IP   = "127.0.0.1"
UDP_PORT = 1400

def no_sequence_numbers_poc():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # --- 1) DH Exchange ---
    client_priv, client_pub = dh_keygen()
    sock.sendto(client_pub.to_bytes(256, "big"), (UDP_IP, UDP_PORT))
    server_pub = int.from_bytes(sock.recv(4096), "big")
    ksession = ksession_from_secret(dh_shared_secret(server_pub, client_priv))

    # --- 2) HELLO ---
    pubkey_id = os.urandom(4)
    rsa_key    = rsa_keygen()
    sock.sendto(build_hello(pubkey_id, rsa_key), (UDP_IP, UDP_PORT))
    srv_hello = sock.recv(1024)
    _, server_pubkey = parse_hello(srv_hello)

    # --- 3) Bouw twee berichten ---
    P1 = b"Bericht A"
    P2 = b"Bericht B"
    pkt1 = build_data_packet(P1, ksession, rsa_key, pubkey_id)
    pkt2 = build_data_packet(P2, ksession, rsa_key, pubkey_id)

    # --- 4) Out‐of‐order sturen: eerst P2, dan P1 ---
    sock.sendto(pkt2, (UDP_IP, UDP_PORT))
    print("[POC] Verzonden out-of-order: Bericht B")
    time.sleep(0.2)

    sock.sendto(pkt1, (UDP_IP, UDP_PORT))
    print("[POC] Verzonden out-of-order: Bericht A")
    time.sleep(0.2)

    # --- 5) Duplicate sturen: weer P1 ---
    sock.sendto(pkt1, (UDP_IP, UDP_PORT))
    print("[POC] Verzonden duplicate: Bericht A (nogmaals)")

if __name__ == "__main__":
    no_sequence_numbers_poc()
