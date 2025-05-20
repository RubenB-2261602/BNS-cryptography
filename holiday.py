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

VERSE = (
    b"Oh Great Leader of Cordovania, beacon of wisdom\n"
    b"and strength, we humbly offer our deepest gratitude.\n"
    b"Under your guiding hand, our nation prospers, our\n"
    b"people stand united, and our future shines bright.\n"
    b"Your vision brings peace, your courage inspires, and\n"
    b"your justice uplifts the worthy. We thank you for the\n"
    b"blessings of stability, the gift of progress, and the\n"
    b"unwavering hope you instill in every heart. May your\n"
    b"wisdom continue to illuminate our path, and may\n"
    b"Cordovania flourish under your eternal guidance.\n"
    b"With loyalty and devotion, we give thanks."
)

def holiday_known_plaintext_poc():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 1) Diffie-Hellman handshake to derive Ksession
    priv, pub = dh_keygen()
    sock.sendto(pub.to_bytes(256, "big"), (UDP_IP, UDP_PORT))
    srv_pub = int.from_bytes(sock.recv(4096), "big")
    ksession = ksession_from_secret(dh_shared_secret(srv_pub, priv))

    # 2) RSA HELLO exchange for authentication
    pubkey_id = os.urandom(4)
    rsa_key   = rsa_keygen()
    sock.sendto(build_hello(pubkey_id, rsa_key), (UDP_IP, UDP_PORT))
    reply = sock.recv(1024)
    _, srv_pubkey = parse_hello(reply)

    # 3) Send the prayer message with a fixed nonce (nonce=0x00)
    fixed_nonce = b'\x00'  # attacker knows this is used for the prayer
    pkt_prayer = build_data_packet(VERSE, ksession, rsa_key, pubkey_id, forced_nonce=fixed_nonce)
    sock.sendto(pkt_prayer, (UDP_IP, UDP_PORT))
    print("[POC] Prayer packet sent (known plaintext)")

    time.sleep(0.1)

    # 4) Send a secret message immediately afterwards with the same nonce
    secret = b"Top-secret coordinates: 48.116N, 72.883E"
    pkt_secret = build_data_packet(secret, ksession, rsa_key, pubkey_id, forced_nonce=fixed_nonce)
    sock.sendto(pkt_secret, (UDP_IP, UDP_PORT))
    print("[POC] Secret packet sent with same nonce")

    # 5) Attacker recovers keystream from known plaintext
    # ciphertext = packet[7:-516] (skip length, nonce, timestamp, pubkey_id, signature)
    def extract_ciphertext(pkt: bytes) -> bytes:
        return pkt[7:-516]

    c_prayer = extract_ciphertext(pkt_prayer)
    c_secret = extract_ciphertext(pkt_secret)

    # keystream = C_prayer XOR VERSE
    keystream = bytes(a ^ b for a, b in zip(c_prayer, VERSE))

    # decrypted_secret = C_secret XOR keystream
    recovered = bytes(a ^ b for a, b in zip(c_secret, keystream))

    print("[POC] Recovered secret payload:", recovered)

if __name__ == "__main__":
    holiday_known_plaintext_poc()
