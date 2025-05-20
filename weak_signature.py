# weak_signature_poc.py

from murmurat import *
import socket, time

UDP_IP = "127.0.0.1"
UDP_PORT = 1400

def weak_signature_poc():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # --- 1) DH key exchange ---
    client_priv, client_pub = dh_keygen()
    sock.sendto(client_pub.to_bytes(256, "big"), (UDP_IP, UDP_PORT))
    server_pub = int.from_bytes(sock.recv(4096), "big")
    ksession = ksession_from_secret(dh_shared_secret(server_pub, client_priv))

    # --- 2) HELLO (éénmalig) ---
    pubkey_id = os.urandom(4)
    rsa_key = rsa_keygen()
    sock.sendto(build_hello(pubkey_id, rsa_key), (UDP_IP, UDP_PORT))
    srv_hello = sock.recv(1024)
    server_pubkey_id, server_pubkey = parse_hello(srv_hello)

    # --- 3) Bouw een geldig DATA-pakket en verstuur ---
    P = b"Dit is een veilig bericht"
    original_pkt = build_data_packet(P, ksession, rsa_key, pubkey_id)
    sock.sendto(original_pkt, (UDP_IP, UDP_PORT))
    print("[POC] Origineel pakket verstuurd.")

    time.sleep(0.5)

    # --- 4) Tamper metadata (nonce & timestamp) ---
    tampered = bytearray(original_pkt)
    # Zet nonce op 0xFF (positie 2)
    tampered[2] = 0xFF
    # Zet timestamp op huidige tijd (positie 3–6)
    new_ts = int(time.time()).to_bytes(4, "big")
    tampered[3:7] = new_ts
    tampered = bytes(tampered)

    # --- 5) Verstuur het gemanipuleerde pakket ---
    sock.sendto(tampered, (UDP_IP, UDP_PORT))
    print("[POC] Pakket ge-tamperd en opnieuw verstuurd (nonce & timestamp gewijzigd).")

if __name__ == "__main__":
    weak_signature_poc()
