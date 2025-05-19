from murmurat import *
import socket, os, time

UDP_IP = "127.0.0.1"
UDP_PORT = 1400

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# --- DH Key Exchange ---
client_priv, client_pub = dh_keygen()
client_pub_bytes = client_pub.to_bytes(256, "big")
sock.sendto(client_pub_bytes, (UDP_IP, UDP_PORT))
server_pub_bytes, _ = sock.recvfrom(4096)
server_pub = int.from_bytes(server_pub_bytes, "big")
shared_secret = dh_shared_secret(server_pub, client_priv)
ksession = ksession_from_secret(shared_secret)

# --- HELLO ---
pubkey_id = os.urandom(4)
rsa_key = rsa_keygen()
hello_msg = build_hello(pubkey_id, rsa_key)
sock.sendto(hello_msg, (UDP_IP, UDP_PORT))
server_hello, _ = sock.recvfrom(1024)
server_pubkey_id, server_pubkey = parse_hello(server_hello)

# --- Meerdere DATA berichten in één sessie ---
for i in range(3): 
    data_pkt = build_data_packet(f"Testbericht {i}".encode(), ksession, rsa_key, pubkey_id)
    sock.sendto(data_pkt, (UDP_IP, UDP_PORT))
    print(f"DATA verstuurd: Testbericht {i}")
    time.sleep(0.5)  # Kleine delay voor de leesbaarheid
