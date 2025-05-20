# murmurat.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256
from Crypto.Signature import pkcs1_15
import random, os, time

G = 2
P = int("""
21894553314596771561196871363069090541066762948701574567164020109267136679658370486943743975837875551999724125675479713926610011157978943480748521006430553187436563793040135859147314200060834037476721054687020332554521482953307933279332569246540222644899052019734402578132147790321819673041697183485577751556671866087760112758069112215318623491422973743109959408989119853925061221424914969592119964092790966627078188061704838361168099808241706347071334601734718683912103883792713733499106500967971247312946335678666117988734426818897467285005428051841972129518278136019917483333422790215788404956414952116894714913327
""".replace('\n', '').replace(' ', ''))

# Global counter for deterministic nonces
_nonce_counter = 0


def dh_keygen():
    priv = random.randint(2, P-2)
    pub = pow(G, priv, P)
    return priv, pub


def dh_shared_secret(other_pub, priv):
    return pow(other_pub, priv, P)


def ksession_from_secret(secret):
    return secret.to_bytes((secret.bit_length()+7)//8, "big")[:16]


def rsa_keygen():
    return RSA.generate(2048)


def build_hello(pubkey_id, rsa_key):
    n_bytes = rsa_key.n.to_bytes(512, "big")
    return pubkey_id + n_bytes


def parse_hello(data):
    pubkey_id = data[:4]
    n = int.from_bytes(data[4:516], "big")
    pubkey = RSA.construct((n, 65537))
    return pubkey_id, pubkey


def encrypt_aes_ctr(plaintext, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(plaintext)


def build_data_packet(plaintext, ksession, rsa_priv, pubkey_id, forced_nonce=None):
    global _nonce_counter
    # Use forced nonce if provided, else deterministic incrementing nonce
    if forced_nonce is not None:
        nonce = forced_nonce
    else:
        nonce_val = _nonce_counter % 256
        nonce = nonce_val.to_bytes(1, "big")
        _nonce_counter += 1

    timestamp = int(time.time()).to_bytes(4, "big")
    ciphertext = encrypt_aes_ctr(plaintext, ksession, nonce)
    length = (1 + 4 + len(ciphertext) + 4 + 512)
    length_bytes = length.to_bytes(2, "big")

    # Sign only the ciphertext
    h = SHA3_256.new(ciphertext)
    signature = pkcs1_15.new(rsa_priv).sign(h)
    if len(signature) < 512:
        signature = signature.ljust(512, b"\x00")
    elif len(signature) > 512:
        signature = signature[:512]

    # Construct packet in correct order
    packet = (
        length_bytes + nonce + timestamp + ciphertext + pubkey_id + signature
    )
    return packet


def parse_data_packet(packet):
    length = int.from_bytes(packet[:2], "big")
    nonce = packet[2:3]
    timestamp = int.from_bytes(packet[3:7], "big")
    sig_start = -512
    pubkeyid_start = sig_start - 4
    ciphertext = packet[7:pubkeyid_start]
    pubkey_id = packet[pubkeyid_start:sig_start]
    signature = packet[sig_start:]
    return {
        "length": length,
        "nonce": nonce,
        "timestamp": timestamp,
        "ciphertext": ciphertext,
        "pubkey_id": pubkey_id,
        "signature": signature
    }
