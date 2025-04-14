import asyncio
import signal
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

YOUR_PROMPT = "\033[32m" + ">>> " + "\033[0m"
THEIR_PROMPT = "\033[31m" + "\n<<< " + "\033[0m"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

SESSION_KEY_SALT = b"some fixed salt"


def prompt():
    """Show prompt for message"""
    print(YOUR_PROMPT, end="", flush=True)


def show(msg):
    """Print received message

    Args:
        msg (str|bytes): received message in bytes or decoded str.
    """
    if isinstance(msg, bytes):
        msg = msg.decode()
    print(f"{THEIR_PROMPT}{msg}", flush=True)


async def read_message_from_stdin():
    """Read message to be sent from command line"""
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def alice_server(handler):
    loop = asyncio.get_running_loop()
    # loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Alice runs the server
    server = await asyncio.start_server(
        lambda r, w: handler(r, w), SERVER_HOST, SERVER_PORT
    )
    async with server:
        await server.serve_forever()


async def bob_client():
    loop = asyncio.get_running_loop()
    # loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Bob connects to Alice
    return await asyncio.open_connection(SERVER_HOST, SERVER_PORT)


def generate_key_pair_ecds():
    """Generate a new ECDSA private and public key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Using a standard elliptic curve
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_key_pair():
    """Generate a new ECDSA private and public key pair."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),  # Using a standard elliptic curve
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    """Serialize the public key to bytes."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes


def serialize_private_key(private_key):
    """Serialize the private key to bytes (for storage, handle with care!)."""
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_bytes


def deserialize_public_key(public_bytes):
    """Deserialize the public key from bytes."""
    public_key = serialization.load_pem_public_key(public_bytes)
    return public_key


def sign_data(private_key, data):
    """Sign data using the private key."""
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature


def verify_signature(public_key, signature, data):
    """Verify the signature of the data using the public key."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_diffie_hellman_key():
    """Generate a Diffie-Hellman private key."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_dh_public_key(public_key):
    """Serialize the Diffie-Hellman public key to bytes."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return public_bytes


def deserialize_dh_public_key(public_bytes):
    """Deserialize the Diffie-Hellman public key from bytes."""
    public_key = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    return public_key


def derive_shared_secret(private_key, public_key):
    """Derive a shared secret using Diffie-Hellman."""
    shared_secret = private_key.exchange(public_key)
    return shared_secret


def derive_session_key(shared_secret):
    """Derive a session key from the shared secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256 key
        salt=SESSION_KEY_SALT,
        info=b"session key",  # Contextual information
    )
    session_key = hkdf.derive(shared_secret)
    return session_key


def encrypt_message(session_key, plaintext):
    """Encrypt a message using AES-GCM."""
    iv = os.urandom(12)  # 12-byte nonce for GCM
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag


def decrypt_message(session_key, ciphertext_with_tag):
    """Decrypt a message encrypted with AES-GCM."""
    iv = ciphertext_with_tag[:12]
    ciphertext = ciphertext_with_tag[12:-16]
    tag = ciphertext_with_tag[-16:]
    cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
