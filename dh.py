import os
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Utility functions
def generate_nonce(length=16):
    """Generate a secure random nonce."""
    return secrets.token_bytes(length)

def hash_function(data):
    """SHA-256 hash function."""
    return hashlib.sha256(data).digest()

def aes_encrypt(key, iv, plaintext):
    """Encrypt plaintext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def aes_decrypt(key, iv, ciphertext, tag):
    """Decrypt ciphertext using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM, iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# DH helper functions
def generate_dh_keypair(prime, generator):
    """Generate a Diffie-Hellman private and public key pair."""
    private_key = secrets.randbelow(prime - 2) + 1
    public_key = pow(generator, private_key, prime)
    return private_key, public_key

def compute_shared_secret(public_key, private_key, prime):
    """Compute the shared secret using the DH formula."""
    return pow(public_key, private_key, prime)

# Authorization Key Generation
class DiffieHellmanAKProtocol:
    def __init__(self, prime, generator):
        self.prime = prime
        self.generator = generator
        self.client_nonce = None
        self.server_nonce = None
        self.shared_secret = None
        self.authorization_key = None

    # Round 1: Client sends nonce, server responds with its nonce, challenge, and public key fingerprints
    def round1_client_nonce(self):
        """Client generates and sends a nonce."""
        self.client_nonce = generate_nonce()
        return self.client_nonce

    def round1_server_response(self, client_nonce):
        """Server generates a response with its nonce, challenge, and public key fingerprints."""
        self.server_nonce = generate_nonce()
        challenge = self.generate_challenge()
        public_key_fingerprints = self.get_public_key_fingerprints()
        return self.server_nonce, challenge, public_key_fingerprints

    # Round 2: Client processes the challenge, retrieves server public key
    def round2_client(self, server_nonce, challenge, server_public_key):
        """Client processes the challenge and sends encrypted data."""
        self.client_nonce = generate_nonce()
        ephemeral_key_material = hash_function(server_nonce + self.client_nonce)
        symmetric_key, iv = ephemeral_key_material[:16], ephemeral_key_material[16:32]
        encrypted_data, tag = aes_encrypt(symmetric_key, iv, self.client_nonce + server_nonce)
        return encrypted_data, tag

    # Round 3: Server chooses DH parameters and computes public value
    def round3_server(self, client_encrypted_data, client_tag, server_private_key):
        """Server computes public DH value and sends it to the client."""
        ephemeral_key_material = hash_function(self.client_nonce + self.server_nonce)
        symmetric_key, iv = ephemeral_key_material[:16], ephemeral_key_material[16:32]
        decrypted_data = aes_decrypt(symmetric_key, iv, client_encrypted_data, client_tag)
        # Verify decrypted data
        server_public_value = pow(self.generator, server_private_key, self.prime)
        return server_public_value

    # Both parties derive the Authorization Key (AK)
    def derive_authorization_key(self, shared_secret):
        """Derive the Authorization Key (AK) from the shared secret."""
        self.authorization_key = hash_function(shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big'))
        return self.authorization_key

    # Helper functions
    def generate_challenge(self):
        """Generate a cryptographic challenge."""
        prime1 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                     "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                     "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                     "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
        prime2 = int("E95E4A5F737059DC60DF5991D45029409E60FC09CEC8B8F5"
                     "6AEB7B2C0B80C6E6E2F3184E5A6D12A77D6A03B5CE8F5E2A"
                     "0E2B9E040CC9E0A13E2A7F22C8EFAE29B77C1F42F2A06F5A"
                     "4B1A4C3F4DE2A5B5F7D1B5E5E7A3F2D5B92A9E2D5F5B7F9", 16)
        return prime1 * prime2

    def get_public_key_fingerprints(self):
        """Retrieve server public key fingerprints."""
        # Replace with real public key fingerprints for production
        return [hash_function(b"PublicKey1"), hash_function(b"PublicKey2")]
