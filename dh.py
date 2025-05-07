from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os

# Function to derive a key using SHA256
def derive_key(shared_secret):
    # Derive key using SHA256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()

# Generate an EC key pair
def generate_key_pair():
    # Using P-256 curve (NIST) for ECC
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key

# Compute a shared secret
def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Key rotation mechanism (generating a new key pair)
def rotate_key():
    return generate_key_pair()

# Print a key in hex format
def print_key(key, label):
    print(f"{label}: {key.hex()}")

def main():
    # Generate key pairs for two parties (Alice and Bob)
    alice_private_key = generate_key_pair()
    bob_private_key = generate_key_pair()

    # Extract public keys
    alice_public_key = alice_private_key.public_key()
    bob_public_key = bob_private_key.public_key()

    # Compute shared secrets
    alice_shared_secret = compute_shared_secret(alice_private_key, bob_public_key)
    bob_shared_secret = compute_shared_secret(bob_private_key, alice_public_key)

    # Derive keys using SHA256
    alice_derived_key = derive_key(alice_shared_secret)
    bob_derived_key = derive_key(bob_shared_secret)

    # Print the derived keys
    print_key(alice_derived_key, "Alice's Derived Key")
    print_key(bob_derived_key, "Bob's Derived Key")

    # Verify that both parties derived the same key
    if alice_derived_key == bob_derived_key:
        print("Key agreement successful. The keys match!")
    else:
        print("Key agreement failed. The keys do not match!")

    # Rotate keys
    alice_private_key = rotate_key()
    bob_private_key = rotate_key()

    # Cleanup - In Python, we rely on garbage collection
    # No explicit free like in C++

if __name__ == "__main__":
    main()
