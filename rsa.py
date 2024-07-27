import random
from sympy import isprime, mod_inverse

def generate_prime_candidate(length):
    """Generate an odd prime candidate of specified bit length."""
    # Generate a random integer of the specified bit length
    p = random.getrandbits(length)
    # Ensure p is odd and has the correct length by setting the highest and lowest bits
    p |= (1 << length - 1) | 1  
    return p

def generate_prime_number(length):
    """Generate a prime number of specified bit length."""
    p = 4  # Initialize p to a non-prime number
    # Keep generating candidates until a prime number is found
    while not isprime(p):
        p = generate_prime_candidate(length)
    return p

def generate_keypair(bits):
    """Generate RSA public and private keypair."""
    # Generate two distinct prime numbers p and q
    p = generate_prime_number(bits)
    q = generate_prime_number(bits)
    # Compute n, the modulus for the public and private keys
    n = p * q
    # Calculate the totient (φ(n))
    phi = (p - 1) * (q - 1)

    # Choose public exponent e (commonly 65537)
    e = 65537  
    # Calculate the private exponent d, which is the modular inverse of e mod φ(n)
    d = mod_inverse(e, phi)

    # Return the public key (e, n) and private key (d, n)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    """Encrypt the plaintext using the public key."""
    e, n = public_key  # Unpack the public key
    # Compute ciphertext c = m^e mod n
    ciphertext = pow(plaintext, e, n)
    return ciphertext

def decrypt(private_key, ciphertext):
    """Decrypt the ciphertext using the private key."""
    d, n = private_key  # Unpack the private key
    # Compute plaintext m = c^d mod n
    plaintext = pow(ciphertext, d, n)
    return plaintext

# Example usage
if __name__ == "__main__":
    bits = 8  # For simplicity, use a small key size; use 2048 for real applications
    # Generate a public and private keypair
    public_key, private_key = generate_keypair(bits)

    # Display the generated keys
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Example plaintext message (must be less than n)
    message = 42  
    print("Original Message:", message)

    # Encrypt the message using the public key
    encrypted_msg = encrypt(public_key, message)
    print("Encrypted Message:", encrypted_msg)

    # Decrypt the message using the private key
    decrypted_msg = decrypt(private_key, encrypted_msg)
    print("Decrypted Message:", decrypted_msg)