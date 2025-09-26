# SecureRune

A compact utility aiming to cover and demonstrate every security and encryption algorithm.

## Features

SecureRune provides implementations and command-line interfaces for:

### 🔐 Symmetric Encryption Algorithms
- **AES (Advanced Encryption Standard)** - CBC, GCM, and CTR modes
- **DES (Data Encryption Standard)** - Legacy support
- **3DES (Triple DES)** - Legacy support with improved security
- **ChaCha20** - Modern stream cipher

### 🔑 Asymmetric (Public-Key) Encryption
- **RSA** - Key generation, encryption/decryption, digital signatures
- **DSA (Digital Signature Algorithm)** - Digital signatures
- **ECC (Elliptic Curve Cryptography)** - ECDSA signatures

### #️⃣ Cryptographic Hash Functions
- **MD5** - Legacy hash (not recommended for security)
- **SHA-1** - Legacy hash (not recommended for security)
- **SHA-2 family** - SHA-256, SHA-384, SHA-512
- **SHA-3 family** - SHA3-256, SHA3-384, SHA3-512
- **BLAKE2** - BLAKE2b and BLAKE2s
- **SHAKE** - SHAKE128 and SHAKE256 (variable output length)

### 🗝️ Key Derivation Functions (KDF)
- **PBKDF2** - Password-Based Key Derivation Function 2
- **scrypt** - Memory-hard key derivation function
- **Argon2** - Modern password hashing (Argon2i, Argon2d, Argon2id)
- **bcrypt** - Adaptive password hashing

### 🔐 Message Authentication Codes (MAC)
- **HMAC** - Hash-based MAC with various hash functions
- **CMAC-AES** - Cipher-based MAC using AES

### 🎲 Cryptographically Secure Random Generation
- Secure random bytes, integers, hex strings
- Password generation with customizable complexity
- Cryptographic salt, IV, and nonce generation
- Basic randomness quality assessment

## Installation

```bash
pip install -e .
```

## Command-Line Usage

### Hash Computation
```bash
# Compute SHA-256 hash of text
securerune hash compute -t "Hello World" -a sha256

# Compute hash of file
securerune hash compute -i myfile.txt -a sha512

# Available algorithms: md5, sha1, sha256, sha384, sha512, sha3-256, blake2b, etc.
```

### Symmetric Encryption
```bash
# Encrypt text with AES-256-CBC (generates random key)
securerune symmetric encrypt -t "Secret message" -a aes

# Encrypt with specific key
securerune symmetric encrypt -t "Secret message" -a aes -k "your-hex-key-here"

# Decrypt
securerune symmetric decrypt -c "ciphertext-hex" -a aes -k "key-hex" --iv "iv-hex"

# Available algorithms: aes, des, 3des, chacha20
# Available AES modes: CBC, GCM, CTR
```

### Asymmetric Cryptography
```bash
# Generate RSA key pair
securerune asymmetric keygen -a rsa --key-size 2048

# Generate ECC key pair
securerune asymmetric keygen -a ecc --curve SECP256R1
```

### Key Derivation
```bash
# Derive key from password using PBKDF2
securerune kdf derive -p "mypassword" -a pbkdf2 --iterations 100000

# Use scrypt
securerune kdf derive -p "mypassword" -a scrypt
```

### Message Authentication
```bash
# Compute HMAC-SHA256
securerune mac compute-mac -t "message" -k "secret-key-hex" -a hmac-sha256
```

### Random Generation
```bash
# Generate random bytes
securerune random bytes -l 32

# Generate secure password
securerune random password -l 16

# Generate password without symbols
securerune random password -l 16 --no-symbols
```

## Python API Usage

### Symmetric Encryption Example
```python
from securerune.symmetric import SymmetricCrypto
from securerune.random_utils import RandomUtils

# Generate a key
key = RandomUtils.generate_key(32)  # 256-bit key

# Encrypt data
plaintext = b"Hello, World!"
ciphertext, iv = SymmetricCrypto.aes_encrypt(plaintext, key, 'CBC')

# Decrypt data
decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, iv, 'CBC')
assert decrypted == plaintext
```

### Hashing Example
```python
from securerune.hashing import HashingAlgorithms

# Compute various hashes
data = b"Hello, World!"

sha256_hash = HashingAlgorithms.sha256(data)
print(f"SHA-256: {sha256_hash.hex()}")

blake2b_hash = HashingAlgorithms.blake2b(data, digest_size=32)
print(f"BLAKE2b: {blake2b_hash.hex()}")
```

### Key Derivation Example
```python
from securerune.kdf import KeyDerivation

# Derive key from password
password = "my-secure-password"
key, salt = KeyDerivation.pbkdf2(password.encode(), iterations=100000)

# Hash password with Argon2
hashed = KeyDerivation.argon2_hash(password)
is_valid = KeyDerivation.argon2_verify(password, hashed)
```

### Random Generation Example
```python
from securerune.random_utils import RandomUtils

# Generate cryptographically secure random data
random_key = RandomUtils.generate_key(32)
random_password = RandomUtils.generate_password(16, include_symbols=True)
random_salt = RandomUtils.generate_salt(16)

# Test randomness quality
quality = RandomUtils.test_randomness(random_key)
print(f"Entropy ratio: {quality['entropy_ratio']:.2f}")
```

## Testing

Run the test suite:
```bash
pytest tests/ -v
```

## Security Notes

- This library is intended for educational and demonstration purposes
- For production use, always use well-established cryptographic libraries
- Some algorithms (MD5, SHA-1, DES) are included for legacy compatibility but are not cryptographically secure
- Always use cryptographically secure random number generation for keys, IVs, and salts
- Properly validate and sanitize all inputs
- Follow current cryptographic best practices and guidelines

## License

BSD 3-Clause License - see LICENSE file for details.
