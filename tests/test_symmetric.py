"""
Test suite for SecureRune symmetric encryption algorithms.
"""

import pytest
from securerune.symmetric import SymmetricCrypto
from securerune.random_utils import RandomUtils


class TestSymmetricCrypto:
    """Test symmetric encryption algorithms."""
    
    def test_aes_cbc_encrypt_decrypt(self):
        """Test AES-CBC encryption and decryption."""
        plaintext = b"Hello, World! This is a test message for AES encryption."
        key = RandomUtils.generate_key(32)  # 256-bit key
        
        ciphertext, iv = SymmetricCrypto.aes_encrypt(plaintext, key, 'CBC')
        decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, iv, 'CBC')
        
        assert decrypted == plaintext
        assert len(iv) == 16  # AES block size
        assert ciphertext != plaintext
    
    def test_aes_gcm_encrypt_decrypt(self):
        """Test AES-GCM encryption and decryption."""
        plaintext = b"Hello, World! This is a test message for AES-GCM."
        key = RandomUtils.generate_key(32)  # 256-bit key
        
        ciphertext_with_tag, nonce = SymmetricCrypto.aes_encrypt(plaintext, key, 'GCM')
        decrypted = SymmetricCrypto.aes_decrypt(ciphertext_with_tag, key, nonce, 'GCM')
        
        assert decrypted == plaintext
        assert len(nonce) == 12  # GCM nonce size
        assert len(ciphertext_with_tag) == len(plaintext) + 16  # + tag size
    
    def test_aes_ctr_encrypt_decrypt(self):
        """Test AES-CTR encryption and decryption."""
        plaintext = b"Hello, World! This is a test message for AES-CTR."
        key = RandomUtils.generate_key(32)  # 256-bit key
        
        ciphertext, nonce = SymmetricCrypto.aes_encrypt(plaintext, key, 'CTR')
        decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, nonce, 'CTR')
        
        assert decrypted == plaintext
        assert len(nonce) == 12  # CTR nonce size
        assert len(ciphertext) == len(plaintext)
    
    def test_des_encrypt_decrypt(self):
        """Test DES encryption and decryption."""
        plaintext = b"Hello, World! Test DES."
        key = RandomUtils.generate_key(8)  # 64-bit key
        
        ciphertext, iv = SymmetricCrypto.des_encrypt(plaintext, key)
        decrypted = SymmetricCrypto.des_decrypt(ciphertext, key, iv)
        
        assert decrypted == plaintext
        assert len(iv) == 8  # DES block size
    
    def test_triple_des_encrypt_decrypt(self):
        """Test 3DES encryption and decryption."""
        plaintext = b"Hello, World! Test 3DES."
        key = RandomUtils.generate_key(24)  # 192-bit key
        
        ciphertext, iv = SymmetricCrypto.triple_des_encrypt(plaintext, key)
        decrypted = SymmetricCrypto.triple_des_decrypt(ciphertext, key, iv)
        
        assert decrypted == plaintext
        assert len(iv) == 8  # DES block size
    
    def test_chacha20_encrypt_decrypt(self):
        """Test ChaCha20 encryption and decryption."""
        plaintext = b"Hello, World! This is a test message for ChaCha20."
        key = RandomUtils.generate_key(32)  # 256-bit key
        
        ciphertext, nonce = SymmetricCrypto.chacha20_encrypt(plaintext, key)
        decrypted = SymmetricCrypto.chacha20_decrypt(ciphertext, key, nonce)
        
        assert decrypted == plaintext
        assert len(nonce) == 12  # ChaCha20 nonce size
        assert len(ciphertext) == len(plaintext)
    
    def test_aes_key_sizes(self):
        """Test AES with different key sizes."""
        plaintext = b"Test message"
        
        for key_size in [16, 24, 32]:  # 128, 192, 256 bits
            key = RandomUtils.generate_key(key_size)
            ciphertext, iv = SymmetricCrypto.aes_encrypt(plaintext, key, 'CBC')
            decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, iv, 'CBC')
            assert decrypted == plaintext
    
    def test_empty_plaintext(self):
        """Test encryption/decryption of empty data."""
        plaintext = b""
        key = RandomUtils.generate_key(32)
        
        # Test AES-GCM with empty plaintext
        ciphertext, nonce = SymmetricCrypto.aes_encrypt(plaintext, key, 'GCM')
        decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, nonce, 'GCM')
        assert decrypted == plaintext
    
    def test_large_data(self):
        """Test encryption/decryption of large data."""
        plaintext = b"A" * 10000  # 10KB of data
        key = RandomUtils.generate_key(32)
        
        ciphertext, iv = SymmetricCrypto.aes_encrypt(plaintext, key, 'CBC')
        decrypted = SymmetricCrypto.aes_decrypt(ciphertext, key, iv, 'CBC')
        
        assert decrypted == plaintext