"""
Test suite for SecureRune hashing algorithms.
"""

import pytest
from securerune.hashing import HashingAlgorithms


class TestHashingAlgorithms:
    """Test hashing algorithms."""
    
    def test_md5_hash(self):
        """Test MD5 hash computation."""
        data = b"Hello, World!"
        expected = bytes.fromhex("65a8e27d8879283831b664bd8b7f0ad4")
        result = HashingAlgorithms.md5(data)
        assert result == expected
    
    def test_sha1_hash(self):
        """Test SHA-1 hash computation."""
        data = b"Hello, World!"
        expected = bytes.fromhex("0a0a9f2a6772942557ab5355d76af442f8f65e01")
        result = HashingAlgorithms.sha1(data)
        assert result == expected
    
    def test_sha256_hash(self):
        """Test SHA-256 hash computation."""
        data = b"Hello, World!"
        expected = bytes.fromhex("dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f")
        result = HashingAlgorithms.sha256(data)
        assert result == expected
    
    def test_sha512_hash(self):
        """Test SHA-512 hash computation."""
        data = b"Hello, World!"
        result = HashingAlgorithms.sha512(data)
        assert len(result) == 64  # 512 bits = 64 bytes
        assert isinstance(result, bytes)
    
    def test_blake2b_hash(self):
        """Test BLAKE2b hash computation."""
        data = b"Hello, World!"
        
        # Default size (64 bytes)
        result = HashingAlgorithms.blake2b(data)
        assert len(result) == 64
        
        # Custom size
        result_32 = HashingAlgorithms.blake2b(data, digest_size=32)
        assert len(result_32) == 32
        
        # With key
        key = b"secret"
        result_keyed = HashingAlgorithms.blake2b(data, key=key)
        assert len(result_keyed) == 64
        assert result_keyed != result  # Different with key
    
    def test_blake2s_hash(self):
        """Test BLAKE2s hash computation."""
        data = b"Hello, World!"
        
        # Default size (32 bytes)
        result = HashingAlgorithms.blake2s(data)
        assert len(result) == 32
        
        # Custom size
        result_16 = HashingAlgorithms.blake2s(data, digest_size=16)
        assert len(result_16) == 16
    
    def test_shake128_hash(self):
        """Test SHAKE128 hash computation."""
        data = b"Hello, World!"
        
        result_16 = HashingAlgorithms.shake_128(data, 16)
        assert len(result_16) == 16
        
        result_32 = HashingAlgorithms.shake_128(data, 32)
        assert len(result_32) == 32
        
        # Different inputs should produce different outputs
        different_data = b"Different data"
        different_result = HashingAlgorithms.shake_128(different_data, 16)
        assert result_16 != different_result
    
    def test_shake256_hash(self):
        """Test SHAKE256 hash computation."""
        data = b"Hello, World!"
        
        result_16 = HashingAlgorithms.shake_256(data, 16)
        assert len(result_16) == 16
        
        result_64 = HashingAlgorithms.shake_256(data, 64)
        assert len(result_64) == 64
    
    def test_hex_conversion(self):
        """Test hex conversion utility."""
        data = b"Hello, World!"
        hash_result = HashingAlgorithms.sha256(data)
        hex_result = HashingAlgorithms.get_hex(hash_result)
        
        assert isinstance(hex_result, str)
        assert len(hex_result) == 64  # 32 bytes = 64 hex chars
        assert hex_result == hash_result.hex()
    
    def test_hash_verification(self):
        """Test hash verification."""
        data = b"Hello, World!"
        
        # Test correct hash
        correct_hash = HashingAlgorithms.sha256(data)
        assert HashingAlgorithms.verify_hash(data, correct_hash, 'sha256')
        
        # Test incorrect hash
        incorrect_hash = b'\x00' * 32
        assert not HashingAlgorithms.verify_hash(data, incorrect_hash, 'sha256')
        
        # Test with different algorithms
        md5_hash = HashingAlgorithms.md5(data)
        assert HashingAlgorithms.verify_hash(data, md5_hash, 'md5')
    
    def test_empty_data(self):
        """Test hashing empty data."""
        data = b""
        
        result = HashingAlgorithms.sha256(data)
        expected = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result == expected
    
    def test_large_data(self):
        """Test hashing large data."""
        data = b"A" * 1000000  # 1MB of data
        
        result = HashingAlgorithms.sha256(data)
        assert len(result) == 32
        assert isinstance(result, bytes)
    
    def test_consistency(self):
        """Test that same input produces same output."""
        data = b"Consistent test data"
        
        result1 = HashingAlgorithms.sha256(data)
        result2 = HashingAlgorithms.sha256(data)
        
        assert result1 == result2