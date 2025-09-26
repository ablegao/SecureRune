"""
Hashing algorithms implementation.
"""

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class HashingAlgorithms:
    """Hashing algorithms collection."""
    
    @staticmethod
    def md5(data: bytes) -> bytes:
        """
        Compute MD5 hash.
        
        ⚠️ WARNING: MD5 is cryptographically broken and should not be used 
        for security purposes. This implementation is for legacy compatibility 
        and educational purposes only.
        
        Args:
            data: Data to hash
            
        Returns:
            MD5 hash digest
        """
        return hashlib.md5(data).digest()
    
    @staticmethod
    def sha1(data: bytes) -> bytes:
        """
        Compute SHA-1 hash.
        
        ⚠️ WARNING: SHA-1 is deprecated and should not be used for security 
        purposes due to collision vulnerabilities. Use SHA-256 or higher.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-1 hash digest
        """
        return hashlib.sha1(data).digest()
    
    @staticmethod
    def sha256(data: bytes) -> bytes:
        """
        Compute SHA-256 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-256 hash digest
        """
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def sha384(data: bytes) -> bytes:
        """
        Compute SHA-384 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-384 hash digest
        """
        return hashlib.sha384(data).digest()
    
    @staticmethod
    def sha512(data: bytes) -> bytes:
        """
        Compute SHA-512 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-512 hash digest
        """
        return hashlib.sha512(data).digest()
    
    @staticmethod
    def sha3_256(data: bytes) -> bytes:
        """
        Compute SHA3-256 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-256 hash digest
        """
        return hashlib.sha3_256(data).digest()
    
    @staticmethod
    def sha3_384(data: bytes) -> bytes:
        """
        Compute SHA3-384 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-384 hash digest
        """
        return hashlib.sha3_384(data).digest()
    
    @staticmethod
    def sha3_512(data: bytes) -> bytes:
        """
        Compute SHA3-512 hash.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA3-512 hash digest
        """
        return hashlib.sha3_512(data).digest()
    
    @staticmethod
    def blake2b(data: bytes, digest_size: int = 64, key: bytes = None) -> bytes:
        """
        Compute BLAKE2b hash.
        
        Args:
            data: Data to hash
            digest_size: Output size in bytes (1-64)
            key: Optional key for keyed hashing
            
        Returns:
            BLAKE2b hash digest
        """
        if key is None:
            return hashlib.blake2b(data, digest_size=digest_size).digest()
        else:
            return hashlib.blake2b(data, digest_size=digest_size, key=key).digest()
    
    @staticmethod
    def blake2s(data: bytes, digest_size: int = 32, key: bytes = None) -> bytes:
        """
        Compute BLAKE2s hash.
        
        Args:
            data: Data to hash
            digest_size: Output size in bytes (1-32)
            key: Optional key for keyed hashing
            
        Returns:
            BLAKE2s hash digest
        """
        if key is None:
            return hashlib.blake2s(data, digest_size=digest_size).digest()
        else:
            return hashlib.blake2s(data, digest_size=digest_size, key=key).digest()
    
    @staticmethod
    def shake_128(data: bytes, length: int) -> bytes:
        """
        Compute SHAKE128 hash with variable output length.
        
        Args:
            data: Data to hash
            length: Output length in bytes
            
        Returns:
            SHAKE128 hash digest
        """
        return hashlib.shake_128(data).digest(length)
    
    @staticmethod
    def shake_256(data: bytes, length: int) -> bytes:
        """
        Compute SHAKE256 hash with variable output length.
        
        Args:
            data: Data to hash
            length: Output length in bytes
            
        Returns:
            SHAKE256 hash digest
        """
        return hashlib.shake_256(data).digest(length)
    
    @staticmethod
    def get_hex(digest: bytes) -> str:
        """
        Convert hash digest to hexadecimal string.
        
        Args:
            digest: Hash digest bytes
            
        Returns:
            Hexadecimal string representation
        """
        return digest.hex()
    
    @staticmethod
    def verify_hash(data: bytes, expected_hash: bytes, algorithm: str) -> bool:
        """
        Verify data against expected hash.
        
        Args:
            data: Original data
            expected_hash: Expected hash digest
            algorithm: Hash algorithm name
            
        Returns:
            True if hash matches, False otherwise
        """
        algorithm_map = {
            'md5': HashingAlgorithms.md5,
            'sha1': HashingAlgorithms.sha1,
            'sha256': HashingAlgorithms.sha256,
            'sha384': HashingAlgorithms.sha384,
            'sha512': HashingAlgorithms.sha512,
            'sha3-256': HashingAlgorithms.sha3_256,
            'sha3-384': HashingAlgorithms.sha3_384,
            'sha3-512': HashingAlgorithms.sha3_512,
        }
        
        if algorithm not in algorithm_map:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        computed_hash = algorithm_map[algorithm](data)
        return computed_hash == expected_hash