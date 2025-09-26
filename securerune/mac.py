"""
Message Authentication Code (MAC) algorithms implementation.
"""

import hmac
import hashlib
from cryptography.hazmat.primitives import hashes, cmac
from cryptography.hazmat.primitives.ciphers import algorithms


class MACAlgorithms:
    """Message Authentication Code algorithms collection."""
    
    @staticmethod
    def hmac_sha256(key: bytes, message: bytes) -> bytes:
        """
        Compute HMAC-SHA256.
        
        Args:
            key: Secret key
            message: Message to authenticate
            
        Returns:
            HMAC-SHA256 digest
        """
        return hmac.new(key, message, hashlib.sha256).digest()
    
    @staticmethod
    def hmac_sha1(key: bytes, message: bytes) -> bytes:
        """
        Compute HMAC-SHA1.
        
        Args:
            key: Secret key
            message: Message to authenticate
            
        Returns:
            HMAC-SHA1 digest
        """
        return hmac.new(key, message, hashlib.sha1).digest()
    
    @staticmethod
    def hmac_sha512(key: bytes, message: bytes) -> bytes:
        """
        Compute HMAC-SHA512.
        
        Args:
            key: Secret key
            message: Message to authenticate
            
        Returns:
            HMAC-SHA512 digest
        """
        return hmac.new(key, message, hashlib.sha512).digest()
    
    @staticmethod
    def hmac_md5(key: bytes, message: bytes) -> bytes:
        """
        Compute HMAC-MD5.
        
        Args:
            key: Secret key
            message: Message to authenticate
            
        Returns:
            HMAC-MD5 digest
        """
        return hmac.new(key, message, hashlib.md5).digest()
    
    @staticmethod
    def hmac_custom(key: bytes, message: bytes, hash_algorithm: str) -> bytes:
        """
        Compute HMAC with custom hash algorithm.
        
        Args:
            key: Secret key
            message: Message to authenticate
            hash_algorithm: Hash algorithm name ('sha256', 'sha1', 'sha512', 'md5')
            
        Returns:
            HMAC digest
        """
        hash_func = getattr(hashlib, hash_algorithm.lower())
        return hmac.new(key, message, hash_func).digest()
    
    @staticmethod
    def cmac_aes(key: bytes, message: bytes) -> bytes:
        """
        Compute CMAC-AES.
        
        Args:
            key: AES key (16, 24, or 32 bytes)
            message: Message to authenticate
            
        Returns:
            CMAC-AES digest
        """
        c = cmac.CMAC(algorithms.AES(key))
        c.update(message)
        return c.finalize()
    
    @staticmethod
    def verify_hmac(key: bytes, message: bytes, expected_mac: bytes, 
                   hash_algorithm: str = 'sha256') -> bool:
        """
        Verify HMAC authentication code.
        
        Args:
            key: Secret key
            message: Original message
            expected_mac: Expected MAC value
            hash_algorithm: Hash algorithm name
            
        Returns:
            True if MAC is valid, False otherwise
        """
        try:
            computed_mac = MACAlgorithms.hmac_custom(key, message, hash_algorithm)
            return hmac.compare_digest(computed_mac, expected_mac)
        except Exception:
            return False
    
    @staticmethod
    def verify_cmac_aes(key: bytes, message: bytes, expected_mac: bytes) -> bool:
        """
        Verify CMAC-AES authentication code.
        
        Args:
            key: AES key
            message: Original message
            expected_mac: Expected MAC value
            
        Returns:
            True if MAC is valid, False otherwise
        """
        try:
            c = cmac.CMAC(algorithms.AES(key))
            c.update(message)
            c.verify(expected_mac)
            return True
        except Exception:
            return False
    
    @staticmethod
    def get_mac_length(algorithm: str) -> int:
        """
        Get MAC length for specified algorithm.
        
        Args:
            algorithm: MAC algorithm name
            
        Returns:
            MAC length in bytes
        """
        mac_lengths = {
            'hmac-sha256': 32,
            'hmac-sha1': 20,
            'hmac-sha512': 64,
            'hmac-md5': 16,
            'cmac-aes': 16,
        }
        
        return mac_lengths.get(algorithm.lower(), 0)