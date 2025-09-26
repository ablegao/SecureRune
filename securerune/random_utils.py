"""
Random number generation utilities.
"""

import os
import secrets
import random
from typing import List


class RandomUtils:
    """Random number generation utilities."""
    
    @staticmethod
    def secure_random_bytes(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Secure random bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def secure_random_int(min_value: int = 0, max_value: int = 2**31 - 1) -> int:
        """
        Generate cryptographically secure random integer.
        
        Args:
            min_value: Minimum value (inclusive)
            max_value: Maximum value (inclusive)
            
        Returns:
            Secure random integer
        """
        return secrets.randbelow(max_value - min_value + 1) + min_value
    
    @staticmethod
    def secure_random_hex(length: int) -> str:
        """
        Generate cryptographically secure random hex string.
        
        Args:
            length: Number of hex characters
            
        Returns:
            Secure random hex string
        """
        return secrets.token_hex(length // 2)
    
    @staticmethod
    def secure_random_urlsafe(length: int) -> str:
        """
        Generate cryptographically secure URL-safe random string.
        
        Args:
            length: Approximate number of characters (actual may vary due to base64 encoding)
            
        Returns:
            Secure random URL-safe string
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def os_urandom(length: int) -> bytes:
        """
        Generate random bytes using os.urandom().
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes from OS entropy source
        """
        return os.urandom(length)
    
    @staticmethod
    def generate_password(length: int = 16, include_symbols: bool = True) -> str:
        """
        Generate secure random password.
        
        Args:
            length: Password length
            include_symbols: Whether to include special symbols
            
        Returns:
            Secure random password
        """
        import string
        
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """
        Generate cryptographic salt.
        
        Args:
            length: Salt length in bytes
            
        Returns:
            Random salt bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_iv(length: int = 16) -> bytes:
        """
        Generate initialization vector (IV).
        
        Args:
            length: IV length in bytes
            
        Returns:
            Random IV bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """
        Generate cryptographic nonce.
        
        Args:
            length: Nonce length in bytes
            
        Returns:
            Random nonce bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_key(length: int = 32) -> bytes:
        """
        Generate cryptographic key.
        
        Args:
            length: Key length in bytes
            
        Returns:
            Random key bytes
        """
        return secrets.token_bytes(length)
    
    @staticmethod
    def secure_choice(sequence: List) -> any:
        """
        Securely choose random element from sequence.
        
        Args:
            sequence: List or sequence to choose from
            
        Returns:
            Randomly chosen element
        """
        return secrets.choice(sequence)
    
    @staticmethod
    def test_randomness(data: bytes) -> dict:
        """
        Basic randomness tests on data.
        
        Args:
            data: Data to test
            
        Returns:
            Dictionary with test results
        """
        if len(data) == 0:
            return {'error': 'No data provided'}
        
        # Basic entropy estimation
        byte_counts = [0] * 256
        for byte_val in data:
            byte_counts[byte_val] += 1
        
        # Calculate basic entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        # Count unique bytes
        unique_bytes = sum(1 for count in byte_counts if count > 0)
        
        return {
            'length': data_len,
            'unique_bytes': unique_bytes,
            'estimated_entropy': entropy,
            'max_entropy': 8.0,  # Maximum entropy for bytes
            'entropy_ratio': entropy / 8.0,
        }