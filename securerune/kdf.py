"""
Key derivation functions and password hashing algorithms.
"""

import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from argon2 import PasswordHasher
from argon2.low_level import hash_secret, verify_secret, Type


class KeyDerivation:
    """Key derivation functions and password hashing collection."""
    
    @staticmethod
    def pbkdf2(password: bytes, salt: bytes = None, iterations: int = 100000, 
               key_length: int = 32, hash_algorithm: str = 'SHA256') -> Tuple[bytes, bytes]:
        """
        Derive key using PBKDF2 (Password-Based Key Derivation Function 2).
        
        Args:
            password: Password to derive key from
            salt: Salt bytes (generated if None)
            iterations: Number of iterations
            key_length: Desired key length in bytes
            hash_algorithm: Hash algorithm ('SHA256', 'SHA1', 'SHA512')
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        hash_alg = getattr(hashes, hash_algorithm)()
        kdf = PBKDF2HMAC(
            algorithm=hash_alg,
            length=key_length,
            salt=salt,
            iterations=iterations
        )
        
        derived_key = kdf.derive(password)
        return derived_key, salt
    
    @staticmethod
    def scrypt_derive(password: bytes, salt: bytes = None, n: int = 2**14, 
                     r: int = 8, p: int = 1, key_length: int = 32) -> Tuple[bytes, bytes]:
        """
        Derive key using scrypt.
        
        Args:
            password: Password to derive key from
            salt: Salt bytes (generated if None)
            n: CPU/memory cost parameter
            r: Block size parameter
            p: Parallelization parameter
            key_length: Desired key length in bytes
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = Scrypt(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            n=n,
            r=r,
            p=p
        )
        
        derived_key = kdf.derive(password)
        return derived_key, salt
    
    @staticmethod
    def argon2_hash(password: str, variant: str = 'argon2id', 
                   time_cost: int = 2, memory_cost: int = 2**16, 
                   parallelism: int = 1, hash_len: int = 32, salt_len: int = 16) -> str:
        """
        Hash password using Argon2.
        
        Args:
            password: Password to hash
            variant: Argon2 variant ('argon2id', 'argon2i', 'argon2d')
            time_cost: Time cost parameter
            memory_cost: Memory cost in KiB
            parallelism: Parallelism parameter
            hash_len: Hash length in bytes
            salt_len: Salt length in bytes
            
        Returns:
            Argon2 hash string
        """
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len
        )
        
        return ph.hash(password)
    
    @staticmethod
    def argon2_verify(password: str, hash_string: str) -> bool:
        """
        Verify password against Argon2 hash.
        
        Args:
            password: Password to verify
            hash_string: Argon2 hash string
            
        Returns:
            True if password matches, False otherwise
        """
        ph = PasswordHasher()
        try:
            ph.verify(hash_string, password)
            return True
        except Exception:
            return False
    
    @staticmethod
    def argon2_raw(password: bytes, salt: bytes, variant: str = 'argon2id',
                   time_cost: int = 2, memory_cost: int = 2**16, 
                   parallelism: int = 1, hash_len: int = 32) -> bytes:
        """
        Raw Argon2 hash without encoding.
        
        Args:
            password: Password bytes
            salt: Salt bytes
            variant: Argon2 variant ('argon2id', 'argon2i', 'argon2d')
            time_cost: Time cost parameter
            memory_cost: Memory cost in KiB
            parallelism: Parallelism parameter
            hash_len: Hash length in bytes
            
        Returns:
            Raw hash bytes
        """
        type_map = {
            'argon2d': Type.D,
            'argon2i': Type.I,
            'argon2id': Type.ID
        }
        
        return hash_secret(
            password,
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=type_map[variant]
        )
    
    @staticmethod
    def bcrypt_hash(password: str, rounds: int = 12) -> str:
        """
        Hash password using bcrypt (via hashlib).
        
        Args:
            password: Password to hash
            rounds: Cost parameter (4-31)
            
        Returns:
            bcrypt hash string
        """
        import bcrypt
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def bcrypt_verify(password: str, hash_string: str) -> bool:
        """
        Verify password against bcrypt hash.
        
        Args:
            password: Password to verify
            hash_string: bcrypt hash string
            
        Returns:
            True if password matches, False otherwise
        """
        import bcrypt
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hash_string.encode('utf-8'))
        except Exception:
            return False
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None, 
                                algorithm: str = 'pbkdf2', **kwargs) -> Tuple[bytes, bytes]:
        """
        Generic key derivation from password.
        
        Args:
            password: Password string
            salt: Salt bytes (generated if None)
            algorithm: Algorithm ('pbkdf2', 'scrypt')
            **kwargs: Algorithm-specific parameters
            
        Returns:
            Tuple of (derived_key, salt)
        """
        password_bytes = password.encode('utf-8')
        
        if algorithm == 'pbkdf2':
            return KeyDerivation.pbkdf2(password_bytes, salt, **kwargs)
        elif algorithm == 'scrypt':
            return KeyDerivation.scrypt_derive(password_bytes, salt, **kwargs)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """
        Generate cryptographically secure random salt.
        
        Args:
            length: Salt length in bytes
            
        Returns:
            Random salt bytes
        """
        return os.urandom(length)