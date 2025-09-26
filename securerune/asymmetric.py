"""
Asymmetric (public-key) encryption algorithms implementation.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding


class AsymmetricCrypto:
    """Asymmetric encryption algorithms collection."""
    
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair.
        
        Args:
            key_size: Key size in bits (1024, 2048, 3072, 4096)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def rsa_encrypt(plaintext: bytes, public_key_pem: bytes, padding_scheme: str = 'OAEP') -> bytes:
        """
        Encrypt using RSA.
        
        Args:
            plaintext: Data to encrypt
            public_key_pem: Public key in PEM format
            padding_scheme: Padding scheme ('OAEP' or 'PKCS1v15')
            
        Returns:
            Encrypted ciphertext
        """
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        if padding_scheme == 'OAEP':
            ciphertext = public_key.encrypt(
                plaintext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif padding_scheme == 'PKCS1v15':
            ciphertext = public_key.encrypt(
                plaintext,
                asym_padding.PKCS1v15()
            )
        else:
            raise ValueError(f"Unsupported padding scheme: {padding_scheme}")
            
        return ciphertext
    
    @staticmethod
    def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes, padding_scheme: str = 'OAEP') -> bytes:
        """
        Decrypt using RSA.
        
        Args:
            ciphertext: Data to decrypt
            private_key_pem: Private key in PEM format
            padding_scheme: Padding scheme ('OAEP' or 'PKCS1v15')
            
        Returns:
            Decrypted plaintext
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        if padding_scheme == 'OAEP':
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif padding_scheme == 'PKCS1v15':
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.PKCS1v15()
            )
        else:
            raise ValueError(f"Unsupported padding scheme: {padding_scheme}")
            
        return plaintext
    
    @staticmethod
    def generate_dsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate DSA key pair.
        
        Args:
            key_size: Key size in bits (1024, 2048, 3072)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = dsa.generate_private_key(key_size=key_size)
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def dsa_sign(message: bytes, private_key_pem: bytes, hash_algorithm: str = 'SHA256') -> bytes:
        """
        Sign message using DSA.
        
        Args:
            message: Message to sign
            private_key_pem: Private key in PEM format
            hash_algorithm: Hash algorithm ('SHA256', 'SHA1', 'SHA512')
            
        Returns:
            Digital signature
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        
        hash_alg = getattr(hashes, hash_algorithm)()
        signature = private_key.sign(message, hash_alg)
        
        return signature
    
    @staticmethod
    def dsa_verify(message: bytes, signature: bytes, public_key_pem: bytes, hash_algorithm: str = 'SHA256') -> bool:
        """
        Verify DSA signature.
        
        Args:
            message: Original message
            signature: Digital signature
            public_key_pem: Public key in PEM format
            hash_algorithm: Hash algorithm ('SHA256', 'SHA1', 'SHA512')
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            hash_alg = getattr(hashes, hash_algorithm)()
            public_key.verify(signature, message, hash_alg)
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_ecc_keypair(curve: str = 'SECP256R1') -> Tuple[bytes, bytes]:
        """
        Generate ECC (Elliptic Curve Cryptography) key pair.
        
        Args:
            curve: Curve name ('SECP256R1', 'SECP384R1', 'SECP521R1')
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        curve_obj = getattr(ec, curve)()
        private_key = ec.generate_private_key(curve_obj)
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def ecdsa_sign(message: bytes, private_key_pem: bytes, hash_algorithm: str = 'SHA256') -> bytes:
        """
        Sign message using ECDSA.
        
        Args:
            message: Message to sign
            private_key_pem: Private key in PEM format
            hash_algorithm: Hash algorithm ('SHA256', 'SHA384', 'SHA512')
            
        Returns:
            Digital signature
        """
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        hash_alg = getattr(hashes, hash_algorithm)()
        signature = private_key.sign(message, ec.ECDSA(hash_alg))
        
        return signature
    
    @staticmethod
    def ecdsa_verify(message: bytes, signature: bytes, public_key_pem: bytes, hash_algorithm: str = 'SHA256') -> bool:
        """
        Verify ECDSA signature.
        
        Args:
            message: Original message
            signature: Digital signature
            public_key_pem: Public key in PEM format
            hash_algorithm: Hash algorithm ('SHA256', 'SHA384', 'SHA512')
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            hash_alg = getattr(hashes, hash_algorithm)()
            public_key.verify(signature, message, ec.ECDSA(hash_alg))
            return True
        except Exception:
            return False