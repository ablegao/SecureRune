"""
Symmetric encryption algorithms implementation.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import AES as PyCrypto_AES, DES, DES3, ChaCha20


class SymmetricCrypto:
    """Symmetric encryption algorithms collection."""
    
    @staticmethod
    def aes_encrypt(plaintext: bytes, key: bytes, mode: str = 'CBC') -> Tuple[bytes, bytes]:
        """
        Encrypt using AES (Advanced Encryption Standard).
        
        Args:
            plaintext: Data to encrypt
            key: 16, 24, or 32 bytes key
            mode: Encryption mode ('CBC', 'GCM', 'CTR')
            
        Returns:
            Tuple of (ciphertext, iv_or_nonce)
        """
        if mode == 'CBC':
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return ciphertext, iv
            
        elif mode == 'GCM':
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return ciphertext + encryptor.tag, nonce
            
        elif mode == 'CTR':
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce + b'\x00' * 4))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return ciphertext, nonce
            
        else:
            raise ValueError(f"Unsupported mode: {mode}")
    
    @staticmethod
    def aes_decrypt(ciphertext: bytes, key: bytes, iv_or_nonce: bytes, mode: str = 'CBC') -> bytes:
        """
        Decrypt using AES.
        
        Args:
            ciphertext: Data to decrypt
            key: 16, 24, or 32 bytes key
            iv_or_nonce: IV or nonce used during encryption
            mode: Decryption mode ('CBC', 'GCM', 'CTR')
            
        Returns:
            Decrypted plaintext
        """
        if mode == 'CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_or_nonce))
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            return plaintext
            
        elif mode == 'GCM':
            tag = ciphertext[-16:]
            actual_ciphertext = ciphertext[:-16]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv_or_nonce, tag))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
            return plaintext
            
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv_or_nonce + b'\x00' * 4))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
            
        else:
            raise ValueError(f"Unsupported mode: {mode}")
    
    @staticmethod
    def des_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt using DES (Data Encryption Standard).
        
        ⚠️ WARNING: DES is cryptographically broken and should not be used 
        for security purposes. This implementation is for legacy compatibility 
        and educational purposes only.
        
        Args:
            plaintext: Data to encrypt
            key: 8 bytes key
            
        Returns:
            Tuple of (ciphertext, iv)
        """
        iv = os.urandom(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Apply PKCS7 padding
        pad_len = 8 - (len(plaintext) % 8)
        padded_plaintext = plaintext + bytes([pad_len]) * pad_len
        
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext, iv
    
    @staticmethod
    def des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt using DES.
        
        ⚠️ WARNING: DES is cryptographically broken and should not be used 
        for security purposes. This implementation is for legacy compatibility 
        and educational purposes only.
        
        Args:
            ciphertext: Data to decrypt
            key: 8 bytes key
            iv: IV used during encryption
            
        Returns:
            Decrypted plaintext
        """
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        pad_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_len]
        return plaintext
    
    @staticmethod
    def triple_des_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt using 3DES (Triple DES).
        
        ⚠️ WARNING: 3DES is deprecated and should not be used for new applications.
        Use AES instead. This implementation is for legacy compatibility only.
        
        Args:
            plaintext: Data to encrypt
            key: 16 or 24 bytes key
            
        Returns:
            Tuple of (ciphertext, iv)
        """
        iv = os.urandom(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Apply PKCS7 padding
        pad_len = 8 - (len(plaintext) % 8)
        padded_plaintext = plaintext + bytes([pad_len]) * pad_len
        
        ciphertext = cipher.encrypt(padded_plaintext)
        return ciphertext, iv
    
    @staticmethod
    def triple_des_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypt using 3DES.
        
        ⚠️ WARNING: 3DES is deprecated and should not be used for new applications.
        Use AES instead. This implementation is for legacy compatibility only.
        
        Args:
            ciphertext: Data to decrypt
            key: 16 or 24 bytes key
            iv: IV used during encryption
            
        Returns:
            Decrypted plaintext
        """
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        pad_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_len]
        return plaintext
    
    @staticmethod
    def chacha20_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt using ChaCha20.
        
        Args:
            plaintext: Data to encrypt
            key: 32 bytes key
            
        Returns:
            Tuple of (ciphertext, nonce)
        """
        nonce = os.urandom(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext, nonce
    
    @staticmethod
    def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Decrypt using ChaCha20.
        
        Args:
            ciphertext: Data to decrypt
            key: 32 bytes key
            nonce: Nonce used during encryption
            
        Returns:
            Decrypted plaintext
        """
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext