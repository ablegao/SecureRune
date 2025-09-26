"""
Command-line interface for SecureRune.
"""

import click
import os
import sys
from typing import Optional

from .symmetric import SymmetricCrypto
from .asymmetric import AsymmetricCrypto
from .hashing import HashingAlgorithms
from .kdf import KeyDerivation
from .mac import MACAlgorithms
from .random_utils import RandomUtils


def format_bytes(data: bytes, format_type: str = 'hex') -> str:
    """Format bytes for output."""
    if format_type == 'hex':
        return data.hex()
    elif format_type == 'base64':
        import base64
        return base64.b64encode(data).decode()
    else:
        return str(data)


@click.group()
@click.version_option(version='0.1.0')
def main():
    """SecureRune - A compact utility covering security and encryption algorithms."""
    pass


@main.group()
def symmetric():
    """Symmetric encryption algorithms."""
    pass


@symmetric.command()
@click.option('--algorithm', '-a', default='aes', help='Algorithm (aes, des, 3des, chacha20)')
@click.option('--mode', '-m', default='CBC', help='Mode (CBC, GCM, CTR) - AES only')
@click.option('--key', '-k', help='Encryption key (hex)')
@click.option('--key-size', default=256, help='Key size in bits for key generation')
@click.option('--input-file', '-i', help='Input file path')
@click.option('--output-file', '-o', help='Output file path')
@click.option('--text', '-t', help='Text to encrypt')
def encrypt(algorithm, mode, key, key_size, input_file, output_file, text):
    """Encrypt data using symmetric algorithms."""
    
    # Get input data
    if text:
        plaintext = text.encode()
    elif input_file:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
    else:
        plaintext = sys.stdin.buffer.read()
    
    # Generate or parse key
    if key:
        key_bytes = bytes.fromhex(key)
    else:
        if algorithm == 'aes':
            key_bytes = RandomUtils.generate_key(key_size // 8)
        elif algorithm == 'des':
            key_bytes = RandomUtils.generate_key(8)
        elif algorithm == '3des':
            key_bytes = RandomUtils.generate_key(24)
        elif algorithm == 'chacha20':
            key_bytes = RandomUtils.generate_key(32)
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        click.echo(f"Generated key: {key_bytes.hex()}", err=True)
    
    # Encrypt
    try:
        if algorithm == 'aes':
            ciphertext, iv = SymmetricCrypto.aes_encrypt(plaintext, key_bytes, mode)
            click.echo(f"IV/Nonce: {iv.hex()}", err=True)
        elif algorithm == 'des':
            ciphertext, iv = SymmetricCrypto.des_encrypt(plaintext, key_bytes)
            click.echo(f"IV: {iv.hex()}", err=True)
        elif algorithm == '3des':
            ciphertext, iv = SymmetricCrypto.triple_des_encrypt(plaintext, key_bytes)
            click.echo(f"IV: {iv.hex()}", err=True)
        elif algorithm == 'chacha20':
            ciphertext, nonce = SymmetricCrypto.chacha20_encrypt(plaintext, key_bytes)
            click.echo(f"Nonce: {nonce.hex()}", err=True)
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        # Output result
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
        else:
            click.echo(ciphertext.hex())
            
    except Exception as e:
        raise click.ClickException(str(e))


@symmetric.command()
@click.option('--algorithm', '-a', default='aes', help='Algorithm (aes, des, 3des, chacha20)')
@click.option('--mode', '-m', default='CBC', help='Mode (CBC, GCM, CTR) - AES only')
@click.option('--key', '-k', required=True, help='Decryption key (hex)')
@click.option('--iv', required=True, help='IV/Nonce (hex)')
@click.option('--input-file', '-i', help='Input file path')
@click.option('--output-file', '-o', help='Output file path')
@click.option('--ciphertext', '-c', help='Ciphertext (hex)')
def decrypt(algorithm, mode, key, iv, input_file, output_file, ciphertext):
    """Decrypt data using symmetric algorithms."""
    
    # Get input data
    if ciphertext:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    elif input_file:
        with open(input_file, 'rb') as f:
            ciphertext_bytes = f.read()
    else:
        ciphertext_hex = input()
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    
    key_bytes = bytes.fromhex(key)
    iv_bytes = bytes.fromhex(iv)
    
    # Decrypt
    try:
        if algorithm == 'aes':
            plaintext = SymmetricCrypto.aes_decrypt(ciphertext_bytes, key_bytes, iv_bytes, mode)
        elif algorithm == 'des':
            plaintext = SymmetricCrypto.des_decrypt(ciphertext_bytes, key_bytes, iv_bytes)
        elif algorithm == '3des':
            plaintext = SymmetricCrypto.triple_des_decrypt(ciphertext_bytes, key_bytes, iv_bytes)
        elif algorithm == 'chacha20':
            plaintext = SymmetricCrypto.chacha20_decrypt(ciphertext_bytes, key_bytes, iv_bytes)
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        # Output result
        if output_file:
            with open(output_file, 'wb') as f:
                f.write(plaintext)
        else:
            try:
                click.echo(plaintext.decode())
            except UnicodeDecodeError:
                click.echo(plaintext.hex())
            
    except Exception as e:
        raise click.ClickException(str(e))


@main.group()
def asymmetric():
    """Asymmetric (public-key) encryption algorithms."""
    pass


@asymmetric.command()
@click.option('--algorithm', '-a', default='rsa', help='Algorithm (rsa, dsa, ecc)')
@click.option('--key-size', default=2048, help='Key size in bits')
@click.option('--curve', default='SECP256R1', help='Curve for ECC (SECP256R1, SECP384R1, SECP521R1)')
@click.option('--private-key-file', help='Private key output file')
@click.option('--public-key-file', help='Public key output file')
def keygen(algorithm, key_size, curve, private_key_file, public_key_file):
    """Generate asymmetric key pairs."""
    
    try:
        if algorithm == 'rsa':
            private_pem, public_pem = AsymmetricCrypto.generate_rsa_keypair(key_size)
        elif algorithm == 'dsa':
            private_pem, public_pem = AsymmetricCrypto.generate_dsa_keypair(key_size)
        elif algorithm == 'ecc':
            private_pem, public_pem = AsymmetricCrypto.generate_ecc_keypair(curve)
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        if private_key_file:
            with open(private_key_file, 'wb') as f:
                f.write(private_pem)
        else:
            click.echo("Private Key:")
            click.echo(private_pem.decode())
        
        if public_key_file:
            with open(public_key_file, 'wb') as f:
                f.write(public_pem)
        else:
            click.echo("Public Key:")
            click.echo(public_pem.decode())
            
    except Exception as e:
        raise click.ClickException(str(e))


@main.group()
def hash():
    """Hashing algorithms."""
    pass


@hash.command()
@click.option('--algorithm', '-a', default='sha256', help='Hash algorithm')
@click.option('--input-file', '-i', help='Input file path')
@click.option('--text', '-t', help='Text to hash')
def compute(algorithm, input_file, text):
    """Compute hash of data."""
    
    # Get input data
    if text:
        data = text.encode()
    elif input_file:
        with open(input_file, 'rb') as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()
    
    try:
        hash_func = getattr(HashingAlgorithms, algorithm.replace('-', '_'))
        if algorithm.startswith('shake'):
            # SHAKE algorithms need length parameter
            digest = hash_func(data, 32)  # Default to 32 bytes
        else:
            digest = hash_func(data)
        
        click.echo(f"{algorithm.upper()}: {digest.hex()}")
        
    except AttributeError:
        raise click.ClickException(f"Unsupported hash algorithm: {algorithm}")
    except Exception as e:
        raise click.ClickException(str(e))


@main.group()
def kdf():
    """Key derivation functions."""
    pass


@kdf.command()
@click.option('--algorithm', '-a', default='pbkdf2', help='KDF algorithm (pbkdf2, scrypt)')
@click.option('--password', '-p', required=True, help='Password')
@click.option('--salt', '-s', help='Salt (hex)')
@click.option('--iterations', default=100000, help='Iterations for PBKDF2')
@click.option('--key-length', default=32, help='Output key length')
def derive(algorithm, password, salt, iterations, key_length):
    """Derive key from password."""
    
    salt_bytes = bytes.fromhex(salt) if salt else None
    
    try:
        if algorithm == 'pbkdf2':
            key, salt_used = KeyDerivation.pbkdf2(
                password.encode(), salt_bytes, iterations, key_length
            )
        elif algorithm == 'scrypt':
            key, salt_used = KeyDerivation.scrypt_derive(
                password.encode(), salt_bytes, key_length=key_length
            )
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        click.echo(f"Salt: {salt_used.hex()}")
        click.echo(f"Derived key: {key.hex()}")
        
    except Exception as e:
        raise click.ClickException(str(e))


@main.group()
def mac():
    """Message Authentication Code algorithms."""
    pass


@mac.command()
@click.option('--algorithm', '-a', default='hmac-sha256', help='MAC algorithm')
@click.option('--key', '-k', required=True, help='Secret key (hex)')
@click.option('--input-file', '-i', help='Input file path')
@click.option('--text', '-t', help='Text to authenticate')
def compute_mac(algorithm, key, input_file, text):
    """Compute MAC of data."""
    
    # Get input data
    if text:
        data = text.encode()
    elif input_file:
        with open(input_file, 'rb') as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()
    
    key_bytes = bytes.fromhex(key)
    
    try:
        if algorithm == 'hmac-sha256':
            mac_value = MACAlgorithms.hmac_sha256(key_bytes, data)
        elif algorithm == 'hmac-sha1':
            mac_value = MACAlgorithms.hmac_sha1(key_bytes, data)
        elif algorithm == 'hmac-sha512':
            mac_value = MACAlgorithms.hmac_sha512(key_bytes, data)
        elif algorithm == 'cmac-aes':
            mac_value = MACAlgorithms.cmac_aes(key_bytes, data)
        else:
            raise click.ClickException(f"Unsupported algorithm: {algorithm}")
        
        click.echo(f"{algorithm.upper()}: {mac_value.hex()}")
        
    except Exception as e:
        raise click.ClickException(str(e))


@main.group()
def random():
    """Random number generation utilities."""
    pass


@random.command()
@click.option('--length', '-l', default=32, help='Number of bytes to generate')
@click.option('--format', '-f', default='hex', help='Output format (hex, base64)')
def bytes_cmd(length, format):
    """Generate random bytes."""
    
    try:
        random_bytes = RandomUtils.secure_random_bytes(length)
        
        if format == 'hex':
            click.echo(random_bytes.hex())
        elif format == 'base64':
            import base64
            click.echo(base64.b64encode(random_bytes).decode())
        else:
            raise click.ClickException(f"Unsupported format: {format}")
            
    except Exception as e:
        raise click.ClickException(str(e))


@random.command()
@click.option('--length', '-l', default=16, help='Password length')
@click.option('--no-symbols', is_flag=True, help='Exclude special symbols')
def password(length, no_symbols):
    """Generate secure password."""
    
    try:
        pwd = RandomUtils.generate_password(length, not no_symbols)
        click.echo(pwd)
        
    except Exception as e:
        raise click.ClickException(str(e))


if __name__ == '__main__':
    main()