# Cifragem simétrica e hash
# AES-256 no modo CBC + padding PKCS7: biblioteca `cryptography`
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/  
# https://cryptography.io/en/latest/hazmat/primitives/padding/

# SHA-256: módulo `hashlib` da biblioteca padrão do Python
# https://docs.python.org/3/library/hashlib.html

# IV aleatório: `os.urandom`

import hashlib
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAMANHO_BLOCO = 128  # AES trabalha com blocos de 128 bits (16 bytes)


def criptografa(dados: bytes, chave: bytes) -> tuple[bytes, bytes]:
    # AES-256-CBC. Retorna (iv, dados_cifrados). Um IV novo a cada envio.
    iv = os.urandom(16)
    preenchedor = padding.PKCS7(TAMANHO_BLOCO).padder()
    dados_com_padding = preenchedor.update(dados) + preenchedor.finalize()
    cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return iv, cifrador.update(dados_com_padding) + cifrador.finalize()


def descriptografa(cifrado: bytes, chave: bytes, iv: bytes) -> bytes:
    # Decifra AES-256-CBC. Lança ValueError se a chave estiver errada (padding inválido).
    decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
    dados_com_padding = decifrador.update(cifrado) + decifrador.finalize()
    removedor = padding.PKCS7(TAMANHO_BLOCO).unpadder()
    return removedor.update(dados_com_padding) + removedor.finalize()


def sha256(dados: bytes) -> str:
    # Resumo SHA-256 em hexadecimal (64 caracteres).
    return hashlib.sha256(dados).hexdigest()
