# Troca de chaves Diffie-Hellman (mesmo arquivo no cliente e no servidor).
#
# Fonte dos valores públicos p e g:
# RFC 3526 - "More Modular Exponential (MODP) Diffie-Hellman groups for IKE",
#   Seção 3, grupo de 2048 bits (grupo 14).  https://www.rfc-editor.org/rfc/rfc3526#section-3
# As contas seguem o slide 63 de "4 - Criptografia.pdf":
#   chave pública  = g^privada mod p
#   segredo K      = (pública do outro)^(minha privada) mod p

import hashlib
import secrets

# p: primo de 2048 bits da RFC 3526 (grupo 14) | g: gerador
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2


def gerar_par():
    # Gera (chave_privada, chave_publica). A privada nunca sai da máquina.
    privada = secrets.randbelow(P - 3) + 2          # número aleatório entre 2 e p-2
    publica = pow(G, privada, P)                     # g^privada mod p
    return privada, publica


def calcular_chave_aes(publica_do_outro: int, minha_privada: int) -> str:
    # Calcula o segredo K e transforma em chave AES-256 (64 caracteres hex).
    if not 2 <= publica_do_outro <= P - 2:           # recusa valores triviais/inválidos
        raise ValueError("Chave pública Diffie-Hellman inválida")
    segredo = pow(publica_do_outro, minha_privada, P)               # K
    return hashlib.sha256(segredo.to_bytes(256, "big")).hexdigest()  # SHA-256(K) -> 32 bytes


def resumo(valor) -> str:
    # Encurta números grandes para caberem no log.
    s = hex(valor) if isinstance(valor, int) else str(valor)
    return s if len(s) <= 20 else f"{s[:16]}... ({len(s)} caracteres)"
