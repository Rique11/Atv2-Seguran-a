import base64
import hashlib
import hmac
import os
import re
import secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2

TAMANHO_MAXIMO = 1024 * 1024
EXTENSOES = {".txt", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg"}
ASSINATURAS = {
    ".pdf": b"%PDF",
    ".png": b"\x89PNG\r\n\x1a\n",
    ".jpg": b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
}

app = FastAPI(
    title="Servidor",
    description="Recebe arquivos cifrados após troca de chaves Diffie-Hellman",
    version="1.0.0",
)

logs = []
arquivos_recebidos = []


def registrar(msg):
    print(msg)
    logs.append(msg)


def derivar_chaves(segredo):
    bruto = segredo.to_bytes((segredo.bit_length() + 7) // 8, "big")
    return hashlib.sha256(bruto + b"enc").digest(), hashlib.sha256(bruto + b"mac").digest()


def decifrar(chave, iv, dados):
    decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
    preenchido = decifrador.update(dados) + decifrador.finalize()
    removedor = padding.PKCS7(128).unpadder()
    return removedor.update(preenchido) + removedor.finalize()


def validar_arquivo(nome, conteudo):
    nome = os.path.basename(nome)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", nome) or nome.startswith("."):
        raise ValueError("nome de arquivo inválido")
    extensao = os.path.splitext(nome)[1].lower()
    if extensao not in EXTENSOES:
        raise ValueError(f"tipo de arquivo não permitido: {extensao}")
    if len(conteudo) == 0 or len(conteudo) > TAMANHO_MAXIMO:
        raise ValueError(f"tamanho inválido: {len(conteudo)} bytes")
    if extensao in ASSINATURAS and not conteudo.startswith(ASSINATURAS[extensao]):
        raise ValueError("conteúdo não corresponde à extensão")
    if extensao in {".txt", ".csv", ".json"}:
        conteudo.decode("utf-8")
    return nome


@app.get("/status-servidor")
async def status():
    return {"status": "servidor-online"}


@app.get("/logs-servidor")
async def get_logs():
    return {"logs": logs}


@app.get("/arquivos-recebidos")
async def get_arquivos():
    return {"arquivos": arquivos_recebidos}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        inicio = await websocket.receive_json()
        if inicio.get("tipo") != "dh":
            await websocket.close(code=1008)
            return

        privada = secrets.randbelow(P - 3) + 2
        publica = pow(G, privada, P)
        publica_cliente = int(inicio["chave_publica"])
        if not 1 < publica_cliente < P - 1:
            await websocket.close(code=1008)
            return

        await websocket.send_json({"tipo": "dh", "chave_publica": str(publica)})
        segredo = pow(publica_cliente, privada, P)
        chave_enc, chave_mac = derivar_chaves(segredo)
        registrar(f"[DH] chave pública do cliente: {str(publica_cliente)[:40]}...")
        registrar(f"[DH] chave pública do servidor: {str(publica)[:40]}...")
        registrar(f"[DH] chave AES derivada: {chave_enc.hex()}")

        while True:
            msg = await websocket.receive_json()
            iv = base64.b64decode(msg["iv"])
            cifrado = base64.b64decode(msg["dados"])
            registrar(f"[RX] arquivo cifrado recebido ({len(cifrado)} bytes): {msg['dados'][:60]}...")

            mac_esperado = hmac.new(chave_mac, iv + cifrado, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac_esperado, msg["hmac"]):
                registrar("[ERRO] HMAC-SHA256 não confere: chave errada ou dados alterados")
                try:
                    decifrar(chave_enc, iv, cifrado)
                    registrar("[ERRO] decifragem produziu dados inválidos")
                except ValueError as erro:
                    registrar(f"[ERRO] falha ao decifrar: {erro}")
                await websocket.send_json({"tipo": "erro", "motivo": "falha de integridade"})
                continue

            try:
                pacote = decifrar(chave_enc, iv, cifrado)
                nome_bytes, conteudo = pacote.split(b"\x00", 1)
                nome = validar_arquivo(nome_bytes.decode("utf-8"), conteudo)
            except (ValueError, UnicodeDecodeError) as erro:
                registrar(f"[ERRO] arquivo rejeitado: {erro}")
                await websocket.send_json({"tipo": "erro", "motivo": str(erro)})
                continue

            hash_arquivo = hashlib.sha256(conteudo).hexdigest()
            registrar(f"[OK] '{nome}' decifrado ({len(conteudo)} bytes), SHA-256 {hash_arquivo}")
            arquivos_recebidos.append({"nome": nome, "tamanho": len(conteudo), "sha256": hash_arquivo})
            await websocket.send_json({"tipo": "ok", "nome": nome, "sha256": hash_arquivo})

    except WebSocketDisconnect:
        registrar("[WS] cliente desconectado")
