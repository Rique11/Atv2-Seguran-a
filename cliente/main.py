import base64
import hashlib
import hmac
import json
import os
import re
import secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from websockets.asyncio.client import connect

load_dotenv()
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL")

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
    title="Cliente",
    description="Envia arquivos cifrados com chave estabelecida por Diffie-Hellman",
    version="1.0.0",
)

logs = []


def registrar(execucao, msg):
    print(msg)
    execucao.append(msg)
    logs.append(msg)


def derivar_chaves(segredo):
    bruto = segredo.to_bytes((segredo.bit_length() + 7) // 8, "big")
    return hashlib.sha256(bruto + b"enc").digest(), hashlib.sha256(bruto + b"mac").digest()


def cifrar(chave, dados):
    iv = os.urandom(16)
    preenchedor = padding.PKCS7(128).padder()
    preenchido = preenchedor.update(dados) + preenchedor.finalize()
    cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return iv, cifrador.update(preenchido) + cifrador.finalize()


def validar_arquivo(nome, conteudo):
    nome = os.path.basename(nome or "")
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
        try:
            conteudo.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("arquivo de texto não está em UTF-8")
    return nome


@app.get("/status-cliente")
async def status():
    return {"status": "Cliente online"}


@app.get("/logs")
async def get_logs():
    return {"logs": logs}


@app.post("/enviar-arquivo")
async def enviar_arquivo(arquivo: UploadFile = File(...), chave_errada: bool = False):
    if not WEBSOCKET_URL:
        raise HTTPException(status_code=500, detail="WEBSOCKET_URL não definida")

    conteudo = await arquivo.read(TAMANHO_MAXIMO + 1)
    try:
        nome = validar_arquivo(arquivo.filename, conteudo)
    except ValueError as erro:
        raise HTTPException(status_code=400, detail=str(erro))

    execucao = []
    try:
        async with connect(WEBSOCKET_URL, open_timeout=10) as ws:
            privada = secrets.randbelow(P - 3) + 2
            publica = pow(G, privada, P)
            await ws.send(json.dumps({"tipo": "dh", "chave_publica": str(publica)}))
            resposta = json.loads(await ws.recv())
            publica_servidor = int(resposta["chave_publica"])
            if not 1 < publica_servidor < P - 1:
                raise ValueError("chave pública do servidor inválida")

            segredo = pow(publica_servidor, privada, P)
            chave_enc, chave_mac = derivar_chaves(segredo)
            registrar(execucao, f"[DH] chave pública do cliente: {str(publica)[:40]}...")
            registrar(execucao, f"[DH] chave pública do servidor: {str(publica_servidor)[:40]}...")
            registrar(execucao, f"[DH] chave AES derivada: {chave_enc.hex()}")

            if chave_errada:
                chave_enc, chave_mac = os.urandom(32), os.urandom(32)
                registrar(execucao, f"[TESTE] usando chave errada: {chave_enc.hex()}")

            hash_arquivo = hashlib.sha256(conteudo).hexdigest()
            iv, cifrado = cifrar(chave_enc, nome.encode("utf-8") + b"\x00" + conteudo)
            mac = hmac.new(chave_mac, iv + cifrado, hashlib.sha256).hexdigest()
            dados = base64.b64encode(cifrado).decode()
            registrar(execucao, f"[TX] '{nome}' ({len(conteudo)} bytes), SHA-256 {hash_arquivo}")
            registrar(execucao, f"[TX] cifrado: {dados[:60]}...")

            await ws.send(json.dumps({
                "tipo": "arquivo",
                "iv": base64.b64encode(iv).decode(),
                "dados": dados,
                "hmac": mac,
            }))
            resposta = json.loads(await ws.recv())
            registrar(execucao, f"[RX] resposta do servidor: {resposta}")
    except Exception as erro:
        registrar(execucao, f"[ERRO] falha na comunicação: {erro}")
        raise HTTPException(status_code=502, detail=execucao)

    return {"logs": execucao, "resposta": resposta}
