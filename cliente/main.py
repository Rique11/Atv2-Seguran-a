
import base64
import json
import os
from enum import Enum

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, UploadFile
from websockets.asyncio.client import connect

import diffie_hellman as dh
from cripto import criptografa, sha256
from validacao import TAMANHO_MAXIMO, validar_arquivo

load_dotenv()
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL")
logs = []

if not WEBSOCKET_URL:
    logs.append("WEBSOCKET_URL não definida no .env")
    raise ValueError("WEBSOCKET_URL não definida no .env")


class Teste(str, Enum):
    nenhum = "nenhum"                # envio normal
    chave_errada = "chave_errada"    # cifra com uma chave diferente da combinada no DH
    adulterar = "adulterar"          # altera 1 byte do cifrado "no caminho"
    sem_validacao = "sem_validacao"  # pula a validação do cliente (testa a do servidor)


def registrar(etapas, texto):
    print(texto)
    logs.append(texto)
    etapas.append(texto)


async def troca_de_chaves(ws, etapas):
    """Diffie-Hellman: envia a pública do cliente, recebe a do servidor e calcula a chave AES."""
    privada, publica = dh.gerar_par()
    await ws.send(json.dumps({"tipo": "dh", "pub": hex(publica)}))
    resposta = json.loads(await ws.recv())
    publica_servidor = int(resposta["pub"], 16)
    chave_aes = bytes.fromhex(dh.calcular_chave_aes(publica_servidor, privada))
    registrar(etapas, "=== Diffie-Hellman ===")
    registrar(etapas, f"Pública do cliente enviada: {dh.resumo(publica)}")
    registrar(etapas, f"Pública do servidor recebida: {dh.resumo(publica_servidor)}")
    registrar(etapas, f"Chave AES calculada (início): {chave_aes.hex()[:16]}")
    return chave_aes


async def enviar_arquivo(nome, dados, teste: Teste):
    """Um ciclo completo: valida -> conecta -> DH -> hash -> AES -> envia -> resposta."""
    etapas = []
    registrar(etapas, f"=== Envio de {nome!r} ({len(dados)} bytes) | teste: {teste.value} ===")

    # 0) Validação de nome, tamanho e tipo
    if teste != Teste.sem_validacao:
        try:
            nome = validar_arquivo(nome, dados)
        except ValueError as e:
            registrar(etapas, f"RECUSADO no cliente: {e}")
            return {"resultado": "recusado no cliente", "motivo": str(e), "etapas": etapas}

    async with connect(WEBSOCKET_URL, max_size=4 * 1024 * 1024) as ws:
        # 1) Diffie-Hellman
        chave_aes = await troca_de_chaves(ws, etapas)
        if teste == Teste.chave_errada:
            chave_aes = os.urandom(32)
            registrar(etapas, f"[TESTE] Usando CHAVE ERRADA: {chave_aes.hex()[:16]}")

        # 2) Hash SHA-256 do arquivo + pacote = cabeçalho JSON + "\n" + bytes do arquivo
        hash_arquivo = sha256(dados)
        cabecalho = json.dumps({"nome": nome, "tamanho": len(dados), "sha256": hash_arquivo})
        pacote = cabecalho.encode() + b"\n" + dados
        registrar(etapas, f"SHA-256 do arquivo: {hash_arquivo}")

        # 3) Cifra o pacote inteiro com AES-256-CBC (nome, hash e conteúdo ficam sigilosos)
        iv, cifrado = criptografa(pacote, chave_aes)
        registrar(etapas, f"IV: {iv.hex()} | cifrado ({len(cifrado)} bytes): {cifrado[:16].hex()}...")

        if teste == Teste.adulterar and len(cifrado) >= 64:
            cifrado = bytearray(cifrado)
            cifrado[len(cifrado) - 48] ^= 0x01  # inverte 1 bit no meio dos dados do arquivo
            cifrado = bytes(cifrado)
            registrar(etapas, "[TESTE] 1 bit do arquivo cifrado foi alterado no caminho")

        # 4) Envia e aguarda a resposta do servidor
        await ws.send(json.dumps({
            "tipo": "arquivo",
            "iv": base64.b64encode(iv).decode(),
            "cifrado": base64.b64encode(cifrado).decode(),
        }))
        resposta = json.loads(await ws.recv())
        registrar(etapas, f"Resposta do servidor: {resposta}")

    return {"resultado": resposta.get("event"), "resposta_servidor": resposta, "etapas": etapas}


app = FastAPI(
    title="Cliente",
    description="Cliente que envia arquivos cifrados ao servidor (DH + AES-256 + SHA-256). "
                "Use POST /enviar para testar.",
    version="0.3.0",
)


@app.get("/status-cliente")
async def status():
    return {"status": "Cliente online"}


@app.get("/logs")
async def get_logs():
    return {"logs": logs}


@app.post("/enviar")
async def enviar(
    arquivo: UploadFile = File(..., description="Arquivo pequeno (.txt, .png, .jpg, .pdf até 1 MB)"),
    teste: Teste = Form(Teste.nenhum),
    nome: str = Form("", description="Opcional: nome a enviar no lugar do original (ex.: ../../x.txt)"),
):
    dados = await arquivo.read(TAMANHO_MAXIMO + 1)  # nunca lê mais que o limite + 1 byte
    return await enviar_arquivo(nome or arquivo.filename or "", dados, teste)
