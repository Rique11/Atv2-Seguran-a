
import base64
import json
import os
import tempfile
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

import diffie_hellman as dh
from cripto import descriptografa, sha256
from validacao import TAMANHO_MAXIMO, validar_arquivo

app = FastAPI(
    title="Servidor",
    description="Servidor que recebe arquivos cifrados do cliente",
    version="0.3.0",
)

# Localmente salva em ./recebidos. Na Vercel o disco é somente leitura,
# então usa a pasta temporária do sistema (/tmp), a única que aceita escrita.
try:
    PASTA_RECEBIDOS = "recebidos"
    os.makedirs(PASTA_RECEBIDOS, exist_ok=True)
except OSError:
    PASTA_RECEBIDOS = os.path.join(tempfile.gettempdir(), "recebidos")
    os.makedirs(PASTA_RECEBIDOS, exist_ok=True)
arquivos_recebidos = []  # resumo de cada envio (sem o conteúdo)


def registrar(texto):
    print(texto)


@app.get("/status-servidor")
async def status():
    return {"status": "servidor-online"}


@app.get("/mensagens-recebidas")
async def get_mensagens():
    return {"arquivos": arquivos_recebidos}


def processar_arquivo(data, chave_aes):
    """Decifra, confere o hash, valida e salva. Retorna a resposta para o cliente."""
    try:
        iv = base64.b64decode(data["iv"])
        cifrado = base64.b64decode(data["cifrado"])
    except (KeyError, ValueError):
        return {"event": "erro", "motivo": "Mensagem mal formatada"}

    if len(cifrado) > TAMANHO_MAXIMO + 1024:  # barra pacotes gigantes antes de decifrar
        return {"event": "erro", "motivo": "Pacote grande demais"}
    registrar(f"Cifrado recebido ({len(cifrado)} bytes): {cifrado[:16].hex()}...")

    # 1) Decifrar com a chave do Diffie-Hellman (AES-256-CBC)
    try:
        pacote = descriptografa(cifrado, chave_aes, iv)
        cabecalho_json, dados = pacote.split(b"\n", 1)
        cabecalho = json.loads(cabecalho_json)
    except ValueError:
        registrar("FALHA AO DECIFRAR: chave errada ou dados corrompidos")
        return {"event": "erro", "motivo": "Falha ao decifrar (chave errada?)"}

    # 2) Integridade: recalcula o SHA-256 e compara com o que veio dentro do pacote
    hash_recebido = cabecalho.get("sha256", "")
    hash_calculado = sha256(dados)
    registrar(f"SHA-256 recebido:  {hash_recebido}")
    registrar(f"SHA-256 calculado: {hash_calculado}")
    if hash_calculado != hash_recebido:
        registrar("FALHA DE INTEGRIDADE: os hashes são diferentes -> arquivo descartado")
        return {"event": "erro", "motivo": "Falha de integridade (hash não confere)"}

    # 3) Validação de nome, tamanho e tipo (o servidor não confia no cliente)
    try:
        nome = validar_arquivo(str(cabecalho.get("nome", "")), dados)
    except ValueError as e:
        registrar(f"RECUSADO na validação: {e}")
        return {"event": "erro", "motivo": str(e)}

    # 4) Salva com nome aleatório (evita sobrescrever arquivos e path traversal)
    extensao = os.path.splitext(nome)[1].lower()
    destino = os.path.join(PASTA_RECEBIDOS, uuid.uuid4().hex + extensao)
    with open(destino, "wb") as f:
        f.write(dados)
    arquivos_recebidos.append({"nome_original": nome, "salvo_como": destino,
                               "tamanho": len(dados), "sha256": hash_calculado})
    registrar(f"OK: integridade confirmada, {len(dados)} bytes salvos em {destino}")
    # Resposta sem o conteúdo do arquivo (nada em texto claro volta pela rede)
    return {"event": "ok", "nome": nome, "tamanho": len(dados), "sha256": hash_calculado}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    chave_aes = None  # cada conexão tem sua própria chave, criada pelo Diffie-Hellman

    try:
        while True:
            data = await websocket.receive_json()

            # 1) Troca de chaves Diffie-Hellman
            if data.get("tipo") == "dh":
                privada, publica = dh.gerar_par()
                try:
                    publica_cliente = int(data["pub"], 16)
                    chave_aes = bytes.fromhex(dh.calcular_chave_aes(publica_cliente, privada))
                except (KeyError, ValueError) as e:
                    await websocket.send_json({"event": "erro", "motivo": f"Diffie-Hellman inválido: {e}"})
                    continue
                registrar("=== Diffie-Hellman ===")
                registrar(f"Pública do cliente recebida: {dh.resumo(publica_cliente)}")
                registrar(f"Pública do servidor enviada: {dh.resumo(publica)}")
                registrar(f"Chave AES calculada (início): {chave_aes.hex()[:16]}")
                await websocket.send_json({"tipo": "dh", "pub": hex(publica)})
                continue

            # 2) Arquivo cifrado
            if data.get("tipo") == "arquivo":
                if chave_aes is None:
                    await websocket.send_json({"event": "erro", "motivo": "Faça a troca de chaves (dh) primeiro"})
                    continue
                registrar("=== Arquivo recebido ===")
                await websocket.send_json(processar_arquivo(data, chave_aes))
                continue

            await websocket.send_json({"event": "erro", "motivo": "Tipo de mensagem desconhecido"})

    except WebSocketDisconnect:
        print("Cliente desconectado")
