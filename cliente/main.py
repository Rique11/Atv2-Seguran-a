
import asyncio
import json
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from websockets.asyncio.client import connect


load_dotenv()
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL")

logs: list[str] = []

app = FastAPI(
    title="Cliente",
    description="Cliente que se comunica com o servidor",
    version="0.2.0",
)


@app.get("/")
@app.post("/enviar")
async def enviar_mensagem():
    """Envia uma mensagem ao servidor durante a requisicao HTTP atual."""
    if not WEBSOCKET_URL:
        raise HTTPException(
            status_code=500,
            detail="WEBSOCKET_URL nao configurada",
        )

    mensagem = {
        "origem": "A",
        "mensagem": "Ola do cliente A!",
    }

    try:
        async with connect(WEBSOCKET_URL) as websocket:
            await websocket.send(json.dumps(mensagem))
            resposta_bruta = await asyncio.wait_for(websocket.recv(), timeout=10)
            resposta = json.loads(resposta_bruta)

        logs.append(f"Resposta do servidor: {resposta}")

        return {
            "status": "mensagem-enviada",
            "resposta": resposta,
        }
    except Exception as erro:
        logs.append(f"Falha na comunicacao: {erro}")
        raise HTTPException(
            status_code=502,
            detail=f"Falha na comunicacao com o servidor: {erro}",
        ) from erro


@app.get("/status-cliente")
async def status():
    return {"status": "cliente-online"}


@app.get("/logs")
async def get_logs():
    return {"logs": logs}
