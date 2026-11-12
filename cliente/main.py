
import asyncio
import json
from contextlib import asynccontextmanager
import os
from fastapi import FastAPI
from dotenv import load_dotenv
from websockets.asyncio.client import connect

load_dotenv()
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL")

if not WEBSOCKET_URL:
    raise ValueError("WEBSOCKET_URL não definida no .env")

async def comunicar():
    while True:
        try:
            async with connect(WEBSOCKET_URL) as ws:
                print("Conectado ao servidor B!")

                while True:
                    await ws.send(json.dumps({
                        "origem": "A",
                        "mensagem": "Olá do servidor A!"
                    }))

                    resposta = await ws.recv()
                    print("Resposta de B:", json.loads(resposta))

                    await asyncio.sleep(5)

        except Exception as erro:
            print("Conexão perdida:", erro)
            await asyncio.sleep(3)


@asynccontextmanager
async def lifespan(app: FastAPI):
    tarefa = asyncio.create_task(comunicar())

    yield

    tarefa.cancel()

    try:
        await tarefa
    except asyncio.CancelledError:
        pass


app = FastAPI(
    lifespan=lifespan,
    title="Cliente",
    description="Cliente que se comunica com o servidor",
    version="0.1.1",
    )

@app.get("/status-cliente")
async def status():
    return {"status": "Cliente online"}
