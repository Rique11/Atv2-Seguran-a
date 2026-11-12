
import asyncio
import json
from contextlib import asynccontextmanager
import os
from fastapi import FastAPI
from dotenv import load_dotenv
from websockets.asyncio.client import connect
from AES_Python import AES

load_dotenv()
WEBSOCKET_URL = os.getenv("WEBSOCKET_URL")
AES_KEY = os.getenv("AES_KEY")
logs = []

if not WEBSOCKET_URL:
    logs.append("WEBSOCKET_URL não definida no .env")
    raise ValueError("WEBSOCKET_URL não definida no .env")
if not AES_KEY:
    logs.append("AES_KEY não definida no .env")
    raise ValueError("AES_KEY não definida no .env")

async def criptografa(mensagem):
    aes = AES(key=AES_KEY)
    return aes.enc(data_string=mensagem)

async def descriptografa(mensagem):
    aes = AES(key=AES_KEY)
    return aes.dec(data_string=mensagem)

async def comunicar():
    while True:
        try:
            async with connect(WEBSOCKET_URL) as ws:
                print("Conectado ao servidor B!")
                logs.append("Conectado ao servidor B!")
                while True:
                    mensagem_criptografada = await criptografa("Olá do cliente A!")
                    await ws.send(json.dumps({
                        "origem": "A",
                        "mensagem": mensagem_criptografada  
                    }))
                    print("Mensagem enviada para B: \n" +  mensagem_criptografada)
                    resposta = await ws.recv()
                    print("Resposta de B:", json.loads(resposta))
                    logs.append(f"Resposta de B: {json.loads(resposta)}")

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

@app.get("/logs")
async def get_logs():
    return {"logs": logs}   

@app.get("/conecta-servidor")
async def conecta_servidor():
    return await comunicar()