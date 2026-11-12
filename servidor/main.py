
import os

from AES_Python import AES
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv
app = FastAPI(
    title="Servidor",
    description="Servidor que recebe mensagens do cliente",
    version="0.1.0",
)
load_dotenv()   
AES_KEY = os.getenv("AES_KEY")
mensagens_servidor = []
    
async def criptografa(mensagem):
    aes = AES(key=AES_KEY)
    return aes.enc(data_string=mensagem)

async def descriptografa(mensagem):
    aes = AES(key=AES_KEY)
    return aes.dec(data_string=mensagem)

@app.get("/status-servidor")
async def status():
    return {"status": "servidor-online"}

@app.get("/mensagens-recebidas")
async def get_mensagens():
    return {"mensagens": mensagens_servidor}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()
            data = await descriptografa(data["mensagem"])
            mensagens_servidor.append(data)
            print("Mensagem recebida:", data)

            await websocket.send_json({
                "event": "message_received",
                "data": data
            })

    except WebSocketDisconnect:
        print("Cliente desconectado")
