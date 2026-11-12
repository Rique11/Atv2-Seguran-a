
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

app = FastAPI(
    title="Servidor",
    description="Servidor que recebe mensagens do cliente",
    version="0.1.0",
)

@app.get("/status-servidor")
async def status():
    return {"status": "servidor-online"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()

            print("Mensagem recebida:", data)

            await websocket.send_json({
                "event": "message_received",
                "data": data
            })

    except WebSocketDisconnect:
        print("Cliente desconectado")
