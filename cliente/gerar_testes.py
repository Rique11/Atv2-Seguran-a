"""Cria a pasta testes/ com arquivos válidos e maliciosos para os testes do relatório."""
import os
import struct
import zlib

os.makedirs("testes", exist_ok=True)


def png_1x1():
    def chunk(tipo, dados):
        return (struct.pack(">I", len(dados)) + tipo + dados
                + struct.pack(">I", zlib.crc32(tipo + dados) & 0xFFFFFFFF))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))


arquivos = {
    "mensagem.txt": "Mensagem secreta da Atividade 2 - Segurança e Auditoria de Sistemas.\n".encode(),
    "imagem.png": png_1x1(),
    "documento.pdf": b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n",
    "grande.txt": b"A" * (2 * 1024 * 1024),     # 2 MB -> passa do limite de 1 MB
    "virus.png": b"MZ\x90\x00" + b"\x00" * 200,  # executável disfarçado de .png
    "programa.exe": b"MZ\x90\x00" + b"\x00" * 200,  # extensão proibida
}
for nome, dados in arquivos.items():
    with open(os.path.join("testes", nome), "wb") as f:
        f.write(dados)
    print(f"criado testes/{nome} ({len(dados)} bytes)")
