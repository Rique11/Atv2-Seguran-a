# Validação do arquivo antes de enviar (cliente) e depois de receber (servidor):
# NOME, TAMANHO e TIPO — para evitar brechas de segurança.
#
# nem só na extensão, conferir magic bytes, sanitizar o nome contra path traversal).
# Assinaturas (magic numbers): https://en.wikipedia.org/wiki/List_of_file_signatures

import os
import re

TAMANHO_MAXIMO = 1 * 1024 * 1024  # 1 MB ("arquivo pequeno", como pede o enunciado)

# extensão permitida -> assinaturas aceitas no início do arquivo
TIPOS_PERMITIDOS = {
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".pdf": [b"%PDF-"],
    ".txt": None,  # texto não tem magic number: exige UTF-8 sem bytes nulos
}


def validar_arquivo(nome: str, dados: bytes) -> str:
    # Retorna o nome limpo. Lança ValueError com o motivo se o arquivo for recusado.
    # 1) NOME: tira qualquer caminho (../, C:\...) e aceita só caracteres seguros
    nome = os.path.basename(nome.replace("\\", "/")).strip()
    if not re.fullmatch(r"[A-Za-z0-9 _\-.]{1,100}", nome) or nome.startswith("."):
        raise ValueError(f"Nome de arquivo inválido: {nome!r}")

    # 2) TAMANHO
    if len(dados) == 0:
        raise ValueError("Arquivo vazio")
    if len(dados) > TAMANHO_MAXIMO:
        raise ValueError(f"Arquivo muito grande: {len(dados)} bytes (máximo {TAMANHO_MAXIMO})")

    # 3) TIPO: extensão permitida + conteúdo real (magic number)
    extensao = os.path.splitext(nome)[1].lower()
    if extensao not in TIPOS_PERMITIDOS:
        raise ValueError(f"Extensão não permitida: {extensao or '(sem extensão)'}")
    assinaturas = TIPOS_PERMITIDOS[extensao]
    if assinaturas is None:
        if b"\x00" in dados:
            raise ValueError("Arquivo .txt contém bytes binários")
        try:
            dados.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Arquivo .txt não é texto UTF-8")
    elif not any(dados.startswith(a) for a in assinaturas):
        raise ValueError(f"O conteúdo não é de um {extensao} (magic number não confere)")

    return nome
