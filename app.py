"""
Criptografador — backend em Python (Flask + cryptography).

Como funciona
-------------
- A "senha secreta" nunca é usada diretamente: o PBKDF2-HMAC-SHA256 deriva
  dela uma chave de 32 bytes, com um salt aleatório novo a cada mensagem.
- A mensagem é cifrada com Fernet (AES-128-CBC + HMAC-SHA256), que também
  detecta senha errada ou texto alterado.
- O resultado entregue ao usuário é base64url(salt + token), então a mesma
  mensagem gera textos diferentes a cada vez e só a senha certa abre.

Rodar:  pip install -r requirements.txt  &&  python app.py
Abrir:  http://127.0.0.1:5000
"""

import base64
import binascii
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, jsonify, request, send_from_directory

ITERACOES = 600_000
TAM_SALT = 16

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_000_000  # 1 MB por requisição


def derivar_chave(senha: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERACOES
    )
    return base64.urlsafe_b64encode(kdf.derive(senha.encode("utf-8")))


def criptografar(mensagem: str, senha: str) -> str:
    salt = os.urandom(TAM_SALT)
    token = Fernet(derivar_chave(senha, salt)).encrypt(mensagem.encode("utf-8"))
    return base64.urlsafe_b64encode(salt + token).decode("ascii")


def decifrar(texto: str, senha: str) -> str:
    invalido = ValueError("Mensagem criptografada inválida. Cole o texto completo.")
    try:
        bruto = base64.urlsafe_b64decode("".join(texto.split()).encode("ascii"))
    except (binascii.Error, ValueError):
        raise invalido from None
    if len(bruto) <= TAM_SALT:
        raise invalido
    salt, token = bruto[:TAM_SALT], bruto[TAM_SALT:]
    try:
        return Fernet(derivar_chave(senha, salt)).decrypt(token).decode("utf-8")
    except InvalidToken:
        raise ValueError(
            "Senha incorreta ou mensagem alterada. Confira os dois e tente de novo."
        ) from None


def _executar(funcao, mensagem_vazia: str):
    dados = request.get_json(silent=True) or {}
    senha = str(dados.get("senha", ""))
    mensagem = str(dados.get("mensagem", ""))
    try:
        if not senha:
            raise ValueError("Digite a senha secreta.")
        if not mensagem.strip():
            raise ValueError(mensagem_vazia)
        return jsonify(resultado=funcao(mensagem, senha))
    except ValueError as erro:
        return jsonify(erro=str(erro)), 400


@app.get("/")
def pagina():
    return send_from_directory(app.root_path, "index.html")


@app.post("/api/criptografar")
def api_criptografar():
    return _executar(criptografar, "Digite a mensagem.")


@app.post("/api/decifrar")
def api_decifrar():
    return _executar(decifrar, "Cole a mensagem criptografada.")


@app.after_request
def sem_cache(resp):
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    try:
        from waitress import serve
    except ImportError:  # sem waitress, cai no servidor de desenvolvimento do Flask
        app.run(host="127.0.0.1", port=5000, debug=False)
    else:
        print("Rodando em http://127.0.0.1:5000  (Ctrl+C para parar)")
        serve(app, host="127.0.0.1", port=5000)
