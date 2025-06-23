from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import base64

app = Flask(__name__)

# Carrega o certificado do cliente (emitido pela sua CA)
with open("usuario_cert.pem", "rb") as cert_file:
    user_cert = load_pem_x509_certificate(cert_file.read())
    public_key = user_cert.public_key()

@app.route("/mensagem", methods=["POST"])
def receber_mensagem():
    data = request.get_json()
    mensagem = data.get("mensagem", "")
    assinatura_b64 = data.get("assinatura", "")

    try:
        assinatura = base64.b64decode(assinatura_b64)

        public_key.verify(
            assinatura,
            mensagem.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return jsonify({"status": "OK", "verificacao": True}), 200

    except Exception as e:
        return jsonify({"status": "Erro", "verificacao": False, "detalhes": str(e)}), 400

if __name__ == "__main__":
    app.run(
        host="localhost",
        port=5000,
        ssl_context=("servidor_cert.pem", "servidor_key.pem")
    )
