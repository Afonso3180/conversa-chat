from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import ssl
import base64

app = Flask(__name__)
mensagens_armazenadas = []  # Armazena mensagens trocadas

def carregar_certificado_usuario():
    """Carrega o certificado do usuário para validação da assinatura."""
    try:
        with open("usuario_cert.pem", "rb") as f:
            cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data)
    except FileNotFoundError:
        return None

@app.route('/mensagem', methods=['POST'])
def receber_mensagem():
    """Recebe e valida mensagens assinadas digitalmente."""
    data = request.get_json()
    remetente = data.get("remetente")
    destinatario = data.get("destinatario")
    mensagem = data.get("mensagem")
    assinatura = data.get("assinatura")

    cert = carregar_certificado_usuario()
    if cert is None:
        return jsonify({"status": "Erro", "detalhes": "Certificado do remetente não encontrado"}), 400

    public_key = cert.public_key()

    try:
        # Verifica a assinatura da mensagem
        public_key.verify(
            base64.b64decode(assinatura),
            mensagem.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Armazena a mensagem se for válida
        mensagens_armazenadas.append({
            "remetente": remetente,
            "destinatario": destinatario,
            "mensagem": mensagem,
            "assinatura": assinatura
        })

        print("[INFO] Conexão recebida via HTTPS")
        print(f"[HTTPS ATIVO] Mensagem recebida de '{remetente}' para '{destinatario}': OK")
        return jsonify({"status": "OK", "detalhes": "Assinatura válida", "verificacao": True}), 200

    except Exception as e:
        # Em caso de falha na verificação
        return jsonify({"status": "Erro", "detalhes": str(e), "verificacao": False}), 400

@app.route('/mensagens/<usuario>', methods=['GET'])
def mensagens_para_usuario(usuario):
    """Retorna todas as mensagens destinadas a um usuário."""
    mensagens = [
        {
            "remetente": msg.get("remetente"),
            "mensagem": msg.get("mensagem"),
            "assinatura": msg.get("assinatura")
        }
        for msg in mensagens_armazenadas if msg.get("destinatario") == usuario
    ]
    return jsonify(mensagens)

@app.route('/enviadas/<usuario>', methods=['GET'])
def mensagens_enviadas(usuario):
    """Retorna todas as mensagens enviadas por um usuário."""
    mensagens = [
        {
            "remetente": msg.get("remetente"),
            "mensagem": msg.get("mensagem"),
            "assinatura": msg.get("assinatura")
        }
        for msg in mensagens_armazenadas if msg.get("remetente") == usuario
    ]
    return jsonify(mensagens)

if __name__ == '__main__':
    # Configuração HTTPS com certificado e chave privada do servidor
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('servidor_cert.pem', 'servidor_key.pem')
    app.run(ssl_context=context, debug=False)
