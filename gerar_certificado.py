import os
import subprocess

def criar_usuario(nome):
    base_path = os.path.join("usuarios", nome)
    os.makedirs(base_path, exist_ok=True)

    key_path = os.path.join(base_path, "private.pem")
    csr_path = os.path.join(base_path, "request.csr")
    cert_path = os.path.join(base_path, "cert.pem")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(f"[INFO] Certificado e chave já existem para {nome}")
        return

    print(f"[INFO] Gerando certificados para o usuário '{nome}'...")

    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-key", key_path, "-out", csr_path,
        "-subj", f"/C=BR/ST=SP/L=Cidade/O=ChatApp/OU=Usuarios/CN={nome}"
    ], check=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-out", cert_path, "-days", "365", "-sha256"
    ], check=True)

    print(f"[INFO] Certificado gerado em {base_path}")
