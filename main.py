import tkinter as tk
from tkinter import scrolledtext, font as tkfont, simpledialog
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from gerar_certificado import criar_usuario
import base64
import requests
import threading
import time

class ChatInterface(tk.Tk):
    def __init__(self, nome_usuario):
        super().__init__()
        self.title("WhatsApp Clone")
        self.geometry("520x600")
        self.configure(bg="#ECE5DD")
        self.minsize(400, 500)

        # Fontes para diferentes elementos
        self.font_header = tkfont.Font(family="Helvetica", size=16, weight="bold")
        self.font_subheader = tkfont.Font(family="Arial", size=10)
        self.font_message = tkfont.Font(family="Arial", size=11)
        self.font_input = tkfont.Font(family="Arial", size=12)

        # Cabeçalho da janela
        header_frame = tk.Frame(self, bg="#075E54", height=60)
        header_frame.pack(fill='x')
        header_label = tk.Label(
            header_frame, text="Chat Seguro", bg="#075E54", fg="white", font=self.font_header
        )
        header_label.pack(pady=(8,0))
        self.cert_status_header = tk.Label(
            header_frame, text="Status: Não autenticado", bg="#075E54", fg="#D3F8E2", font=self.font_subheader
        )
        self.cert_status_header.pack(pady=(0,8))

        # Área de exibição do chat
        self.chat_display = scrolledtext.ScrolledText(
            self, state='disabled', wrap='word', bg="#ECE5DD",
            fg="#000", font=self.font_message, bd=0,
            padx=10, pady=10, highlightthickness=0
        )
        self.chat_display.pack(padx=10, pady=(10,5), fill='both', expand=True)

        # Área de entrada de mensagem
        input_frame = tk.Frame(self, bg="#ECE5DD", height=60)
        input_frame.pack(fill='x', side='bottom', padx=10, pady=10)

        self.message_entry = tk.Entry(
            input_frame, font=self.font_input, bg="white", bd=0, relief='flat'
        )
        self.message_entry.pack(side='left', fill='x', expand=True, padx=(0,5), ipady=6)
        self.message_entry.bind("<Return>", self.send_message)

        send_button = tk.Button(
            input_frame, text="➤", bg="#25D366", fg="white",
            font=self.font_input, bd=0, relief='flat', command=self.send_message
        )
        send_button.pack(side='left')

        # Dados do usuário e inicialização
        self.nome_usuario = nome_usuario.strip().lower()
        self.servidor_url = "https://127.0.0.1:5000"
        self.certificate = None
        self.mensagens_exibidas = set()
        self.nome_usuario_destino = simpledialog.askstring("Destinatário", "Digite o nome do destinatário:")

        self.authenticate_certificate()
        threading.Thread(target=self.buscar_mensagens, daemon=True).start()

    def authenticate_certificate(self):
        """Carrega chave privada e certificado do usuário."""
        try:
            with open("usuario_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(), password=None
                )
            with open("usuario_cert.pem", "rb") as cert_file:
                self.certificate = load_pem_x509_certificate(cert_file.read())
            self.cert_status_header.config(text="Status: Autenticado", fg="#D3F8E2")
        except Exception as e:
            self.cert_status_header.config(text=f"Erro: {e}", fg="#FFCDD2")

    def buscar_mensagens(self):
        """Consulta mensagens do servidor periodicamente."""
        while True:
            try:
                recebidas = requests.get(
                    f"{self.servidor_url}/mensagens/{self.nome_usuario}", verify="ca.crt"
                ).json()
                enviadas = requests.get(
                    f"{self.servidor_url}/enviadas/{self.nome_usuario}", verify="ca.crt"
                ).json()
                todas = recebidas + enviadas
                todas.sort(key=lambda x: x.get("timestamp", 0))

                for msg in todas:
                    remetente = msg.get("remetente", "desconhecido")
                    texto = msg.get("mensagem", "")
                    if (remetente, texto) not in self.mensagens_exibidas:
                        self.display_message(
                            remetente, texto,
                            align='w' if remetente != self.nome_usuario else 'e',
                            bubble_bg='#FFFFFF' if remetente != self.nome_usuario else '#DCF8C6'
                        )
                        self.mensagens_exibidas.add((remetente, texto))
            except Exception as e:
                print(f"[ERRO] ao buscar mensagens: {e}")
            time.sleep(2)

    def send_message(self, event=None):
        """Assina, exibe localmente e envia a mensagem."""
        msg = self.message_entry.get().strip()
        if msg and self.private_key:
            try:
                signature = self.private_key.sign(
                    msg.encode(), padding.PKCS1v15(), hashes.SHA256()
                )
                signature_b64 = base64.b64encode(signature).decode()

                self.display_message(self.nome_usuario, msg, align='e', bubble_bg='#DCF8C6')
                self.mensagens_exibidas.add((self.nome_usuario, msg))
                print(f"[DEBUG] Enviada mensagem: {msg}")
                print(f"[DEBUG] Assinatura enviada: {signature_b64}")
                self.message_entry.delete(0, tk.END)

                threading.Thread(
                    target=self.enviar_para_servidor,
                    args=(msg, signature_b64), daemon=True
                ).start()
            except Exception as e:
                self.display_message("Erro", f"Falha ao assinar mensagem: {e}", align='w', bubble_bg='#FFCDD2')

    def display_message(self, sender, message, align='w', bubble_bg='#FFFFFF'):
        """Renderiza visualmente uma mensagem na interface."""
        justify_map = {'e': 'right', 'w': 'left', 'center': 'center'}
        justification = justify_map.get(align, 'left')

        self.chat_display.config(state='normal')
        tag = f"tag_{self.chat_display.index(tk.END)}"
        self.chat_display.tag_configure(
            tag, justify=justification, background=bubble_bg,
            lmargin1=10, lmargin2=10, rmargin=50, spacing3=5
        )
        self.chat_display.insert(tk.END, f"{sender}: {message}\n", tag)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def verificar_assinatura(self, mensagem_assinada):
        """Verifica se a assinatura é válida usando a chave pública do certificado."""
        try:
            partes = mensagem_assinada.rsplit("[assinatura: ", 1)
            if len(partes) != 2:
                return False
            mensagem = partes[0].strip()
            assinatura = base64.b64decode(partes[1].replace("]", "").strip())

            public_key = self.certificate.public_key()
            public_key.verify(
                assinatura, mensagem.encode(),
                padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Falha na verificação da assinatura: {e}")
            return False

    def enviar_para_servidor(self, msg, signature_b64):
        """Envia a mensagem assinada ao servidor."""
        print(">>> Iniciando envio para o servidor.")
        data = {
            "mensagem": msg,
            "assinatura": signature_b64,
            "remetente": self.nome_usuario,
            "destinatario": self.nome_usuario_destino
        }
        try:
            response = requests.post(
                f"{self.servidor_url}/mensagem",
                json=data,
                verify="ca.crt"
            )
            print(f"Resposta HTTP: {response.status_code}")
            print(f"JSON: {response.json()}")
            if response.ok and response.json().get("verificacao"):
                status = "✔ Servidor confirmou: assinatura válida"
            else:
                status = "❌ Servidor recusou: assinatura inválida"
        except Exception as e:
            status = f"Erro ao contatar servidor: {e}"
            print(status)
        print(f">>> Chamando display_message com status: {status}")

if __name__ == "__main__":
    # Janela temporária para capturar o nome do usuário
    root = tk.Tk()
    root.withdraw()
    nome_usuario = simpledialog.askstring("Identificação", "Digite seu nome de usuário:", parent=root)
    if not nome_usuario:
        print("Nome de usuário não fornecido. Encerrando.")
        exit()
    root.destroy()

    criar_usuario(nome_usuario.strip().lower())
    app = ChatInterface(nome_usuario)
    app.mainloop()
