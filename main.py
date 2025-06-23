import tkinter as tk
from tkinter import scrolledtext
from tkinter import font as tkfont
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
import base64
import requests
import threading

class ChatInterface(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WhatsApp Clone")
        self.geometry("520x600")
        self.configure(bg="#ECE5DD")
        self.minsize(400, 500)

        self.font_header = tkfont.Font(family="Helvetica", size=16, weight="bold")
        self.font_subheader = tkfont.Font(family="Arial", size=10)
        self.font_message = tkfont.Font(family="Arial", size=11)
        self.font_input = tkfont.Font(family="Arial", size=12)

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

        self.chat_display = scrolledtext.ScrolledText(
            self,
            state='disabled',
            wrap='word',
            bg="#ECE5DD",
            fg="#000",
            font=self.font_message,
            bd=0,
            padx=10,
            pady=10,
            highlightthickness=0
        )
        self.chat_display.pack(padx=10, pady=(10,5), fill='both', expand=True)

        input_frame = tk.Frame(self, bg="#ECE5DD", height=60)
        input_frame.pack(fill='x', side='bottom', padx=10, pady=10)

        self.message_entry = tk.Entry(
            input_frame,
            font=self.font_input,
            bg="white",
            bd=0,
            relief='flat'
        )
        self.message_entry.pack(side='left', fill='x', expand=True, padx=(0,5), ipady=6)
        self.message_entry.bind("<Return>", self.send_message)

        send_button = tk.Button(
            input_frame,
            text="➤",
            bg="#25D366",
            fg="white",
            font=self.font_input,
            bd=0,
            relief='flat',
            command=self.send_message
        )
        send_button.pack(side='left')

        self.certificate = None
        self.authenticate_certificate()

    def authenticate_certificate(self):
        """
        Carrega e valida o certificado digital e a chave privada do usuário.
        """
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

    def send_message(self, event=None):
        msg = self.message_entry.get().strip()
        if msg and self.private_key:
            try:
                signature = self.private_key.sign(
                    msg.encode(),
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                signature_b64 = base64.b64encode(signature).decode()

                self.display_message("Eu", f"{msg}\n[assinatura: {signature_b64}]", align='e', bubble_bg='#DCF8C6')
                self.message_entry.delete(0, tk.END)

                # Cria e inicia a thread para comunicação com servidor
                threading.Thread(
                    target=self.enviar_para_servidor,
                    args=(msg, signature_b64),
                    daemon=True
                ).start()

            except Exception as e:
                self.display_message("Erro", f"Falha ao assinar mensagem: {e}", align='w', bubble_bg='#FFCDD2')

    def display_message(self, sender, message, align='w', bubble_bg='#FFFFFF'):
        justify_map = {'e': 'right', 'w': 'left', 'center': 'center'}
        justification = justify_map.get(align, 'left')

        self.chat_display.config(state='normal')
        tag = f"tag_{self.chat_display.index(tk.END)}"
        self.chat_display.tag_configure(
            tag,
            justify=justification,
            background=bubble_bg,
            lmargin1=10,
            lmargin2=10,
            rmargin=50,
            spacing3=5
        )
        self.chat_display.insert(tk.END, f"{sender}: {message}\n", tag)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def verificar_assinatura(self, mensagem_assinada):
        """
        Separa mensagem e assinatura, e verifica se é válida com base no certificado do usuário.
        """
        try:
            # Separa a mensagem da assinatura
            partes = mensagem_assinada.rsplit("[assinatura: ", 1)
            if len(partes) != 2:
                return False  # formato inválido

            mensagem = partes[0].strip()
            assinatura_b64 = partes[1].replace("]", "").strip()
            assinatura = base64.b64decode(assinatura_b64)

            # Usa a chave pública do certificado pra verificar
            public_key = self.certificate.public_key()
            public_key.verify(
                assinatura,
                mensagem.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return True

        except Exception as e:
            print(f"Falha na verificação da assinatura: {e}")
            return False
        
    def enviar_para_servidor(self, msg, signature_b64):
        print(">>> Iniciando envio para o servidor...")

        data = {
            "mensagem": msg,
            "assinatura": signature_b64
        }
        url = "https://127.0.0.1:5000/mensagem"
        verify_flag = "ca.crt"  # precisa estar na mesma pasta do main.py
        try:
            response = requests.post(
                url,
                json=data,
                verify=verify_flag
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
        self.after(0, lambda: self.display_message("Servidor", status, align='w', bubble_bg='#FFFFFF'))


if __name__ == "__main__":
    app = ChatInterface()
    app.mainloop()
