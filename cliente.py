from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
import qrcode
#from servidor import Servidor
import socket

class Cliente:
    def __init__(self):
        self.request_servidor()
        #self.servidor = Servidor()

    def request_servidor(self):
        self.host = input("Host/IP do servidor [Default: localhost]: ") or "localhost"
        self.port = int(input("Porta do servidor[Default: 8080]: ") or "8080")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.socket: # criando o socket com familia INET e STREAM (TCP)
            self.socket.connect((self.host, self.port))                          # conecta com servidor
            print("Connection established!")

            while True:                                     # loop de mensagens
                print(self.socket.recv(1024).decode())
                msg = input("")
                
                if msg == "":
                    break
 
                self.socket.sendall(msg.encode())             # manda mensagem em bytes
                
                msg = self.socket.recv(1024)                     # espera recebimento de resposta do servidor (tamanho maximo de 1024 bytes)
                
                if not msg:
                    break

                msg = msg.decode()

                if msg == '#cadastrar':
                    msg = self.cadastrar_cliente()
                elif msg == "#login":
                    msg = self.realizar_login()
                
                if msg == False:
                    break
                
                #print(f"Server reply......: [{data.decode()}] OK ::: {message}")

    def cadastrar_cliente(self):
        #if msg_recebida == '#cadastrar':
        login = input('Digite nome de usuário: ')
        senha = input('Digite a senha: ')

        chave = self.realizar_pbkdf(senha)

        self.socket.sendall(f"{login}, {chave}".encode())

        totp_auth = self.socket.recv(1024)

        totp_auth = totp_auth.decode()
        #qrcode_auth = self.servidor.cadastrar_cliente(login, chave)

        if totp_auth == "False":
            return False
        
        print('Usuário cadastrado com sucesso!')
        print("Escaneie o QRCode no app Autenticador (Google)")

        qrcode_auth = qrcode.make(totp_auth)
        qrcode_auth.show()

        return True

    def realizar_login(self):
        login = input('Digite nome de usuário: ')
        senha = input('Digite a senha: ')
        
        chave = self.realizar_pbkdf(senha)

        self.socket.sendall(f"{login}, {chave}".encode())

        existe_usuario = self.socket.recv(1024).decode()
        #existe_usuario, codigo = self.servidor.buscar_cliente(login, chave)

        if existe_usuario == "False":
            print('cliente e/ou senha inválidos')
            return
        
        #msg_2fa = self.socket.recv(1024)
        #print(msg_2fa.decode())

        while True:
            codigo_2fa = input("Digite o código de 2º fator: ")
            self.socket.sendall(codigo_2fa.encode())
            
            autenticado = self.socket.recv(1024).decode()
            print(autenticado)
            if autenticado == "False":
                print("Código de 2º fator incorreto")

            elif autenticado == "True":
                if autenticado == "True":
                    
                    print('Código de 2º fator validado - Login realizado')
                    self.chave_sessao = self.realizar_pbkdf(codigo_2fa, SHA256)
                    self.trocar_mensagens()
                    return True
                else:
                    print("Código 2fa incorreto")
                    return False
        
    def encriptar_msg(self, msg, chave):
        msg = msg.encode()
        cipher = AES.new(chave, AES.MODE_GCM)

        texto_cifrado = cipher.encrypt(msg)

        hmac = HMAC.new(chave, digestmod=SHA256)
        tag = hmac.update(texto_cifrado).digest()

        return tag + texto_cifrado

    def descriptar_autenticar_msg(self, msg, chave):
        tag = msg[0:32]
        texto_cifrado = msg[32:]

        try:
            hmac = HMAC.new(chave, digestmod=SHA256)
            hmac.update(texto_cifrado).verify(tag)
        except:
            pass
            #mensagem modificada
        
        cipher = AES.new(chave, AES.MODE_GCM)
        texto = cipher.decrypt(texto_cifrado)
        
        return texto
   
    def trocar_mensagens(self):
        while True:
            msg = input("Digite a mensagem para enviar: ")
            msg = self.encriptar_msg(msg, self.chave_sessao)
            self.socket.sendall(msg.encode())

            msg_resposta = self.socket.recv(1024).decode()
            msg_resposta = self.descriptar_autenticar_msg(msg_resposta, self.chave_sessao)
            print(f"Resposta do servidor: {msg_resposta}")


    def realizar_pbkdf(self, senha, hash=SHA512): #usuario, 
        salt = 'madonna'
        chave = PBKDF2(senha, salt, count=1000, hmac_hash_module=hash)
        return chave


c = Cliente()
