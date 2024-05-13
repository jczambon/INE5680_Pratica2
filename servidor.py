from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from pyotp.totp import TOTP
import socket
from deep_translator import GoogleTranslator
import base64
import csv


class Servidor:
    def __init__(self) -> None:
        self.__clientes = {}
        self.carregar_clientes_do_csv()

        self.host = input("Host/IP [Default: localhost]: ") or "localhost"
        self.port = int(input("Porta [Default: 8080]: ") or "8080")

        self.chave_sessao = ""

        self.escutar()

    @property
    def clientes(self):
        return self.__clientes
    
    def escutar(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.socket: # criando o socket com familia INET e STREAM (TCP)
            self.socket.bind((self.host, self.port))        # seta o ip do socket
            self.socket.listen()                  # escuta por conexoes
            print("<<< Socket created >>>")
            print("<<< Socket bind complete >>>")

            self.conn, addr = self.socket.accept()                  # espera conexao e aceita

            with self.conn:
                print(f"<<< Connection accepted by {addr} >>>")
                #i = 0               # contador de mensagens dessa conexao
                while True:
                    msg_enviar = '(SERVIDOR)\nO que você deseja fazer? \n1 - Realizar Cadastro \n2 - Realizar Login \n3 - Sair'
                    self.conn.sendall(str(msg_enviar).encode())   # envia numero da mensagem

                    data = self.conn.recv(1024)       # espera recebimento de mensagem de um cliente

                    if not data:
                        break

                    msg = data.decode()     # decodifica os bytes da msg


                    # CHECAR MENSAGENS VAZIAS/INVALIDAS
                    if msg == '1':
                        msg = self.cadastrar_cliente()
                    elif msg == '2':
                        msg = self.realizar_login()
                    elif msg == '3':
                        break
                    else:
                        print('Apenas são aceitos valores inteiros entre 1 e 3')

                    if msg == False:
                        print('#erro')
                        
                    #print(f"[{i}] Mensagem [{addr[0]}:{addr[1]}]: {msg}")
                    
                    
                    #msg_enviar = input("Digite mensagem para enviar")
                    #conn.sendall(str(msg_enviar).encode())   # envia numero da mensagem
                    #i += 1
    
    def carregar_clientes_do_csv(self):
        try:
            with open('clientes.csv', mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    login, chave_scrypt = row
                    self.clientes[login] = chave_scrypt
        except FileNotFoundError:
            print("Arquivo de clientes não encontrado.")

    def cadastrar_cliente(self):
        self.conn.sendall(str('#cadastrar').encode())

        data = self.conn.recv(1024) 
        #! CHECAR MENSAGENS VAZIAS/INVALIDAS
        #if not data:
            #break

        login, chave = data.decode().split(", ")     # decodifica os bytes da msg
        
        if login in self.clientes.keys():
            self.conn.sendall(str("False").encode())
            #print('Cliente já existente')
            return False
        
        chave_scrypt = self.realizar_scrypt(login+chave, login)
        self.clientes[login] = chave_scrypt

        with open('clientes.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([login, chave_scrypt])
            
        totp_auth = TOTP(base64.b32encode(chave_scrypt)).provisioning_uri(name=login, issuer_name='JosePedro')
        #qrcod = qrcode.make(totp_auth)

        self.conn.sendall(str(totp_auth).encode())

        return True

    def realizar_login(self):
        self.conn.sendall(str('#login').encode())
        #! CHECAR MENSAGENS VAZIAS/INVALIDAS
        data = self.conn.recv(1024) 
        login, chave = data.decode().split(", ")     # decodifica os bytes da msg

        # self.clientes = ler csv

        if login in self.clientes.keys():        
            chave_scrypt = self.realizar_scrypt(login+chave, login)
            
            if self.clientes[login] == chave_scrypt:
                self.conn.sendall(str(True).encode())
                codigo_2fa, autenticado = self.realizar_2fa(chave_scrypt)
                #self.conn.sendall(str(autenticado).encode())
                
                if autenticado:
                    self.chave_sessao = self.realizar_pbkdf(codigo_2fa, login)
                    self.trocar_mensagens()
                    return True
            self.conn.sendall(str(False).encode())
        return False

    def encriptar_msg(self, msg, chave):
        msg = msg.encode()
        cipher = AES.new(chave, AES.MODE_GCM)

        texto_cifrado = cipher.encrypt(msg)

        hmac = HMAC.new(chave, digestmod=SHA256)
        tag = hmac.update(cipher.nonce + texto_cifrado).digest()

        return cipher.nonce + tag + texto_cifrado

    def descriptar_autenticar_msg(self, msg, chave):
        nonce = msg[0:16]
        tag = msg[16:48]
        texto_cifrado = msg[48:]
        #print("coisas:", tag, texto_cifrado)
        
        try:
            hmac = HMAC.new(chave, digestmod=SHA256)
            hmac.update(nonce + texto_cifrado).verify(tag)
        except:
            print("mensagem modificada")
            pass
            #mensagem modificada
        
        cipher = AES.new(chave, AES.MODE_GCM, nonce)
        texto = cipher.decrypt(texto_cifrado)
        #print("sexo:", texto)
        return texto

    def trocar_mensagens(self):
        while True:
            msg_cliente = self.conn.recv(1024)
            print("Mensagem encriptada recebida:", msg_cliente)
            msg_cliente = self.descriptar_autenticar_msg(msg_cliente, self.chave_sessao)
            #print("chave:", self.chave_sessao)
            print(f"Mensagem do cliente: {msg_cliente.decode()}")

            resposta = input("Digite a mensagem para enviar: ")
            resposta = self.encriptar_msg(resposta, self.chave_sessao)
            print("Mensagem encriptada sendo enviada:", resposta)
            self.conn.sendall(resposta)

    def buscar_cliente(self, login, chave):
        chave_scrypt = self.realizar_scrypt(login+chave, login)
        
        if (login, chave_scrypt) in self.clientes.items():
            totp, fa = self.realizar_2fa(chave_scrypt)

            if fa:
                self.logado(totp)
                
        return False
    
    def realizar_scrypt(self, chave, salt):
        salt = GoogleTranslator(source='auto', target='la').translate(salt)

        #salt = 'madonna'
        chave_scrypt = scrypt(chave, salt, 16, N=2**14, r=8, p=1)
        return chave_scrypt
    
    def realizar_2fa(self, chave_scrypt):
        totp = TOTP(base64.b32encode(chave_scrypt))
        while True:
            #self.conn.sendall(str('Digite o código de 2º fator: ').encode())
            codigo_2fa = self.conn.recv(1024).decode()

            if totp.verify(codigo_2fa):
                self.conn.sendall(str(True).encode())
                #print("código de 2º fator validado")
                return [codigo_2fa, True]
            self.conn.sendall(str(False).encode())
            #print("código de 2º fator incorreto")

    def realizar_pbkdf(self, senha, salt, hash=SHA256): #usuario, 
        salt = GoogleTranslator(source='auto', target='la').translate(salt)

        #salt = 'madonna'
        chave = PBKDF2(senha, salt, count=1000, hmac_hash_module=hash)
        return chave


s = Servidor()