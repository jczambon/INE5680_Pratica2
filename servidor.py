from Crypto.Protocol.KDF import scrypt
from pyotp.totp import TOTP
import qrcode
import base64

class Servidor:
    def __init__(self) -> None:
        self.__clientes = {}

    @property
    def clientes(self):
        return self.__clientes
    
    def cadastrar_cliente(self, login, chave):
        if login in self.clientes.keys():
            print('Cliente já existente')
            return False
        
        chave_scrypt = self.realizar_scrypt(chave)
        self.clientes[login] = chave_scrypt
        
        totp_auth = TOTP(base64.b32encode(chave_scrypt)).provisioning_uri(name=login, issuer_name='JosePedro')
        qrcod = qrcode.make(totp_auth)

        return qrcod
    
    def buscar_cliente(self, login, chave):
        chave_scrypt = self.realizar_scrypt(chave)
        
        if (login, chave_scrypt) in self.clientes.items():
            fa = self.realizar_2fa(chave_scrypt)

            if fa:
                return True
        
        return False
    
    def realizar_scrypt(self, chave):
        salt = 'madonna'
        chave_scrypt = scrypt(chave, salt, 16, N=2**14, r=8, p=1)
        return chave_scrypt
    
    def realizar_2fa(self, chave_scrypt):
        codigo = False
        while codigo is False:
            totp = TOTP(base64.b32encode(chave_scrypt))
            totp_input = input('Digite o código de 2º fator: ')

            if totp.verify(totp_input):
                print("código de 2º fator validado")
                return True
            print("código de 2º fator incorreto")

        return totp.verify(totp_input)