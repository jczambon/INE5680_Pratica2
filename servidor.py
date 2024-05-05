from Crypto.Protocol.KDF import scrypt
import pyotp
import time
import qrcode

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
        return True
    
    def buscar_cliente(self, login, chave):
        chave_scrypt = self.realizar_scrypt(chave)
        if (login, chave_scrypt) in self.clientes.items():
            return True
        return False
    
    def realizar_scrypt(self, chave):
        salt = 'madonna'
        chave_scrypt = scrypt(chave, salt, 16, N=2**14, r=8, p=1)
        return chave_scrypt
    
    def realizar_2fa(self):
        codigo = False
        while codigo is False:
            totp = pyotp.TOTP('base32secret3232')
            qrcode.make(totp.now()).save('totp.png')
            print('código: ' + totp.now())
            print('Digite o código de 2º fator')
            totp_input = input()
            codigo = totp.verify(totp_input)
        return totp.verify(totp_input)